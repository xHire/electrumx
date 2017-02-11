# Copyright (c) 2017, Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

'''Peer management.'''

import ast
import asyncio
import random
import ssl
import time
from collections import defaultdict, Counter
from functools import partial

from lib.jsonrpc import JSONSession
from lib.peer import Peer
from lib.socks import SocksProxy
import lib.util as util
from server.irc import IRC
import server.version as version


PEERS_FILE = 'peers'
PEER_GOOD, PEER_STALE, PEER_NEVER = range(3)
FORGET_SECS = 14 * 86400
STALE_SECS = 86400
WAKEUP_SECS = 300


def peer_from_env(env):
    '''Return ourself as a peer from the environment settings.'''
    main_identity = env.identities[0]
    hosts = {identity.host : {'tcp_port': identity.tcp_port,
                              'ssl_port': identity.ssl_port}
             for identity in env.identities}
    features = {
        'hosts': hosts,
        'ssl_port': main_identity.ssl_port,
        'tcp_port': main_identity.tcp_port,
        'pruning': None,
        'server_version': version.VERSION,
        'protocol_min': version.PROTOCOL_MIN,
        'protocol_max': version.PROTOCOL_MAX,
        'genesis_hash': env.coin.GENESIS_HASH,
    }

    return Peer(main_identity.host, features, 'env')


class PeerSession(JSONSession):
    '''An outgoing session to a peer.'''

    def __init__(self, peer, peer_mgr, kind):
        super().__init__()
        self.max_send = 0
        self.peer = peer
        self.peer_mgr = peer_mgr
        self.kind = kind
        self.failed = False

    def have_pending_items(self):
        self.peer_mgr.ensure_future(self.process_pending_items())

    def connection_made(self, transport):
        '''Handle an incoming client connection.'''
        super().connection_made(transport)
        self.log_prefix = '[{}] '.format(str(self.peer)[:25])

        # Update IP address
        if not self.peer.is_tor:
            peer_info = self.peer_info()
            if peer_info:
                self.peer.ip_addr = peer_info[0]

        # Collect data
        proto_ver = (version.PROTOCOL_MIN, version.PROTOCOL_MAX)
        self.send_request(self.on_version, 'server.version',
                          [version.VERSION, proto_ver])
        self.send_request(self.on_peers_subscribe, 'server.peers.subscribe')
        self.send_request(self.on_features, 'server.features')
        if not self.peer.announced:
            self.send_request(self.on_add_peer, 'server.add_peer',
                              [self.peer_mgr.myself.features])

    def connection_lost(self, exc):
        '''Handle disconnection.'''
        super().connection_lost(exc)
        self.peer_mgr.connection_lost(self)

    def on_add_peer(self, result, error):
        '''Handle the response to the add_peer message.'''
        self.peer.announced = True
        self.close_if_done()

    def on_peers_subscribe(self, result, error):
        '''Handle the response to the peers.subcribe message.'''
        if error:
            self.failed = True
            self.log_error('server.peers.subscribe: {}'.format(error))
        else:
            self.peer_mgr.add_session_peers(self, result)
        self.close_if_done()

    def on_features(self, features, error):
        # Several peers don't implement this.
        if not error:
            self.peer.update_features(features)
        self.close_if_done()

    def on_version(self, result, error):
        '''Handle the response to the version message.'''
        if error:
            self.failed = True
            self.log_error('server.version: {}'.format(error))
        elif isinstance(result, str):
            self.peer.server_version = result
            self.peer.features['server_version'] = result
        self.close_if_done()

    def close_if_done(self):
        if not self.has_pending_requests():
            self.peer.last_connect = time.time()
            if not self.failed:
                self.peer.try_count = 0
                self.peer.source = 'peer'
                self.peer_mgr.verified_connection(self)
            self.close_connection()


class PeerManager(util.LoggedClass):
    '''Looks after the DB of peer network servers.

    Attempts to maintain a connection with up to 8 peers.
    Issues a 'peers.subscribe' RPC to them and tells them our data.
    '''
    def __init__(self, env, controller):
        super().__init__()
        # Initialise the Peer class
        Peer.DEFAULT_PORTS = env.coin.PEER_DEFAULT_PORTS
        self.env = env
        self.controller = controller
        self.loop = controller.loop
        self.irc = IRC(env, self)
        self.myself = peer_from_env(env)
        # value is max outgoing connections at a time
        self.semaphore = asyncio.BoundedSemaphore(value=8)
        self.retry_event = asyncio.Event()
        # Peers have one entry per hostname.  Once connected, the
        # ip_addr property is either None, an onion peer, or the
        # IP address that was connected to.  Adding a peer will evict
        # any other peers with the same host name or IP address.
        self.peers = set()
        self.onion_peers = []
        self.tor_proxy = SocksProxy(env.tor_proxy_host, env.tor_proxy_port,
                                    loop=self.loop)
        self.import_peers()

    def info(self):
        '''The number of peers.'''
        counter = Counter(self.peer_statuses())
        return {
            'current': counter[PEER_GOOD],
            'never': counter[PEER_NEVER],
            'stale': counter[PEER_STALE],
            'total': len(self.peers),
        }

    def peer_statuses(self):
        '''Return a list of peer statuses.'''
        cutoff = time.time() - STALE_SECS
        def peer_status(peer):
            if peer.last_connect > cutoff:
                return PEER_GOOD
            elif peer.last_connect:
                return PEER_STALE
            else:
                return PEER_NEVER

        return [peer_status(peer) for peer in self.peers]

    def rpc_data(self):
        '''Peer data for the peers RPC method.'''
        descs = ['good', 'stale', 'never']

        def peer_data(peer, status):
            data = peer.serialize()
            data['status'] = descs[status]
            return data

        return [peer_data(peer, status) for peer, status
                in zip(self.peers, self.peer_statuses())]

    def matches(self, peer):
        '''Return peers whose host matches the given peer's host or IP
        address.  This results in our favouring host names over IP
        addresses.
        '''
        candidates = (peer.host.lower(), peer.ip_addr)
        return [p for p in self.peers if p.host.lower() in candidates]

    def remove_matches(self, peer):
        matches = self.matches(peer)
        assert peer in matches
        for match in matches:
            if match != peer:
                self.peers.remove(match)

    def add_peers(self, peers, limit=3, source=None):
        '''Add peers that are not already present.'''
        new_peers = [peer for peer in peers
                     if peer.is_valid and not self.matches(peer)]
        if new_peers:
            source = source or new_peers[0].source
            if limit:
                random.shuffle(new_peers)
                use_peers = new_peers[:limit]
            else:
                use_peers = new_peers
            self.logger.info('accepted {:d}/{:d} new peers of {:d} from {}'
                             .format(len(use_peers), len(new_peers),
                                     len(peers), source))
            self.peers.update(use_peers)
            self.retry_event.set()

    def on_add_peer(self, features, source):
        '''Add peers from an incoming connection.'''
        peers = Peer.peers_from_features(features, source)
        if peers:
            self.log_info('add_peer request received from {}'
                          .format(peers[0].host))
        self.add_peers(peers, limit=3)
        return bool(peers)

    def on_peers_subscribe(self):
        '''Returns the server peers as a list of (ip, host, details) tuples.

        We return all peers we've connected to in the last day.
        Additionally, if we don't have onion routing, we return up to
        three randomly selected onion servers.
        '''
        buckets = defaultdict(list)
        cutoff = time.time() - STALE_SECS
        recent = [peer for peer in self.peers
                  if peer.last_connect > cutoff and peer.is_public]
        for peer in recent:
            buckets[peer.bucket()].append(peer)

        # Return one clearnet peer from each bucket, and no more than
        # 20% onion peers (but up to 10 is OK anyway)
        onion_peers = buckets.pop('onion', self.onion_peers)
        peers = [random.choice(bpeers) for bpeers in buckets.values()]
        max_onion = max(10, len(peers) // 4)
        random.shuffle(onion_peers)
        peers += onion_peers[:max_onion]

        return [peer.to_tuple() for peer in peers]

    def serialize(self):
        serialized_peers = [peer.serialize() for peer in self.peers]
        data = (1, serialized_peers)  # version 1
        return repr(data)

    def write_peers_file(self):
        with util.open_truncate(PEERS_FILE) as f:
            f.write(self.serialize().encode())
        self.logger.info('wrote out {:,d} peers'.format(len(self.peers)))

    def read_peers_file(self):
        try:
            with util.open_file(PEERS_FILE, create=True) as f:
                data = f.read(-1).decode()
        except Exception as e:
            self.logger.error('error reading peers file {}'.format(e))
        else:
            if data:
                version, items = ast.literal_eval(data)
                if version == 1:
                    peers = [Peer.deserialize(item) for item in items]
                    self.add_peers(peers, source='peers file', limit=None)

    def import_peers(self):
        '''Import hard-coded peers from a file or the coin defaults.'''
        coin_peers = self.env.coin.PEERS
        self.onion_peers = [Peer.from_real_name(rn, 'coins.py')
                            for rn in coin_peers if '.onion ' in rn]
        self.logger.info('found {:d} onion peers in lib/coins.py'
                         .format(len(self.onion_peers)))

        # If we don't have many peers in the peers file, add
        # hard-coded ones
        self.read_peers_file()
        if len(self.peers) < 5:
            peers = [Peer.from_real_name(real_name, 'coins.py')
                     for real_name in coin_peers]
            self.add_peers(peers, limit=None)

    def connect_to_irc(self):
        '''Connect to IRC if not disabled.'''
        if self.env.irc:
            pairs = [(self.myself.real_name(ident.host), ident.nick_suffix)
                     for ident in self.env.identities]
            self.ensure_future(self.irc.start(pairs))
        else:
            self.logger.info('IRC is disabled')

    def add_irc_peer(self, nick, real_name):
        '''Add an IRC peer.'''
        peer = Peer.from_real_name(real_name, '{}'.format(nick))
        self.add_peers([peer])

    def add_session_peers(self, session, updates):
        '''When a peer gives us a peer update.

        Each update is expected to be of the form:
            [ip_addr, hostname, ['v1.0', 't51001', 's51002']]
        '''
        try:
            real_names = [' '.join([u[1]] + u[2]) for u in updates]
            peers = [Peer.from_real_name(real_name, str(session.peer))
                     for real_name in real_names]
        except Exception:
            session.log_error('bad updates from {}'.format(session.peer))
        else:
            self.add_peers(peers)

    def ensure_future(self, coro, callback=None):
        '''Schedule the coro to be run.'''
        return self.controller.ensure_future(coro, callback=callback)

    def forget_unreachable_peers(self):
        '''Forget unreachable peers.'''
        now = time.time()
        hour_ago = now - 3600
        forget_time = now - FORGET_SECS

        def is_unreachable(peer):
            if peer.last_try > hour_ago and peer.last_connect < forget_time:
                if peer.try_count >= (10 if peer.last_connect else 5):
                    return True
            return not peer.tcp_port and not peer.ssl_port

        peers = [peer for peer in self.peers if is_unreachable(peer)]
        if peers:
            self.logger.info('forgetting unreachable peers: {}'
                             .format(', '.join(str(peer) for peer in peers)))
            self.peers.difference_update(peers)

    async def main_loop(self):
        '''Main loop performing peer maintenance.  This includes

          1) Forgetting unreachable peers.
          2) Verifying connectivity of new peers.
          3) Retrying old peers at regular intervals.
        '''
        self.connect_to_irc()
        try:
            while True:
                timeout = self.loop.call_later(WAKEUP_SECS,
                                               self.retry_event.set)
                await self.retry_event.wait()
                self.retry_event.clear()
                timeout.cancel()
                self.forget_unreachable_peers()
                await self.retry_peers()
        finally:
            self.write_peers_file()

    async def retry_peers(self):
        '''Retry peers that are close to getting stale.'''
        # Exponential backoff of retries
        now = time.time()
        retry_cutoff = (now - STALE_SECS) + WAKEUP_SECS * 2

        peers = [peer for peer in self.peers
                 if peer.last_connect < retry_cutoff
                 and peer.last_try < now - WAKEUP_SECS * 2 ** peer.try_count]

        for peer in peers:
            await self.semaphore.acquire()
            self.retry_peer(peer)

    def retry_peer(self, peer):
        if peer.ssl_port and not peer.is_tor:
            port = peer.ssl_port
            kind = 'SSL'
            # Python 3.5.3: use PROTOCOL_TLS
            sslc = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        else:
            kind = 'TCP'
            port = peer.tcp_port
            if not port:
                return
            sslc = None

        peer.last_try = time.time()
        peer.try_count += 1

        if peer.is_tor:
            if self.tor_proxy.is_down():
                return
            create_connection = self.tor_proxy.create_connection
        else:
            create_connection = self.loop.create_connection

        protocol_factory = partial(PeerSession, peer, self, kind)
        coro = create_connection(protocol_factory, peer.host, port, ssl=sslc)
        self.ensure_future(coro, partial(self.on_create_connection, peer))

    def on_create_connection(self, peer, future):
        '''Called when a connection attempt succeeds or fails.

        If failed, lot it and release the connection count semaphore.'''
        try:
            exception = future.exception()
        except asyncio.CancelledError:
            pass
        else:
            if exception:
                self.logger.info('failed connecting to {}: {}'
                                 .format(peer, exception))
                self.semaphore.release()

    def connection_lost(self, session):
        '''Called by the peer session when disconnected.'''
        self.semaphore.release()

    def verified_connection(self, session):
        '''Called by the peer session if a connection was verified.'''
        peer = session.peer
        self.remove_matches(peer)
        if peer.is_tor:
            self.log_info('peer {} verified via {} over Tor'
                          .format(peer, session.kind))
        else:
            self.log_info('peer {} verified via {} at {}'
                          .format(peer, session.kind, peer.ip_addr))
