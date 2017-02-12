# Copyright (c) 2016-2017, Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

'''Classes for local RPC server and remote client TCP/SSL servers.'''

import time
from functools import partial

from lib.jsonrpc import JSONSession, RPCError, JSONRPCv2
from server.daemon import DaemonError
import server.version as version


class SessionBase(JSONSession):
    '''Base class of ElectrumX JSON sessions.

    Each session runs its tasks in asynchronous parallelism with other
    sessions.
    '''

    def __init__(self, controller, kind):
        # Force v2 as a temporary hack for old Coinomi wallets
        # Remove in April 2017
        super().__init__(version=JSONRPCv2)
        self.kind = kind  # 'RPC', 'TCP' etc.
        self.controller = controller
        self.bp = controller.bp
        self.env = controller.env
        self.daemon = self.bp.daemon
        self.client = 'unknown'
        self.protocol_version = '1.0'
        self.anon_logs = self.env.anon_logs
        self.last_delay = 0
        self.txs_sent = 0
        self.requests = []
        self.start_time = time.time()
        self.close_time = 0
        self.bw_limit = self.env.bandwidth_limit
        self.bw_time = self.start_time
        self.bw_interval = 3600
        self.bw_used = 0
        self.peer_added = False

    def have_pending_items(self):
        '''Called each time the pending item queue goes from empty to having
        one item.'''
        self.controller.enqueue_session(self)

    def close_connection(self):
        '''Call this to close the connection.'''
        self.close_time = time.time()
        super().close_connection()

    def peername(self, *, for_log=True):
        '''Return the peer address and port.'''
        return self.peer_addr(anon=for_log and self.anon_logs)

    def flags(self):
        '''Status flags.'''
        status = self.kind[0]
        if self.is_closing():
            status += 'C'
        if self.log_me:
            status += 'L'
        status += str(self.controller.session_priority(self))
        return status

    def connection_made(self, transport):
        '''Handle an incoming client connection.'''
        super().connection_made(transport)
        self.controller.add_session(self)

    def connection_lost(self, exc):
        '''Handle client disconnection.'''
        super().connection_lost(exc)
        msg = ''
        if self.pause:
            msg += ' whilst paused'
        if self.controller.is_deprioritized(self):
            msg += ' whilst deprioritized'
        if self.send_size >= 1024*1024:
            msg += ('.  Sent {:,d} bytes in {:,d} messages'
                    .format(self.send_size, self.send_count))
        if msg:
            msg = 'disconnected' + msg
            self.log_info(msg)
        self.controller.remove_session(self)

    def using_bandwidth(self, amount):
        now = time.time()
        # Reduce the recorded usage in proportion to the elapsed time
        elapsed = now - self.bw_time
        self.bandwidth_start = now
        refund = int(elapsed / self.bw_interval * self.bw_limit)
        refund = min(refund, self.bw_used)
        self.bw_used += amount - refund

    def sub_count(self):
        return 0


class ElectrumX(SessionBase):
    '''A TCP server that handles incoming Electrum connections.'''

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.subscribe_headers = False
        self.subscribe_height = False
        self.notified_height = None
        self.max_send = self.env.max_send
        self.max_subs = self.env.max_session_subs
        self.hashX_subs = {}
        self.electrumx_handlers = {
            'blockchain.address.subscribe': self.address_subscribe,
            'blockchain.headers.subscribe': self.headers_subscribe,
            'blockchain.numblocks.subscribe': self.numblocks_subscribe,
            'blockchain.transaction.broadcast': self.transaction_broadcast,
            'server.add_peer': self.add_peer,
            'server.features': self.server_features,
            'server.peers.subscribe': self.peers_subscribe,
            'server.version': self.server_version,
        }

    def sub_count(self):
        return len(self.hashX_subs)

    async def notify(self, height, touched):
        '''Notify the client about changes in height and touched addresses.

        Cache is a shared cache for this update.
        '''
        controller = self.controller
        pairs = []

        if height != self.notified_height:
            self.notified_height = height
            if self.subscribe_headers:
                args = (controller.electrum_header(height), )
                pairs.append(('blockchain.headers.subscribe', args))

            if self.subscribe_height:
                pairs.append(('blockchain.numblocks.subscribe', (height, )))

        matches = touched.intersection(self.hashX_subs)
        for hashX in matches:
            address = self.hashX_subs[hashX]
            status = await controller.address_status(hashX)
            pairs.append(('blockchain.address.subscribe', (address, status)))

        self.send_notifications(pairs)
        if matches:
            es = '' if len(matches) == 1 else 'es'
            self.log_info('notified of {:,d} address{}'
                          .format(len(matches), es))

    def height(self):
        '''Return the current flushed database height.'''
        return self.bp.db_height

    def current_electrum_header(self):
        '''Used as response to a headers subscription request.'''
        return self.controller.electrum_header(self.height())

    def headers_subscribe(self):
        '''Subscribe to get headers of new blocks.'''
        self.subscribe_headers = True
        return self.current_electrum_header()

    def numblocks_subscribe(self):
        '''Subscribe to get height of new blocks.'''
        self.subscribe_height = True
        return self.height()

    def add_peer(self, features):
        '''Add a peer.'''
        if self.peer_added:
            return False
        peer_mgr = self.controller.peer_mgr
        peer_info = self.peer_info()
        source = peer_info[0] if peer_info else 'unknown'
        self.peer_added = peer_mgr.on_add_peer(features, source)
        return self.peer_added

    def peers_subscribe(self):
        '''Return the server peers as a list of (ip, host, details) tuples.'''
        return self.controller.peer_mgr.on_peers_subscribe()

    async def address_subscribe(self, address):
        '''Subscribe to an address.

        address: the address to subscribe to'''
        # First check our limit.
        if len(self.hashX_subs) >= self.max_subs:
            raise RPCError('your address subscription limit {:,d} reached'
                           .format(self.max_subs))
        # Now let the controller check its limit
        hashX, status = await self.controller.new_subscription(address)
        self.hashX_subs[hashX] = address
        return status

    def server_features(self):
        '''Returns a dictionary of server features.'''
        return self.controller.peer_mgr.myself.features

    def server_version(self, client_name=None, protocol_version=None):
        '''Returns the server version as a string.

        client_name: a string identifying the client
        protocol_version: the protocol version spoken by the client
        '''
        if client_name:
            self.client = str(client_name)[:17]
        if protocol_version is not None:
            self.protocol_version = protocol_version
        return version.VERSION

    async def transaction_broadcast(self, raw_tx):
        '''Broadcast a raw transaction to the network.

        raw_tx: the raw transaction as a hexadecimal string'''
        # An ugly API: current Electrum clients only pass the raw
        # transaction in hex and expect error messages to be returned in
        # the result field.  And the server shouldn't be doing the client's
        # user interface job here.
        try:
            tx_hash = await self.daemon.sendrawtransaction([raw_tx])
            self.txs_sent += 1
            self.log_info('sent tx: {}'.format(tx_hash))
            self.controller.sent_tx(tx_hash)
            return tx_hash
        except DaemonError as e:
            error = e.args[0]
            message = error['message']
            self.log_info('sendrawtransaction: {}'.format(message),
                          throttle=True)
            if 'non-mandatory-script-verify-flag' in message:
                return (
                    'Your client produced a transaction that is not accepted '
                    'by the network any more.  Please upgrade to Electrum '
                    '2.5.1 or newer.'
                )

            return (
                'The transaction was rejected by network rules.  ({})\n[{}]'
                .format(message, raw_tx)
            )

    def request_handler(self, method):
        '''Return the async handler for the given request method.'''
        handler = self.electrumx_handlers.get(method)
        if not handler:
            handler = self.controller.electrumx_handlers.get(method)
        return handler


class LocalRPC(SessionBase):
    '''A local TCP RPC server session.'''

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.client = 'RPC'
        self.max_send = 0

    def request_handler(self, method):
        '''Return the async handler for the given request method.'''
        return self.controller.rpc_handlers.get(method)
