# Copyright (c) 2017, Neil Booth
#
# All rights reserved.
#
# The MIT License (MIT)
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
# and warranty status of this software.

'''Socks proxying.'''

import asyncio
import ipaddress
import logging
import socket
import struct
from functools import partial

import lib.util as util

INITIAL, HANDSHAKE, COMPLETED, TIMEDOUT, DISCONNECTED = range(5)
TIMEOUT_SECS=10
MSGS = {
    TIMEDOUT: 'proxy server timed out',
    DISCONNECTED: 'proxy server disconnected during handshake',
}

class SocksProtocol(util.LoggedClass, asyncio.Protocol):
    '''Socks protocol wrapper.'''

    class Error(Exception):
        pass

    def __init__(self, loop):
        super().__init__()
        self.loop = loop
        self.data = b''
        self.transport = None
        self.event = asyncio.Event()
        self.state = INITIAL
        self.debug = False

    def connection_made(self, transport):
        '''Handle connection to the proxy.'''
        self.transport = transport

    def connection_lost(self, exc):
        '''Handle disconnection from the proxy.'''
        self.state = DISCONNECTED
        self.event.set()

    def data_received(self, data):
        if self.debug:
            self.log_info('{:d} bytes received: {}'.format(len(data), data))
        self.data += data
        self.event.set()

    def close(self):
        self.transport.close()

    def timedout(self):
        self.state = TIMEDOUT
        self.event.set()

    async def wait(self, send_data, length):
        '''Wait for length bytes to come in, and return them.

        Optionally send some data first.
        '''
        if send_data:
            self.transport.write(send_data)

        while len(self.data) < length:
            timeout = self.loop.call_later(TIMEOUT_SECS, self.timedout)
            await self.event.wait()
            self.event.clear()
            timeout.cancel()
            if self.state in MSGS:
                raise self.Error(MSGS[self.state])

        result = self.data[:length]
        self.data = self.data[length:]
        return result

    async def handshake(self, host, port):
        '''Write the proxy handshake sequence.'''
        try:
            assert self.state == INITIAL
            self.state = HANDSHAKE

            if not isinstance(host, str):
                raise self.Error('host must be a string not {}'
                                 .format(type(host)))

            dest = util.host_port_string(host, port)
            socks_handshake = self._socks4_handshake
            try:
                host = ipaddress.ip_address(host)
                if host.version == 6:
                    socks_handshake = self._socks5_handshake
            except ValueError:
                pass

            result = await socks_handshake(host, port)
            if self.debug:
                self.log_info('successful proxy connection to {}'.format(dest))
            return result
        finally:
            if self.state != COMPLETED:
                self.close()

    async def _socks4_handshake(self, host, port):
        if isinstance(host, ipaddress.IPv4Address):
            # Socks 4
            ip_addr = host
            host_bytes = b''
        else:
            # Socks 4a
            ip_addr = ipaddress.ip_address('0.0.0.1')
            host_bytes = host.encode() + b'\0'

        user_id = ''
        data = b'\4\1' + struct.pack('>H', port) + ip_addr.packed
        data += user_id.encode() + b'\0' + host_bytes
        data = await self.wait(data, 8)

        if data[0] != 0:
            raise self.Error('proxy sent bad initial byte')
        if data[1] != 0x5a:
            raise self.Error('proxy request failed or rejected')
        self.state = COMPLETED

    def forward_to_protocol(self, protocol_factory):
        '''Forward the connection to the underlying protocol.'''
        if self.state != COMPLETED:
            raise self.Error('cannot forward if handshake is not complete')

        protocol = protocol_factory()
        for attr in ('connection_lost', 'data_received',
                     'pause_writing', 'resume_writing', 'eof_received'):
            setattr(self, attr, getattr(protocol, attr))
        protocol.connection_made(self.transport)
        if self.data:
            protocol.data_received(self.data)
            self.data = b''
        return self.transport, protocol


class SocksProxy(util.LoggedClass):

    def __init__(self, host, port, loop=None):
        '''Host can be an IPv4 address, IPv6 address, or a host name.'''
        super().__init__()
        self.host = host
        self.port = port
        self.loop = loop or asyncio.get_event_loop()

    def is_down(self):
        return self.port == 0

    async def create_connection(self, protocol_factory, host, port, ssl=None):
        '''All arguments are as to asyncio's create_connection method.'''
        if self.port is None:
            ports = [9050, 9150, 1080]
        else:
            ports = [self.port]

        socks_factory = partial(SocksProtocol, self.loop)
        for proxy_port in ports:
            try:
                transport, socks = await self.loop.create_connection(
                    socks_factory, host=self.host, port=proxy_port)
                break
            except OSError:
                if proxy_port == ports[-1]:
                    self.port = self.port or 0
                    raise

        if self.port is None:
            self.port = proxy_port
            hps = util.host_port_string(self.host, proxy_port)
            self.logger.info('detected proxy at {}'.format(hps))

        await socks.handshake(host, port)
        return socks.forward_to_protocol(protocol_factory)
