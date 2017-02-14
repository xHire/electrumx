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


class Socks(util.LoggedClass):
    '''Socks protocol wrapper.'''

    class Error(Exception):
        pass

    def __init__(self, loop, sock, host, port):
        super().__init__()
        self.loop = loop
        self.sock = sock
        self.host = host
        self.port = port
        try:
            self.ip_address = ipaddress.ip_address(host)
        except ValueError:
            self.ip_address = None
        self.debug = False

    async def _socks4_handshake(self):
        if self.ip_address:
            # Socks 4
            ip_addr = self.ip_address
            host_bytes = b''
        else:
            # Socks 4a
            ip_addr = ipaddress.ip_address('0.0.0.1')
            host_bytes = self.host.encode() + b'\0'

        user_id = ''
        data = b'\4\1' + struct.pack('>H', self.port) + ip_addr.packed
        data += user_id.encode() + b'\0' + host_bytes
        await self.loop.sock_sendall(self.sock, data)
        data = await self.loop.sock_recv(self.sock, 8)
        if data[0] != 0:
            raise self.Error('proxy sent bad initial byte')
        if data[1] != 0x5a:
            raise self.Error('proxy request failed or rejected')

    async def handshake(self):
        '''Write the proxy handshake sequence.'''
        if self.ip_address and self.ip_address.version == 6:
            await self._socks5_handshake()
        else:
            await self._socks4_handshake()

        if self.debug:
            address = (self.host, self.port)
            self.log_info('successful connection via proxy to {}'
                          .format(util.address_string(address)))


class SocksProxy(util.LoggedClass):

    def __init__(self, host, port, loop=None):
        '''Host can be an IPv4 address, IPv6 address, or a host name.'''
        super().__init__()
        self.host = host
        self.port = port
        self.ip_addr = None
        self.loop = loop or asyncio.get_event_loop()

    async def create_connection(self, protocol_factory, host, port, ssl=None):
        '''All arguments are as to asyncio's create_connection method.'''
        if self.port is None:
            proxy_ports = [9050, 9150, 1080]
        else:
            proxy_ports = [self.port]

        for proxy_port in proxy_ports:
            address = (self.host, proxy_port)
            sock = socket.socket()
            sock.setblocking(False)
            try:
                await self.loop.sock_connect(sock, address)
            except OSError as e:
                if proxy_port == proxy_ports[-1]:
                    raise
                continue

            socks = Socks(self.loop, sock, host, port)
            try:
                await socks.handshake()
                if self.port is None:
                    self.ip_addr = sock.getpeername()[0]
                    self.port = proxy_port
                    self.logger.info('detected proxy at {} ({})'
                                     .format(util.address_string(address),
                                             self.ip_addr))
                break
            except Exception as e:
                sock.close()
                raise

        hostname = host if ssl else None
        return await self.loop.create_connection(
            protocol_factory, ssl=ssl, sock=sock, server_hostname=hostname)
