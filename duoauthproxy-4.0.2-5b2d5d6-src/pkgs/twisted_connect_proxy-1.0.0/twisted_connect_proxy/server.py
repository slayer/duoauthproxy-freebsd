#!/usr/bin/env python
# Copyright (c) 2014, Peter Ruibal.  All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.
#
from twisted.internet.protocol import Protocol, ClientFactory
from twisted.web.proxy import Proxy, ProxyRequest
from twisted.python import log

import netaddr
from urllib import parse


def is_ip_in_networks(ip, networks):
    ip_address = netaddr.IPAddress(ip)
    return any([ip_address in network for network in networks])


class ConnectProxyRequest(ProxyRequest):
    """HTTP ProxyRequest handler (factory) that supports CONNECT"""

    connectedProtocol = None

    def process(self):
        client_address = self.getClientAddress()
        if len(self.channel.client_ips) and not is_ip_in_networks(client_address.host, self.channel.client_ips):
            fail_title = "Bad Proxy Request"
            fail_msg = ("Attempted connection creation from non-approved client IP: %s"
                        % client_address.host)
            self.fail(fail_title, fail_msg, code=403)
            log.msg(fail_title + ': ' + fail_msg)
        elif self.method == b'CONNECT':
            self.processConnectRequest()
        else:
            self.fail("Bad Proxy Request",
                      "Attempted connection creation without initial CONNECT", code=405)

    def fail(self, message, body, code=500):
        self.setResponseCode(code, message.encode())
        self.responseHeaders.addRawHeader(b"Content-Type", b"text/html")
        self.write(body.encode())
        self.finish()

    def splitHostPort(self, hostport, default_port):
        port = default_port
        parts = hostport.split(b':', 1)
        if len(parts) == 2:
            try:
                port = int(parts[1])
            except ValueError:
                pass
        return parts[0], port

    def processConnectRequest(self):
        # Reject http:// requests
        # Prepend https:// to requests that come in without a protocol
        if self.uri.startswith(b'http://'):
            self.fail("Bad Proxy Request",
                      "Unable to accept non-HTTPS requests", code=403)
            return
        if not self.uri.startswith(b'https://'):
            self.uri = b'https://' + self.uri
        parsed = parse.urlparse(self.uri)
        default_port = self.ports.get(parsed.scheme)

        host, port = self.splitHostPort(parsed.netloc or parsed.path,
                                        default_port)
        if port is None:
            self.fail("Bad CONNECT Request",
                      "Unable to parse port from URI: %s" % repr(self.uri), code=400)
            return
        if self.channel.host != host.decode():
            fail_title = "Bad Proxy Request"
            fail_msg = "Attempted connection creation to non-approved host: %s" % host.decode()
            self.fail(fail_title, fail_msg, code=403)
            log.msg(fail_title + ': ' + fail_msg)
            return

        clientFactory = ConnectProxyClientFactory(host, port, self)

        # TODO provide an API to set proxy connect timeouts
        self.reactor.connectTCP(host, port, clientFactory)
        self.connectedProtocol = True


class ConnectProxy(Proxy, object):
    """HTTP Server Protocol that supports CONNECT"""
    requestFactory = ConnectProxyRequest
    connectedRemote = None

    def __init__(self, host='', client_ips=None, **kwargs):
        self.host = host
        if client_ips is None:
            self.client_ips = []
        else:
            self.client_ips = set(client_ips)
        super(ConnectProxy, self).__init__(**kwargs)

    def requestDone(self, request):
        if request.method == b'CONNECT' and self.connectedRemote is not None:
            self.connectedRemote.connectedClient = self
            self._networkProducer.resumeProducing()
            if self._savedTimeOut:
                self.setTimeout(self._savedTimeOut)
            data = b''.join(self._dataBuffer)
            self._dataBuffer = []
            self.setLineMode(data)

        else:
            Proxy.requestDone(self, request)

    def connectionLost(self, reason):
        if self.connectedRemote is not None:
            self.connectedRemote.transport.loseConnection()
        Proxy.connectionLost(self, reason)

    def dataReceived(self, data):
        if self.connectedRemote is None:
            Proxy.dataReceived(self, data)
        else:
            # Once proxy is connected, forward all bytes received
            # from the original client to the remote server.
            self.connectedRemote.transport.write(data)


class ConnectProxyClient(Protocol):
    connectedClient = None

    def connectionMade(self):
        self.factory.request.channel.connectedRemote = self
        self.factory.request.setResponseCode(200, b"CONNECT OK")
        self.factory.request.setHeader(b'X-Connected-IP',
                                       self.transport.realAddress[0])
        self.factory.request.setHeader(b'Content-Length', b'0')
        self.factory.request.finish()

    def connectionLost(self, reason):
        if self.connectedClient is not None:
            self.connectedClient.transport.loseConnection()

    def dataReceived(self, data):
        if self.connectedClient is not None:
            # Forward all bytes from the remote server back to the
            # original connected client
            self.connectedClient.transport.write(data)
        else:
            log.msg("UNEXPECTED DATA RECEIVED:", data)


class ConnectProxyClientFactory(ClientFactory):
    protocol = ConnectProxyClient

    def __init__(self, host, port, request):
        self.request = request
        self.host = host
        self.port = port

    def clientConnectionFailed(self, connector, reason):
        self.request.fail("Gateway Error", str(reason), code=502)


if __name__ == '__main__':
    import sys
    log.startLogging(sys.stderr)

    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('port', default=8080, nargs='?', type=int)
    ap.add_argument('--ssl-cert', type=str)
    ap.add_argument('--ssl-key', type=str)
    ns = ap.parse_args()

    import twisted.web.http
    factory = twisted.web.http.HTTPFactory()
    factory.protocol = ConnectProxy

    import twisted.internet
    if ns.ssl_key and not ns.ssl_cert:
        log.msg("--ssl-key must be used with --ssl-cert")
        sys.exit(1)
    if ns.ssl_cert:
        from twisted.internet import ssl
        with open(ns.ssl_cert, 'rb') as fp:
            ssl_cert = fp.read()
        if ns.ssl_key:
            from OpenSSL import crypto
            with open(ns.ssl_key, 'rb') as fp:
                ssl_key = fp.read()
            certificate = ssl.PrivateCertificate.load(
                    ssl_cert,
                    ssl.KeyPair.load(ssl_key, crypto.FILETYPE_PEM),
                    crypto.FILETYPE_PEM)
        else:
            certificate = ssl.PrivateCertificate.loadPEM(ssl_cert)
        twisted.internet.reactor.listenSSL(ns.port, factory,
                                           certificate.options())
    else:
        twisted.internet.reactor.listenTCP(ns.port, factory)
    twisted.internet.reactor.run()
