#
# Copyright (c) 2011 Duo Security
# All Rights Reserved
#

import time
import urllib.parse
import base64

from twisted.internet import reactor, defer, protocol
from twisted.protocols.basic import LineReceiver
from twisted.web.client import HTTPClientFactory

import twisted.web.error
import twisted.internet.error

from duoauthproxy.lib.ssl_verify import create_context_factory
from . import log


class ProxyError(Exception):
    pass


class _ConnectProxyClientProtocol(LineReceiver):
    def __init__(self):
        self._firstline = False
        self._timeout_dc = None

    def connectionMade(self):
        # set the timeout callback
        remain = self.factory.remaining_timeout()
        if remain is not None:
            self._timeout_dc = reactor.callLater(
                self.factory.remaining_timeout(), self._timeout)
        # send proxy-connect request
        self.sendLine(b'CONNECT ' + self.factory.dest + b' HTTP/1.0')
        if self.factory.agent:
            self.sendLine(b'User-Agent: ' + self.factory.agent)
        self.sendLine(b'')

    def connectionLost(self, reason):
        self._cleanup_timeout()
        if not self.factory.deferred.called:
            self.factory.deferred.errback(reason)

    def lineReceived(self, line):
        if not self._firstline:
            # this is the first line; should be the HTTP status response
            fields = line.split()
            try:
                if (fields[0] not in (b'HTTP/1.0', b'HTTP/1.1')
                        or fields[1] != b'200'):
                    raise ProxyError()
            except (IndexError, ProxyError):
                self.factory.deferred.errback(
                    ProxyError('Proxy Error: %s' % line))
                self.transport.abortConnection()

            self._firstline = True
        elif not line:
            # last line of the connect proxy response; we can start tunneling
            # TLS traffic now

            # set up the client factory, update its timeout, build
            # protocol instance
            http_factory = self.factory.tunnel_factory
            remain = self.factory.remaining_timeout()
            if remain is not None:
                http_factory.timeout = self.factory.remaining_timeout()
            http_factory.doStart()
            p = http_factory.buildProtocol(self.transport.getPeer())

            # start TLS, swap out the protocol on the transport
            self.transport.protocol = p
            self.transport.startTLS(self.factory.ssl_ctx_factory)
            p.makeConnection(self.transport)
            http_factory.deferred.chainDeferred(self.factory.deferred)

            # it's up to the http factory to handle timeouts now
            self._cleanup_timeout()
            self.transport = None

    def _timeout(self):
        self.transport.abortConnection()

    def _cleanup_timeout(self):
        if self._timeout_dc is not None:
            try:
                self._timeout_dc.cancel()
            except twisted.internet.error.AlreadyCalled:
                pass


class _ConnectProxyClientFactory(protocol.ClientFactory):
    protocol = _ConnectProxyClientProtocol

    def __init__(self, dest: bytes, tunnel_factory, ssl_ctx_factory, timeout=None,
                 agent: bytes = None):
        self.dest = dest
        self.tunnel_factory = tunnel_factory
        self.ssl_ctx_factory = ssl_ctx_factory
        self.timeout = timeout
        self.agent = agent

        self.deferred = defer.Deferred()
        self.start_time = None

    def startFactory(self):
        self.start_time = time.time()
        return protocol.ClientFactory.startFactory(self)

    def clientConnectionFailed(self, connector, reason):
        self.deferred.errback(reason)

    def remaining_timeout(self):
        if not (self.timeout and self.start_time):
            return None

        elapsed = time.time() - self.start_time
        remain = self.timeout - elapsed
        if remain < 0:
            remain = 0.1
        return remain


class _DuoHTTPClientFactory(HTTPClientFactory):
    """ The timeout you can set in a regular HTTPClientFactory doesn't
    take into account connection set-up. Since we use a new
    HTTPClientFactory instance for every request, we can do this
    here..."""

    def startFactory(self):
        self.__start_time = time.time()
        return HTTPClientFactory.startFactory(self)

    def buildProtocol(self, addr):
        if self.timeout:
            elapsed = time.time() - self.__start_time
            self.timeout = self.timeout - elapsed
            if self.timeout <= 0:
                self.timeout = 0.1
        return HTTPClientFactory.buildProtocol(self, addr)


class HTTPClient(object):
    def __init__(self, ca_certs=None, user_agent=None, http_proxy_host=None,
                 http_proxy_port=None, debug=False, logger=log):
        """ Initialize an HTTP client.

        ca_certs should be a list of PyOpenSSL X509 objects (e.g. as
        returned from the load_ca_bundle() function

        user_agent, if specified, is the string to send as the
        User-Agent HTTP header"""
        self.ca_certs = ca_certs
        self.user_agent = user_agent
        self.set_proxy(http_proxy_host, http_proxy_port)
        self.debug = debug
        self.logger = logger
        self.is_logging_insecure = False

    def set_proxy(self, http_proxy_host, http_proxy_port):
        if (http_proxy_host is None) != (http_proxy_port is None):
            raise ValueError('Both http_proxy_host and http_proxy_port must be '
                             'specified, or neither')
        if http_proxy_host:
            http_proxy_host = http_proxy_host.encode()

        self.http_proxy_host = http_proxy_host
        self.http_proxy_port = http_proxy_port

    def _build_http_factory(self, method, url, body, headers, timeout_params,
                            protocol_class=None):

        req = urllib.parse.urlsplit(url)
        # create http client factory
        netloc = req.hostname
        if req.port:
            netloc += ':%d' % req.port
        factory_url = urllib.parse.urlunsplit((req.scheme, netloc, req.path or '/',
                                               req.query, req.fragment)).encode("utf-8")

        # Encoding everything in header into bytes
        encoded_headers = {}
        for (name, value) in headers.items():
            encoded_headers[name.encode()] = value.encode()

        # add Authorization header (http basic auth) if appropriate
        if req.username and req.password and b'Authorization' not in encoded_headers:
            auth = base64.b64encode(f"{req.username}:{req.password}".encode())
            encoded_headers[b'Authorization'] = b'Basic %s' % auth

        http_factory = _DuoHTTPClientFactory(
            factory_url, method=method.encode(), postdata=body.encode(),
            headers=encoded_headers, **timeout_params)

        if protocol_class:
            http_factory.protocol = protocol_class

        # set the user agent if appropriate
        if self.user_agent and 'User-Agent' not in headers:
            http_factory.agent = self.user_agent.encode('utf-8')

        return http_factory

    @defer.inlineCallbacks
    def request(self, method, url, body, headers, timeout=0,
                protocol_class=None,
                disconnect=True,
                ssl_hostname_override=None):
        """ Perform an HTTP(S) request to a given URL

        @param method: HTTP method to use
        @param url: absolute URL
        @param body: If method is POST (or PUT), the body of the request
        @param headers: Dict of request headers
        @param timeout: number of seconds to wait for a response
        @param ssl_hostname_override: a hostname, or list of hostnames,
            to match the server's SSL certificate against, *instead* of
            the hostname from the provided URL. This can be used when
            servers provide incorrect SSL certificates, but should nevertheless
            be trusted...
        @param protocol_class Alternative twisted.web.http.HTTPClient subclass.
            Must integrate with disconnectedDeferred and page semantics
            for HTTPClientFactory or the request will hang.
        @param disconnect If True, ensure the connection is closed.
        """
        # only log post body if debug-logging is enabled
        if self.debug:
            self.logger.msg('http %s to %s: %s' % (method, url, sanitize_params(body)))
        else:
            self.logger.msg('http %s to %s' % (method, url))

        # determine whether we should pass timeout params to http factory,
        # reactor
        timeout_params = {}
        if timeout:
            timeout_params['timeout'] = timeout

        # build http client factory
        http_factory = self._build_http_factory(
            method, url, body, headers, timeout_params,
            protocol_class=protocol_class,
        )

        # build ssl context factory, if necessary
        ctx_factory = None

        if http_factory.scheme == b'https':
            if not self.ca_certs:
                self.logger.msg(
                    'WARNING: CA certs for HTTPS certificate verification '
                    'were not specified. Peer certificate verification is '
                    'therefore DISABLED')
            ctx_factory = create_context_factory(
                hostnames=(ssl_hostname_override or http_factory.host.decode('utf-8')),
                caCerts=self.ca_certs)

        # handle proxy
        host = http_factory.host
        port = http_factory.port
        factory = http_factory

        if self.http_proxy_host:
            if ctx_factory is None:
                raise ValueError(
                    'Proxy support is only available for HTTPS connections')
            dest = b'%s:%d' % (host, port)
            proxy_factory = _ConnectProxyClientFactory(
                dest, http_factory, ctx_factory, timeout or None,
                self.user_agent.encode('utf-8'))

            factory = proxy_factory
            host = self.http_proxy_host
            port = self.http_proxy_port

        # connect http client over TCP for 'http', SSL for 'https'
        if http_factory.scheme == b'http':
            connector = reactor.connectTCP(
                host.decode(), port, factory, **timeout_params)
        elif http_factory.scheme == b'https':
            if self.http_proxy_host:
                connector = reactor.connectTCP(
                    host.decode(), port, factory, **timeout_params)
            else:
                connector = reactor.connectSSL(
                    host.decode(), port, factory, ctx_factory, **timeout_params)
        else:
            raise ValueError('unsupported protocol scheme')

        # get http response
        try:
            response = yield factory.deferred
            status = http_factory.status
            headers = http_factory.response_headers
        except twisted.web.error.Error as e:
            # raised for HTTP errors
            response = e.response
            status = e.status
            headers = {}
        finally:
            if disconnect:
                # Make sure we disconnect.
                connector.disconnect()

        defer.returnValue((int(status), response, headers))

    def get(self, url, headers=None, **kwargs):
        """Convenience function to perform an HTTP(S) GET request"""
        if headers is None:
            headers = {}
        return self.request('GET', url, '', headers, **kwargs)

    def post(self, url, fields=None, headers=None, **kwargs):
        """Convenience function to perform an HTTP(S) POST request"""
        if fields is None:
            fields = {}
        if headers is None:
            headers = {}
        body = urllib.parse.urlencode(fields)
        headers.setdefault('Content-Type', 'application/x-www-form-urlencoded')
        return self.request('POST', url, body, headers, **kwargs)


# create default HTTP Client object
_client = HTTPClient([])
request = _client.request
get = _client.get
post = _client.post


def set_proxy(http_proxy_host, http_proxy_port):
    global _client
    _client.http_proxy_host = http_proxy_host.encode()
    _client.http_proxy_port = http_proxy_port


def set_ca_certs(ca_certs):
    """Set list of CA Certificates for global HTTP Client"""
    global _client
    _client.ca_certs = ca_certs


def set_user_agent(user_agent):
    """Set the user-agent string for global HTTP Client"""
    global _client
    _client.user_agent = user_agent


def set_debug(debug):
    global _client
    _client.debug = debug


def set_is_logging_insecure(is_logging_insecure):
    global _client
    _client.is_logging_insecure = is_logging_insecure


def sanitize_params(serialized_params):
    global _client
    if _client.is_logging_insecure:
        return serialized_params
    params = urllib.parse.parse_qsl(serialized_params, True)
    for i, p in enumerate(params):
        if p[0] == 'auto':
            params[i] = ('auto', 'xxxxxxxx')
    return urllib.parse.urlencode(params)
