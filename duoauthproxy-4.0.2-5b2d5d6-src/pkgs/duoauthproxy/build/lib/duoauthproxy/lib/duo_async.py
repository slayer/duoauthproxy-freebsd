#
# Copyright (c) 2011 Duo Security
# All Rights Reserved
#

import abc
import base64
import datetime
import functools
import hashlib
import hmac
import json
import time
import urllib.parse

from twisted.internet import defer
from twisted.internet.error import ConnectionRefusedError
from twisted.web.http import HTTPClient as twistedHTTPClient

from duoauthproxy.lib.primary_only_manager import PrimaryOnlyManager
from duoauthproxy.lib.cloudsso_server_factory import CloudSSOServerFactory
from duoauthproxy.lib.directory_sync_server_factory import DirectorySyncServerFactory
from duoauthproxy.lib import log
from . import http

DRPC_ROTATE_ENDPOINT = '/drpc/v1/rotate'

FAILMODE_SAFE = 'safe'
FAILMODE_SECURE = 'secure'
FAILMODE_UNKNOWN = 'unknown'
FAILMODES = [FAILMODE_SAFE, FAILMODE_SECURE]

FAILMODE_SAFE_MSG = 'Failmode Safe - Allowed Duo login on preauth failure'
FAILMODE_SECURE_MSG = 'Failmode Secure - Denied Duo login on preauth failure'

PRIMARY_ONLY_FAILMODE_SAFE_MSG = 'Primary Only Mode - Secondary authentication bypassed'

MAX_FACTOR_OR_PASSCODE_LENGTH = 2000

ROTATE_RESPONSE_CODE = 200


class DuoAPIError(Exception):
    # Clients in FAILMODE_SAFE may fail open iff fail_open is True.
    def __init__(self, message='', info=None):
        super(DuoAPIError, self).__init__(message)
        self.info = info

    info = None
    fail_open = False


class DuoAPIFailClosedError(DuoAPIError):
    pass


class DuoAPIFailOpenError(DuoAPIError):
    fail_open = True


class DuoAPIProxyJoinError(DuoAPIError):
    fail_open = True


class DuoAPIRotateRequiredError(DuoAPIError):
    pass


class DuoAPIProxyNotFoundError(DuoAPIError):
    pass


class DuoAPIBadSignatureError(DuoAPIError):
    pass


class DuoAPIMalformedResponseError(DuoAPIFailOpenError):
    def __init__(self, key):
        msg = ("Malformed API Response - invalid or missing '%s'"
               % key)
        super(DuoAPIMalformedResponseError, self).__init__(msg)


API_RESULT_AUTH = 'auth'
API_RESULT_ALLOW = 'allow'
API_RESULT_DENY = 'deny'
API_RESULT_ENROLL = 'enroll'


def should_server_fail_open(server_section_failmode, is_fail_open):
    """Checks the server section fail mode configuration, the fail mode of the exception and if the Authentication Proxy is running in primary authentication only mode.

    Args:
        server_section_failmode (str): the failmode configuration for a server section ('safe' or 'secure')
        is_fail_open (bool): the fail_open value of an DuoAPIError

    Returns:
        bool: True if the server section is configured to fail safe and either the AuthProxy is running in primary only mode or the exception type allows failing open. Otherwise False.
    """
    return server_section_failmode == FAILMODE_SAFE and (is_fail_open or PrimaryOnlyManager.is_primary_only_enabled())


def get_fail_open_msg():
    """Determines the fail open message depending on if the Authentication Proxy
    is running in primary mode or not.

    Returns:
        string: a fail open message
    """
    if PrimaryOnlyManager.is_primary_only_enabled():
        return PRIMARY_ONLY_FAILMODE_SAFE_MSG

    return FAILMODE_SAFE_MSG


def rotate_indicated(response, status):
    if 'not_upgraded' in response and response['not_upgraded'] == 'rotate':
        return True

    return False


def proxy_not_found(response, status):
    if 'code' in response and str(response['code']) == '40401' and str(status) == '404':
        return True
    return False


def bad_signature(response, status):
    return 'code' in response and str(response['code']) == '40103' and str(status) == '401'


class BaseDuoClient(abc.ABC):

    # overall default timeout: whatever the requestor decides
    TIMEOUT_DEFAULT = 0
    ping_endpoint = '/auth/v2/ping'
    signature_hash = hashlib.sha1

    def __init__(self, host, duo_creds, port=443,
                 requestor=http.request, timeout_default=TIMEOUT_DEFAULT):
        """
        * requestor: Function API-compatible with http.request. Must
          return a Deferred.
        """
        self.duo_creds = duo_creds
        self.host = host
        self.port = port
        self.requestor = requestor
        self.time_offset = 0  # Between local clock and service.

        # per-instance default timeout
        self.timeout_default = timeout_default

    @staticmethod
    def encode_params(params):
        """Like urllib.urlencode, but sorted by name, and ~ values escaped."""
        result = []
        for k, v in sorted(params.items()):
            if isinstance(k, str):
                k = k.encode('utf-8')
            if isinstance(v, str):
                v = v.encode('utf-8')
            result.append('%s=%s' % (urllib.parse.quote(k, '~'), urllib.parse.quote(v, '~')))
        return '&'.join(result)

    def _sign_request(self, method, uri, params, date=None):
        """Return request signature as HTTP basic authorization header."""
        url = self._get_canonical_url(method, uri, params, date)
        return self._get_signature(url)

    def _get_canonical_url(self, method, uri, params, date):
        if not isinstance(params, str):
            params = self.encode_params(params)

        if date is None:
            canon = []
        else:
            canon = [date]
        canon += [method.upper(), self.host.lower(), uri, params]
        canon = '\n'.join(canon)
        return canon

    def _get_signature(self, canon):
        """ Signs the provided string as utf-8 encoded bytes using an identity and secret key

        Args:
            canon (str): String to be signed

        Returns:
            a string of the form 'Basic <base-64 encoded signature>'

        """
        ctx = hmac.new(self.duo_creds.get_secret(), canon.encode(), self.signature_hash)
        auth = '%s:%s' % (self.duo_creds.get_identity(), ctx.hexdigest())
        return 'Basic ' + base64.b64encode(auth.encode()).decode()

    def _format_request(self, method, uri, params, signature_version):
        url = 'https://%s:%d%s' % (self.host, self.port, uri)
        qs = self.encode_params(params)

        if signature_version != 1:
            d = datetime.datetime.utcnow()
            d += datetime.timedelta(seconds=self.time_offset)
            date = d.strftime('%a, %d %b %Y %H:%M:%S -0000')
            headers = {
                'Date': date,
                'Authorization': self._sign_request(method, uri, qs, date=date)
            }
        else:
            headers = {'Authorization': self._sign_request(method, uri, qs)}

        if method == 'GET':
            if qs:
                url += '?' + qs
                qs = None
        else:
            headers['Content-Type'] = 'application/x-www-form-urlencoded'

        return (method, url, qs, headers)

    @defer.inlineCallbacks
    def call(self, method, uri, params, timeout=None,
             force_fail_closed=False, expect_type=dict, signature_version=1):
        if signature_version != 1:
            yield self.ping()

        request_args = self._format_request(method, uri, params, signature_version)

        code, data, headers = yield self._request(
            *request_args,
            force_fail_closed=force_fail_closed,
            timeout=timeout
        )
        res = self._parse_response(code, data, expect_type=expect_type)
        defer.returnValue(res)

    @abc.abstractmethod
    def _request(self, method, url, body, headers, timeout=None,
                 force_fail_closed=False, **kwargs):
        raise NotImplementedError("BaseDuoClient is an abstract base clase")

    @staticmethod
    def _parse_response(code, data, expect_type=dict):
        try:
            rsp = json.loads(data)
            if rsp['stat'] == 'OK':
                res = rsp['response']
            elif rsp['stat'] == 'FAIL':
                msg = ('%s: %s' % (rsp['code'], rsp['message']))
                if str(code).startswith('5'):
                    raise DuoAPIFailOpenError(msg, info=rsp)
                else:
                    raise DuoAPIFailClosedError(msg, info=rsp)
            else:
                raise DuoAPIMalformedResponseError('stat', info=rsp)
        except (ValueError, KeyError):
            # some sort of parse error. if we got a 200 response, this
            # is weird; otherwise, it's less weird
            if code != 200:
                msg = 'API request failed: HTTP Error %d' % code
            else:
                msg = 'Invalid Remote API Response: %r' % data
            # response?
            if str(code).startswith('5'):
                raise DuoAPIFailOpenError(msg, info={'code': code})
            else:
                raise DuoAPIFailClosedError(msg, info={'code': code})
        if not (res and isinstance(res, expect_type)):
            raise DuoAPIFailOpenError('Malformed API Response', info={'code': code})
        return res

    @defer.inlineCallbacks
    def ping(self):
        start = int(time.time())
        res = yield self.call('GET', self.ping_endpoint, {}, signature_version=1)

        # Validate result format.
        server_time = res.get('time')
        if not server_time:
            raise DuoAPIMalformedResponseError('time')

        self.time_offset = res['time'] - start
        defer.returnValue(res)


class AuthDuoClient(BaseDuoClient):
    TIMEOUT_DEFAULT = 0
    ping_endpoint = '/auth/v2/ping'
    signature_hash = hashlib.sha1

    def _request(self, method, url, body, headers, timeout=None,
                 force_fail_closed=False, **kwargs):
        self.primary_only_check()

        if timeout is None:
            timeout = self.timeout_default
        d = self.requestor(method, url, body, headers,
                           timeout=timeout,
                           **kwargs)

        def err_func(err):
            if force_fail_closed:
                raise DuoAPIFailClosedError(
                    'API Request Failed: %r' % err.value
                )
            else:
                raise DuoAPIFailOpenError(
                    'API Request Failed: %r' % err.value
                )
        d.addErrback(err_func)
        return d

    @defer.inlineCallbacks
    def preauth(self, username, client_ip, failmode=FAILMODE_UNKNOWN):
        if client_ip is None:
            client_ip = '0.0.0.0'

        params = dict(user=username, ipaddr=client_ip, failmode=failmode)
        preauth_res = yield self.call('POST', '/rest/v1/preauth', params, signature_version=1)

        # validate preauth result format
        result = preauth_res.get('result', None)
        if result in (API_RESULT_ALLOW, API_RESULT_DENY, API_RESULT_ENROLL):
            if 'status' not in preauth_res:
                raise DuoAPIMalformedResponseError('status')
        elif result == API_RESULT_AUTH:
            if not isinstance(preauth_res.get('factors', None), dict):
                raise DuoAPIMalformedResponseError('factors')
            elif 'prompt' not in preauth_res:
                raise DuoAPIMalformedResponseError('prompt')
        else:
            raise DuoAPIMalformedResponseError('result')

        defer.returnValue(preauth_res)

    @staticmethod
    def primary_only_check():
        if PrimaryOnlyManager.is_primary_only_enabled():
            raise DuoAPIFailOpenError('The proxy is operating in primary-only mode')

    @defer.inlineCallbacks
    def auth(self, username, passcode, client_ip):
        if client_ip is None:
            client_ip = '0.0.0.0'

        if len(passcode) > MAX_FACTOR_OR_PASSCODE_LENGTH:
            raise DuoAPIError('Factor or passcode length cannot exceed {}'.format(MAX_FACTOR_OR_PASSCODE_LENGTH))

        params = dict(user=username, factor='auto', auto=passcode,
                      ipaddr=client_ip)

        auth_res = yield self.call(
            'POST', '/rest/v1/auth', params, force_fail_closed=True, signature_version=1)

        # validate auth result format
        potential_auth_results = (API_RESULT_ALLOW, API_RESULT_DENY)
        if not auth_res.get('result', None) in potential_auth_results:
            raise DuoAPIMalformedResponseError('result')
        elif 'status' not in auth_res:
            raise DuoAPIMalformedResponseError('status')
        defer.returnValue(auth_res)

    @defer.inlineCallbacks
    def proxy_init(self, username):
        init_res = yield self.call('POST', '/rest/v1/tx/proxy_init',
                                   dict(user=username), signature_version=1)

        # validate init result format
        if 'proxy_txid' not in init_res:
            raise DuoAPIMalformedResponseError('proxy_txid')
        defer.returnValue(init_res)

    @defer.inlineCallbacks
    def proxy_finish(self, auth_cookie):
        finish_res = yield self.call('POST', '/rest/v1/tx/proxy_finish',
                                     dict(auth_cookie=auth_cookie), signature_version=1)

        # validate init result format
        if 'valid_cookie' not in finish_res:
            raise DuoAPIMalformedResponseError('valid_cookie')
        elif finish_res['valid_cookie'] and 'user' not in finish_res:
            raise DuoAPIMalformedResponseError('user')
        defer.returnValue(finish_res)


class HTTPClientDRPC(twistedHTTPClient, abc.ABC):
    """
    Abstract HTTP client for upgrade to DRPC.
    Do not instantiate directly. Missing:
        - make_drpc_server_factory
    """
    def __init__(self,
                 duo_client,
                 server_module,
                 drpc_path,
                 *args, **kwargs):
        self.duo_client = duo_client
        self.server_module = server_module
        self.drpc_path = drpc_path
        self.rpc_server = None
        super(HTTPClientDRPC, self).__init__(*args, **kwargs)

    @abc.abstractmethod
    def make_drpc_server_factory(self, time_offset, response):
        """ Function returns an instance of DRPC Server Factory
        Subclass should implement this function to return a ServerFactory
        appropriate to their version and use case. """
        raise NotImplementedError("Children class must implement this function for their specific DRPC version and use case")

    def lineReceived(self, line):
        if self.rpc_server:
            return self.rpc_server.dataReceived(line)
        else:
            return super(HTTPClientDRPC, self).lineReceived(line)

    def rawDataReceived(self, data):
        if self.rpc_server:
            return self.rpc_server.dataReceived(data)
        if self.length is not None:
            data, rest = data[:self.length], data[self.length:]
            self.length -= len(data)
        else:
            rest = b''
        self.handleResponsePart(data)
        if self.length == 0:
            self.handleResponseEnd()
            if self.rpc_server:
                self.rpc_server.dataReceived(rest)
            else:
                self.setLineMode(rest)

    def connectionMade(self):
        """ This function is called after our connection to
        https://api-host.duo.com:443 is complete. At this point we don't
        have a connection to specific web handler. In this method we will
        send the commands and headers to make the connection to the join handler.
        We will also send along the headers to request the HTTP upgrade to drpc. """
        path = self.drpc_path
        method = 'POST'

        d = datetime.datetime.utcnow()
        d += datetime.timedelta(seconds=self.duo_client.time_offset)
        date = d.strftime('%a, %d %b %Y %H:%M:%S -0000')

        self.sendCommand(method, path)
        self.sendHeader(b'Host', self.factory.headers.get(b'host',
                                                          self.factory.host))
        self.sendHeader(b'User-Agent', self.factory.agent)
        auth = self.duo_client._sign_request(
            method=method,
            uri=path,
            params={},
            date=date,
        )
        self.sendHeader(b'Authorization', auth)
        self.sendHeader(b'Connection', 'upgrade')
        self.sendHeader(b'Content-Length', '0')
        self.sendHeader(b'Content-Type', 'application/x-www-form-urlencoded')
        self.sendHeader(b'Date', date)
        self.sendHeader(b'Upgrade', 'drpc')
        self.endHeaders()

    def sendCommand(self, command, path):
        self.transport.writeSequence([command.encode(),
                                      b' ',
                                      path.encode(),
                                      b' HTTP/1.1\r\n'])

    def handleStatus(self, version, status, message):
        self.factory.gotStatus(version, status, message)

    def handleResponse(self, response):
        """ This function is called with the response from the actual handler.
        In this method we will check the status and make sure it's okay to proceed
        with our connection. If so, we swap out the protocol and factory on the transport so data
        will now flow through DRPC protocols.
        Args:
            response (json): data from Duo Cloud
        Effects:
            Fires a deferred on the factory's deferred either with an error if HTTP status is bad
            or with the new drpc protocol object if everything is good
        """
        def disconnect(error):
            """
            Terminate the connection and send the waiting Deferred the reason why.
            """
            self.transport.abortConnection()
            self.factory.noPage(error)
            self.factory._disconnectedDeferred.callback(None)

        def err(reason):
            """
            Send a DuoAPIProxyJoinError back to original caller and close the
            connection.  Convenience wrapper around the disconnect method.
            """
            disconnect(DuoAPIProxyJoinError(reason, info=response))

        # Parse HTTP response.
        status = self.factory.status
        if str(int(status)) not in ('101', '200', '401', '404'):
            try:
                resp_dict = json.loads(response)
            except ValueError:
                resp_dict = {}
            err(self._build_error_message(resp_dict, status))
            return
        try:
            response = json.loads(response)
        except Exception:
            err('Malformed HTTP response')
            return
        if not isinstance(response, dict):
            err('Malformed HTTP response')
            return
        if proxy_not_found(response, status):
            disconnect(DuoAPIProxyNotFoundError())
            return
        if bad_signature(response, status):
            disconnect(DuoAPIBadSignatureError())
            return
        if str(int(status)) in ('401', '404'):
            err(self._build_error_message(response, status))
            return
        if response.get('stat') != 'OK':
            err('Failed HTTP response')
            return
        response = response.get('response')
        if not isinstance(response, dict):
            err('Malformed HTTP response')
            return
        if response.get('call_message_type') != 0:
            err('Unknown protocol version')
            return
        if rotate_indicated(response, status):
            disconnect(DuoAPIRotateRequiredError())
            return

        # Calculate time offset.
        server_time = response.get('time')
        if server_time:
            time_offset = server_time - int(time.time())
        else:
            time_offset = self.duo_client.time_offset

        # Build DRPC protocol to take over the connection.
        trans = self.transport
        factory = self.make_drpc_server_factory(time_offset, response)
        self.rpc_server = factory.buildProtocol(trans.getPeer())
        self.rpc_server.makeConnection(trans)

        # Tell the transport to send data to the RPC server from now
        # on instead of the original protocol. If TLS-wrappered,
        # however, need to get plaintext, not the raw data.
        if trans.TLS:
            # trans.protocol is a TLSMemoryBIOProtocol initiated by
            # startTLS because the connection uses an HTTPS proxy.
            trans.protocol.wrappedProtocol = self.rpc_server
        elif hasattr(trans, 'wrappedProtocol'):
            # From connectSSL().
            trans.wrappedProtocol = self.rpc_server
        else:
            # Not TLS. Update raw, unwrapped transport.
            trans.protocol = self.rpc_server

        # Smuggle DRPC protocol (and protocol.factory) back to caller of proxy_join.
        self.factory.page(self.rpc_server)
        self.factory._disconnectedDeferred.callback(None)

    def connectionLost(self, reason):
        if self.rpc_server:
            return self.rpc_server.connectionLost(reason)
        else:
            self.factory.noPage(DuoAPIProxyJoinError('Connection lost'))
            if not self.factory._disconnectedDeferred.called:
                self.factory._disconnectedDeferred.callback(None)
            return super(HTTPClientDRPC, self).connectionLost(reason)

    @staticmethod
    def _build_error_message(response, status):
        response_message = response.get('message', "Error not available")
        error_message = "Unexpected HTTP status {status}. Error message: {err_msg}".format(status=status, err_msg=response_message)

        return error_message


class DirectorySyncHTTPClient(HTTPClientDRPC):
    """ http client for directory sync use case. """
    def make_drpc_server_factory(self, time_offset, response):
        return DirectorySyncServerFactory(
            module=self.server_module,
            ikey=self.duo_client.duo_creds.get_identity(),
            skey=self.duo_client.duo_creds.get_secret(),
            time_offset=time_offset,
            auto_zlib_min_length=response.get('auto_zlib_min_length'),
            enable_unzlib=True,
            idle_rpc_timeout=response.get('idle_rpc_timeout', 600),
        )


class CloudSSOHTTPClient(HTTPClientDRPC):
    """ http client for cloudsso use case. """
    def make_drpc_server_factory(self, time_offset, response):
        return CloudSSOServerFactory(
            module=self.server_module,
            drpc_creds=self.duo_client.duo_creds.create_drpc_credentials(),
            time_offset=time_offset,
            auto_zlib_min_length=response.get('auto_zlib_min_length'),
            enable_unzlib=True,
            idle_rpc_timeout=response.get('idle_rpc_timeout', 600),
        )


class DRPCDuoClient(BaseDuoClient, abc.ABC):

    @abc.abstractproperty
    def ping_endpoint(self):
        raise NotImplementedError()

    @abc.abstractproperty
    def signature_hash(self):
        raise NotImplementedError()

    @abc.abstractproperty
    def http_client(self):
        raise NotImplementedError()

    @staticmethod
    def primary_only_check():
        # Primary only mode doesn't make sense with a drpcserv client
        pass

    # Override the _request method because the failmode logic doesn't apply to DRPCServ connections
    def _request(self, method, url, body, headers, timeout=None, force_fail_closed=False, **kwargs):
        if timeout is None:
            timeout = self.timeout_default
        d = self.requestor(method, url, body, headers,
                           timeout=timeout,
                           **kwargs)

        def err_func(err):
            raise err

        d.addErrback(err_func)
        return d

    @defer.inlineCallbacks
    def proxy_join(self, server_module, drpc_path):
        """
        Connects a proxy to the Duo service and establishes a long lived connection.
        Args:
            server_module (module): A module that implements the methods from the DRPC plugin interface
            drpc_path (str): url path to the join endpoint
        """
        try:
            yield self.ping()       # Update self.time_offset. Needed for sigV2+.

            # Open a request normally (using configured HTTPS proxy,
            # etc.), but upgrade protocol to DRPC instead of calling API.
            method = 'POST'
            _status, rpc_protocol, _headers = yield self._request(
                method=method,
                # URL used only for scheme, host, and port.
                url=('https://{0}:{1:d}/'.format(self.host, self.port)),
                body='',            # overridden in protocol.
                headers={},         # overridden in protocol to sign with v2.
                timeout=self.timeout_default,
                protocol_class=functools.partial(
                    self.http_client,
                    duo_client=self,
                    server_module=server_module,
                    drpc_path=drpc_path,
                ),
                disconnect=False,
            )
            defer.returnValue(rpc_protocol)
        except ConnectionRefusedError as e:
            log.msg("Encountered exception while attempting to join. Error: {}".format(e))
            # Translate exception into DuoAPIError so that the interface is the same
            # for all callers.
            raise DuoAPIError(str(e))


class DirectorySyncDuoClient(DRPCDuoClient):
    ping_endpoint = '/auth/v2/ping'
    signature_hash = hashlib.sha1
    http_client = DirectorySyncHTTPClient


class CloudSSODuoClient(DRPCDuoClient):
    signature_hash = hashlib.sha512
    ping_endpoint = '/drpc/v1/ping'
    http_client = CloudSSOHTTPClient

    @defer.inlineCallbacks
    def proxy_rotate_skeys(self, proxy_public_key):
        """
        Call the DRPC endpoint to exchange public keys as part of rotating skeys via ECDHE

        Args:
            proxy_public_key (bytes): a public key

        Returns:
            (dict) the result of the call, which if successful will contain Duo's public key as a unicode

        Raises:
            DuoAPIMalformedResponse if the response does not contain a 'duo_public_key' entry
            DuoAPIFailOpenError / DuoAPIFailClosedError for various request/response problems
        """
        DUO_PUBLIC_KEY = 'duo_public_key'

        rotate_res = yield self.call(
            'POST',
            DRPC_ROTATE_ENDPOINT,
            dict(proxy_public_key=proxy_public_key),
            signature_version=2
        )

        if DUO_PUBLIC_KEY not in rotate_res:
            raise DuoAPIMalformedResponseError(DUO_PUBLIC_KEY)

        defer.returnValue(rotate_res)
