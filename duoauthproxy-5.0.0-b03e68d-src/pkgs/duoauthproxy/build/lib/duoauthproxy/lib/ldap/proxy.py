#
# Copyright (c) 2012 Duo Security
# All Rights Reserved
#
from __future__ import annotations

import functools
import sys
import time
from typing import TYPE_CHECKING, Any, Callable

from ldaptor.protocols import pureldap
from ldaptor.protocols.ldap import ldapclient, ldapconnector, ldaperrors, ldapserver
from OpenSSL import SSL
from twisted.internet import defer, error, reactor
from twisted.python.failure import Failure

from duoauthproxy.lib.looping_call import LoopingCall
from duoauthproxy.lib.util import safe_string_decode

from .. import log

if TYPE_CHECKING:
    from ldaptor.protocols.pureldap import LDAPExtendedRequest

STARTTLS_NOT_SUPPORTED_ERROR_MESSAGE = (
    "Received starttls request for ldap_server_auto without proper tls "
    "configuration. To make starttls requests, add ssl_key_path and ssl_cert_path"
    " to the [ldap_server_auto] section of the config file. For more on "
    "configuring LDAP Auto, see https://duo.com/docs/authproxy-reference#ldap-auto"
)


class Proxy(ldapserver.BaseLDAPServer, object):
    def __init__(
        self,
        sslctx=None,
        network_timeout=(10 * 60),  # 10m
        idle_timeout=(60 * 60),  # 1hr
        debug=False,
        is_logging_insecure=False,
        **kwargs
    ):
        self.reactor = reactor
        self.debug = debug
        self.is_logging_insecure = is_logging_insecure
        ldapserver.BaseLDAPServer.__init__(self)
        self.__client_connected = None
        self.__client = None
        self.bound = 0
        self.sslctx = sslctx
        self.server_section_name = kwargs.get("server_section_name", "Unknown")
        self.server_section_ikey = kwargs.get("server_section_ikey", "Unknown")

        # Shut down both connections if a connection attempt or
        # request to the backing server takes too long.
        self.network_timeout = network_timeout

        # Detect idle clients and shut down both connections.
        self.idle_timeout = idle_timeout
        self.last_activity = 0
        self.activity_lc = None
        self.timeout_dcs = set()

    @defer.inlineCallbacks
    def make_connected_client(self):
        """
        Return a connected _ADServiceClientProtocol instance.
        """
        raise NotImplementedError()

    @defer.inlineCallbacks
    def connectionMade(self):
        self.__client_connected = self.make_connected_client()
        try:
            self.__client = yield self.__client_connected
        except Exception:
            # Connection error returned when handling actual requests.
            pass
        else:
            if self.debug:
                self.__client.debug = self.debug
            if self.is_logging_insecure:
                self.__client.is_logging_insecure = self.is_logging_insecure
            self.__client.unsolicited_notification_handler = (
                self._handle_unsolicited_notifications
            )
            self.__client.upstream_server_disconnect_handler = (
                self._handle_upstream_server_disconnect
            )
            self.__client.transport.setTcpKeepAlive(True)
            self.last_activity = time.time()
            self.activity_lc = LoopingCall(self.check_activity, clock=self.reactor)
            self.activity_lc.start(1, False)  # 1s

            if self.debug and self.transport.connected:
                try:
                    peer = self.transport.getPeer()
                    host = self.transport.getHost()
                    log.msg(
                        "Connection made between client: {client_host}:{client_port} and the server section listening via {server_host}:{server_port}.".format(
                            client_host=peer.host,
                            client_port=peer.port,
                            server_host=host.host,
                            server_port=host.port,
                        )
                    )
                except Exception as e:
                    # Logging error instead of failure to not include tracebacks in the logs
                    # for this situation.
                    log.error(
                        "Error logging client and host information: {error}",
                        error=str(e),
                    )

        ldapserver.BaseLDAPServer.connectionMade(self)

    @defer.inlineCallbacks
    def connectionLost(self, reason):
        yield self.__client_connected  # wait for self.__client to exist
        # Disconnect the connection to the backing server.
        self.bound = 0
        if self.activity_lc:
            self.activity_lc.stop()
            self.activity_lc = None
        if self.__client is not None and self.__client.connected:
            # Choosing to abortConnection over loseConnection
            # because if the connection closes before the TLS
            # handshake completes then loseConnection won't
            # properly tear down.
            self.__client.transport.abortConnection()

        self.__client = None
        self.cleanup_all()
        if reason.check(SSL.Error):
            # Print a log error about setting minimum_tls_version if there are SSL issues
            log.msg(
                "The downstream application and the Authentication Proxy were not able to establish an SSL connection. It is possible this is because of a TLS protocol mismatch."
                " The minimum_tls_version currently allowed may be higher than your application can speak. Please look into setting the `minimum_tls_version` option in your [{}] section"
                " if you need to use a lower version of the TLS Protocol. Error message: {}.".format(
                    self.server_section_name, reason.getErrorMessage()
                )
            )
        elif self.debug:
            log.msg(
                "Closing the connection between the downstream application and the Authentication Proxy. Reason: {}".format(
                    reason.getErrorMessage()
                )
            )
        ldapserver.BaseLDAPServer.connectionLost(self, reason)

    def handle_LDAPAbandonRequest(self, request, controls, reply_fn):
        """ Drop LDAPAbandonRequest requests. """
        pass

    def handle_LDAPUnbindRequest(self, request, controls, reply_fn):
        self.bound = 0
        return self.handleUnknown(request, controls, reply_fn)

    @defer.inlineCallbacks
    def handleUnknown(self, request, controls, reply_fn):
        self.last_activity = time.time()
        yield self.__client_connected  # wait for self.__client to exist

        if self.__client is None:
            response = self._error_for_backing_failure(request)
            defer.returnValue(response)

        # Send request to backing server, calling reply with results.
        if request.needs_answer:
            # No reply within self.network_timeout? Shut it down!
            timeout_dc = self.reactor.callLater(
                self.network_timeout, self._tear_down_connection,
            )
            self.timeout_dcs.add(timeout_dc)
            # Call multiresponse_handler() with one or more responses:
            try:
                yield self.__client.send(
                    request,
                    controls=controls,
                    handler=functools.partial(
                        self.multiresponse_handler,
                        request=request,
                        reply_fn=reply_fn,
                        timeout_dc=timeout_dc,
                    ),
                    return_controls=True,
                )
            except (
                # LDAPClient.connectionLost while request was queued:
                error.ConnectionDone,
                # send() called after __client's connection closed:
                ldapclient.LDAPClientConnectionLostException,
                # Timeout:
                error.ConnectionLost,
            ):
                response = self._error_for_backing_failure(request)
                defer.returnValue(response)
        else:
            yield self.__client.send_noResponse(request)
        return  # no response except via reply()

    def _handle_unsolicited_notifications(self, msg):
        """ This function should be used as a handler to give to an ldap client
        that wants to relay unsolicited notifcations from the upstream server to
        the downstream client.
        """
        # Ignore all unsolicited notifications except server disconnect
        if msg.resultCode == ldaperrors.LDAPUnavailable.resultCode:
            log.msg(
                "Dropping connection between proxy and client due to upstream server unavailability"
            )
            self._tear_down_connection()

    def _handle_upstream_server_disconnect(self, reason, host, port):
        """ This function should be used as a handler to give to an ldap client
        that wants to proxy a TCP disconnect from the upstream server to the downstream client.
        """
        # Our connection to the downstream client is still alive. Let's kill it
        if self.connected:
            log.msg(
                "The upstream LDAP server ({host}:{port}) has closed its connection to the proxy. Now closing our connection to the downstream client. Reason given for close: {reason}.".format(
                    host=host, port=port, reason=reason
                )
            )
            self._tear_down_connection()

    def _error_for_backing_failure(self, request):
        """
        Create or raise the correct response to the request to indicate
        that the connection to the backing server failed.
        """
        msg = "Connection error"
        if isinstance(request, pureldap.LDAPBindRequest):
            log.auth(
                msg="LDAP Connection error occurred during bind",
                dn=safe_string_decode(request.dn),
                auth_stage=log.AUTH_PRIMARY,
                status=log.AUTH_ERROR,
                server_section=self.server_section_name,
            )
            return pureldap.LDAPBindResponse(
                resultCode=ldaperrors.LDAPUnavailable.resultCode, errorMessage=msg,
            )
        else:
            raise ldaperrors.LDAPUnavailable(msg)

    def multiresponse_handler(self, value, controls, timeout_dc, **kwargs):
        """
        Decide how to handle one part of a multiResponse.
        """
        # Timeout tracking
        try:
            self.timeout_dcs.remove(timeout_dc)
        except KeyError:
            pass
        if timeout_dc.active():
            timeout_dc.cancel()
        self.last_activity = time.time()

        # State tracking
        if (
            isinstance(value, pureldap.LDAPBindResponse)
            and value.resultCode == ldaperrors.Success.resultCode
        ):
            self.bound += 1

        # Asynchronously relay response. Can't return a deferred here.
        self.relay_response(value, response_controls=controls, **kwargs)

        # Return True to send_multiResponse() iff it's the final
        # response.
        return isinstance(
            value, (pureldap.LDAPBindResponse, pureldap.LDAPSearchResultDone,)
        )

    def relay_response(self, response, reply_fn, request=None, response_controls=None):
        """
        Relay response from the backing server to this proxy's client.

        Can do so synchronously or asynchronously. The return value is
        ignored.
        """
        reply_fn(response, response_controls=response_controls)

    @defer.inlineCallbacks
    def dn_to_username(self, dn):
        # Open a second client connection to the primary LDAP server.
        client = yield self.make_connected_client()
        try:
            # Primary bind as the service user.
            yield client.primary_bind()
            username = yield client.dn_to_username(dn, client.factory)
            yield client.perform_unbind()
        finally:
            client.transport.abortConnection()
        defer.returnValue(username)

    @defer.inlineCallbacks
    def username_to_dn(self, username):
        # Open a another client connection to the primary LDAP server.
        client = yield self.make_connected_client()
        try:
            # Primary bind as the service user.
            yield client.primary_bind()
            dn = yield client.username_to_dn(username)
            yield client.perform_unbind()
        finally:
            client.transport.abortConnection()
        defer.returnValue(dn)

    def handle_LDAPExtendedRequest(
        self,
        request: LDAPExtendedRequest,
        controls: pureldap.LDAPControl,
        reply_fn: Callable[..., None],
    ) -> Any:
        # Handle STARTTLS locally; proxy everything else.
        if request.requestName != pureldap.LDAPStartTLSRequest.oid:
            return self.handleUnknown(request, controls, reply_fn)

        if not self.sslctx:
            raise ldaperrors.LDAPProtocolError(STARTTLS_NOT_SUPPORTED_ERROR_MESSAGE)

        self.checkControls(controls)  # assert can ignore controls, then do so

        try:
            # Send reply indicating TLS negotiation should start.
            msg = pureldap.LDAPExtendedResponse(
                resultCode=ldaperrors.Success.resultCode,
                responseName=pureldap.LDAPStartTLSRequest.oid,
            )
            reply_fn(msg)
            # Start TLS negotiation!
            self.transport.startTLS(self.sslctx, self.factory)
        except ldaperrors.LDAPException:
            raise
        except Exception:
            raise ldaperrors.LDAPUnwillingToPerform()

    def check_activity(self):
        cutoff = time.time() - self.idle_timeout
        if self.last_activity < cutoff:
            self.transport.loseConnection()

    def cleanup_all(self):
        """
        Immediately clean up all request state including cleanup
        delayed calls and idle detection.
        """
        if self.activity_lc:
            self.activity_lc.stop()
            self.activity_lc = None
        for timeout_dc in self.timeout_dcs:
            if timeout_dc.active():
                timeout_dc.cancel()
        self.timeout_dcs.clear()

    def _cbHandle(self, *args, **kwargs):
        try:
            return ldapserver.BaseLDAPServer._cbHandle(self, *args, **kwargs)
        except ldapserver.LDAPServerConnectionLostException:
            if self.__client is not None:
                raise

    def _tear_down_connection(self):
        """ Helper function to bring down the connection between the proxy and the ldap client
        in the case of unexpected disconnects
        """
        self.transport.abortConnection()
        # Cleanup self.__client and so forth:
        self.connectionLost(Failure(error.ConnectionLost()))


class ProxyToLDAPConfig(Proxy):
    """
    Proxy that connects according to an LDAPConfig.
    """

    def __init__(self, cfg):
        """
        @param cfg: The configuration.
        @type cfg: ldaptor.interfaces.ILDAPConfig
        """
        Proxy.__init__(self)
        self.cfg = cfg

    def make_connected_client(self):
        client_creator = ldapconnector.LDAPClientCreator(
            reactor=reactor, protocolClass=ldapclient.LDAPClient,
        )
        return client_creator.connect(
            dn="", overrides=self.cfg.getServiceLocationOverrides(),
        )


if __name__ == "__main__":
    import twisted.internet
    import twisted.python
    import ldaptor.config

    twisted.python.log.startLogging(sys.stderr)
    backing_host = sys.argv[1]
    backing_port = int(sys.argv[2])
    listening_port = int(sys.argv[3])
    config = ldaptor.config.LDAPConfig(
        serviceLocationOverrides={"": (backing_host, backing_port),}
    )
    factory = twisted.internet.protocol.ServerFactory()
    factory.protocol = functools.partial(ProxyToLDAPConfig, config)
    reactor.listenTCP(listening_port, factory)
    reactor.run()
