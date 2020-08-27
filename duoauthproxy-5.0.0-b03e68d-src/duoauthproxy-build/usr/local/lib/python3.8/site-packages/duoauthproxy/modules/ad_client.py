#
# Copyright (c) 2011 Duo Security
# All Rights Reserved
#
import time

from ldaptor.protocols import pureldap
from ldaptor.protocols.ldap import distinguishedname, ldaperrors
from twisted.internet import defer, protocol, reactor

from ..lib import ldap, log, util
from ..lib.base import AuthResult, ClientModule
from ..lib.ldap.utilities import LdapUsername, LdapUsernameOrigin


class _ADAuthError(ldap.client.ADClientError):
    pass


class _ADServiceClientProtocol(ldap.client.ADClientProtocol):
    def primary_bind(self):
        """
        Perform initial bind as the service user.
        """
        return self.perform_bind(
            auth_type=self.factory.auth_type,
            dn=self.factory.bind_dn,
            username=self.factory.service_account_username,
            password=self.factory.service_account_password,
            domain=self.factory.ntlm_domain,
            workstation=self.factory.ntlm_workstation,
            permit_implicit=True,
        )


class _ADAuthClientProtocol(_ADServiceClientProtocol):
    def __init__(self):
        super(_ADAuthClientProtocol, self).__init__()
        self.timeout_dc = None

    @defer.inlineCallbacks
    def authenticate(self, username, password):
        try:
            yield self.primary_bind()
        except ldaperrors.LDAPStrongAuthRequired as e:
            log.msg(
                "Initial LDAP bind to AD failed: {e}. To correct this you must enable SSL on this connection using 'ssl_ca_certs_file' in the [ad_client] section. Or switch to an authentication type that allows for Windows sign and seal (NTLMv2 or SSPI).",
                e=e,
            )
            yield self.error()
            raise _ADAuthError(
                "Initial LDAP bind to AD failed due to insufficient transport security"
            )
        except ldaperrors.LDAPException as e:
            log.msg("Initial LDAP bind to AD failed: %r" % str(e))
            yield self.error()
            raise _ADAuthError("Initial LDAP bind to AD failed: %r" % str(e))

        # search for the user. With AD, the user's cn is his/her full
        # name, not username so we need to search for a specific
        # attribute value instead (typically, the 'sAMAccountName'
        # attribute)
        try:
            ldap_username = LdapUsername(username, LdapUsernameOrigin.RADIUS)
            user_object = yield self.validate_ldap_username_for_auth(
                ldap_username, self.factory.search_dn
            )
        except ldap.client.NoUserFound as e:
            log.error("{e}", e=e)
            yield self.finish()
            defer.returnValue(AuthResult(False, "Invalid User"))
        except distinguishedname.InvalidRelativeDistinguishedName as e:
            log.error("Bad AD client configuration value: {e}", e=e)
            yield self.error()
            raise _ADAuthError("Bad AD client configuration value: {e}".format(e=e))
        except Exception as e:
            log.error("LDAP search on AD service failed: {e}", e=e)
            yield self.error()
            raise _ADAuthError("LDAP search on AD service failed: {e}".format(e=e))

        # Determine the domain and samaccountname of the user in case we need it for an NTLM or SSPI auth
        msds_principalname = list(user_object.get("msDS-PrincipalName", [b""]))[0]
        if b"\\" in msds_principalname:
            domain_bytes, username_bytes = msds_principalname.split(b"\\", 1)
            domain = domain_bytes.decode()
            ntlm_or_sspi_username = username_bytes.decode()
        else:
            # If we can't determine the domain or samaccountname of the user from MSDSPrincipalName
            # we will just use the configured domain and pass in the original username.
            # This is not an ideal situation as these fields may not be correct, but it's a best effort
            # measure.
            domain = self.factory.ntlm_domain
            ntlm_or_sspi_username = username

        # authenticate as the end user
        try:
            yield self.perform_bind(
                self.factory.auth_type,
                user_object.dn.getText(),
                ntlm_or_sspi_username,
                password,
                domain=domain,
                workstation=self.factory.ntlm_workstation,
            )
        except (ldaperrors.LDAPException, ldap.client.SSPIError) as e:
            log.msg("LDAP Authentication Failed: %r" % str(e))
            yield self.finish()
            defer.returnValue(AuthResult(False, "User Authentication Failed"))
            return

        yield self.finish()
        defer.returnValue(
            AuthResult(success=True, msg="Active Directory authentication succeeded",)
        )

    def connectionLost(self, reason):
        super(_ADAuthClientProtocol, self).connectionLost(reason)

        # connectionLost should get called only after the socket has been
        # properly closed. So, here (and only here) it is safe to cancel our
        # timeout.
        if self.timeout_dc and self.timeout_dc.active():
            self.timeout_dc.cancel()

    def timeout(self):
        # catch-all timeout. This should guarantee that the AD connection(s)
        # get cleaned up - even if the connection is just hanging after
        # everything else has already succeeded
        try:
            self.factory.deferred.errback(_ADAuthError("AD connection timed out"))
        except defer.AlreadyCalledError:
            pass
        self.transport.abortConnection()

    @defer.inlineCallbacks
    def finish(self):
        yield self.perform_unbind()

        if self.timeout_dc and self.timeout_dc.active():
            self.timeout_dc.cancel()

        # https://tools.ietf.org/html/rfc4511#section-5.3
        # Based on RFC document, client should cease ldap exchange
        # and close the transport connection
        self.transport.abortConnection()

    @defer.inlineCallbacks
    def error(self):
        if self.connected:
            # (same rationale as above for not calling
            # self.transport.loseConnection here)
            op = pureldap.LDAPUnbindRequest()
            yield self.send_noResponse(op)


class _ADServiceClientFactory(ldap.client.ADClientFactory):
    protocol = _ADServiceClientProtocol

    def __init__(
        self,
        bind_dn,
        service_account_username,
        service_account_password,
        search_dn,
        auth_type,
        ntlm_domain,
        ntlm_workstation,
        **kwargs
    ):
        super(_ADServiceClientFactory, self).__init__(**kwargs)
        self.bind_dn = bind_dn
        self.service_account_username = service_account_username
        self.service_account_password = service_account_password
        self.search_dn = search_dn
        self.auth_type = auth_type
        self.ntlm_domain = ntlm_domain
        self.ntlm_workstation = ntlm_workstation


class _ADAuthClientFactory(_ADServiceClientFactory):
    protocol = _ADAuthClientProtocol

    def startFactory(self):
        self.__start_time = time.time()
        return protocol.ClientFactory.startFactory(self)

    def buildProtocol(self, addr):
        p = super(_ADAuthClientFactory, self).buildProtocol(addr)

        # determine how much of the timeout has already elapsed
        # and adjust accordingly
        elapsed = time.time() - self.__start_time
        timeout = self.timeout - elapsed
        if timeout <= 0:
            timeout = 0.1
        p.timeout_dc = reactor.callLater(timeout, p.timeout)
        return p

    def clientConnectionFailed(self, connector, reason):
        log.msg("AD Connection failed: %r" % reason)
        self.deferred.errback(_ADAuthError("AD Connection failed: %s" % reason))

    def stopFactory(self):
        protocol.ClientFactory.stopFactory(self)
        if not self.deferred.called:
            # can intercept some SSL errors, and this is a pretty poor
            # choice given that it gives absolutely no indication of
            # what happened.

            log.msg("AD Connection closed prematurely")
            self.deferred.errback(_ADAuthError("AD Connection closed prematurely"))


class Module(ClientModule):

    factory = _ADAuthClientFactory

    def __init__(self, config):
        log.msg("AD Client Module Configuration:")
        log.config(
            config,
            lambda x: x
            in ("service_account_password", "service_account_password_protected"),
        )

        self.factory_kwargs = util.parse_ad_client(config)
        self.hosts = util.get_host_list(config)
        self.port = util.get_ldap_port(config, self.factory_kwargs["transport_type"])

    @defer.inlineCallbacks
    def authenticate(self, username, password, _client_ip, _pass_through_attrs=None):
        if not password:
            # Assume user authentication never legitimately uses anonymous bind.
            defer.returnValue(AuthResult(False, "No password."))

        # General policy here is as follows:
        # * If we can't contact an AD server (connection error or timeout)
        #   fall back to the next one
        # * If we get any errors in the initial bind or the search, it's an
        #   error and we should retry on the next configured AD server.
        #   note that this will catch some configuration errors, and we'll
        #   tend to fail more than once. We can refine this later, if necessary
        # * If we get no results back from the search, auth failed
        # * If the second bind is anything but successful, auth failed
        # * If we can't contact any AD servers, fail closed.

        for host in self.hosts:
            result = yield self._authenticate_with_host(host, username, password)
            if result is not None:
                defer.returnValue(result)

        log.msg(
            "No remaining AD fallback hosts; " "returning authentication failure..."
        )
        defer.returnValue(
            AuthResult(
                False, "Failed to communicate with any" " Active Directory server"
            )
        )

    @defer.inlineCallbacks
    def _authenticate_with_host(self, host, username, password):
        log.msg("Sending AD authentication request for '%s' to '%s'" % (username, host))
        factory = self.factory(**self.factory_kwargs)
        factory.connect_ldap(host, self.port)
        try:
            client = yield factory.deferred
            result = yield client.authenticate(username, password)
            defer.returnValue(result)
        except ldap.client.ADClientError:
            log.msg(
                "Error sending AD auth request to '{host}'. Trying next fallback host...",
                host=host,
            )
        except Exception:
            log.failure(
                "Unexpected Error sending AD auth request to '{host}'. Trying next fallback host...",
                host=host,
            )
        defer.returnValue(None)

    @defer.inlineCallbacks
    def ldap_proxy(self):
        for host in self.hosts:
            factory = _ADServiceClientFactory(**self.factory_kwargs)
            factory.connect_ldap(host, self.port)
            try:
                client = yield factory.deferred
                defer.returnValue(client)
            except ldap.client.ADClientError:
                log.msg(
                    "Error connecting to AD host '{host}'. Trying next fallback host...",
                    host=host,
                )
            except Exception:
                log.failure(
                    "Unexpected error connecting to AD host '{host}'. Trying next fallback host...",
                    host=host,
                )
        raise ldap.client.ADClientError(
            "Failed to communicate with any" " Active Directory server"
        )
