#
# Copyright (c) 2011 Duo Security
# All Rights Reserved
#
import time

from twisted.internet import defer, protocol, reactor

from ldaptor.protocols import pureldap
from ldaptor.protocols.ldap import ldaperrors, distinguishedname

from ..lib import log
from ..lib import ldap
from ..lib import util
from ..lib.base import AuthResult, ClientModule


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
        except ldaperrors.LDAPException as e:
            log.msg('Initial LDAP bind to AD failed: %r' % str(e))
            yield self.error()
            raise _ADAuthError('Initial LDAP bind to AD failed: %r' % str(e))

        username_attribute = self.factory.username_attribute
        if username_attribute.lower() == 'samaccountname' and '\\' in username:
            principal_name = username
            domain, username = username.split('\\', 1)
        else:
            domain = self.factory.ntlm_domain
            principal_name = ''

        # This allows us to search for a different attribute if the username
        # looks like a userPrincipalName (or email address). We can then
        # attempt to authenticate the user without requiring them to remember
        # to use their sAMAccountName or msDS-PrincipalName
        if '@' in username:
            username_attribute = self.factory.at_attribute

        username_match = {username_attribute: username}
        filterObject = yield self.user_filter_object(username_matches=username_match)
        attributes = (username_attribute, 'msds-PrincipalName')

        # search for the user. With AD, the user's cn is his/her full
        # name, not username so we need to search for a specific
        # attribute value instead (typically, the 'sAMAccountName'
        # attribute)
        try:
            result = yield self.perform_search(self.factory.search_dn, filterObject, attributes=attributes)

            if self.factory.domain_discovery:
                # Use the domain returned in the user's principal name
                result_pnames = [
                    next(u['msDS-PrincipalName'].__iter__())
                    for u in result
                    if 'msDS-PrincipalName' in u and u['msDS-PrincipalName']
                ]
                if len(result_pnames) > 1:
                    log.msg("Domain discovery failed due to multiple user results.")
                elif len(result_pnames) == 1 and b'\\' in result_pnames[0]:
                    domain_bytes = result_pnames[0].split(b'\\')[0]
                    domain = domain_bytes.decode()

            # If we have more than one result, narrow it down by msDS-PN
            if len(result) != 1:
                for user in result:
                    if principal_name:
                        user_principal_name = list(user.get('msDS-PrincipalName', [b'']))[0]
                        if user_principal_name.decode().lower() == principal_name.lower():
                            result = [user]
                            break
                else:
                    yield self.finish()
                    defer.returnValue(AuthResult(False, 'Invalid User'))

        except distinguishedname.InvalidRelativeDistinguishedName as e:
            log.msg('Bad AD client configuration value: %r' % str(e))
            yield self.error()
            raise _ADAuthError('Bad AD client configuration value: %r' % str(e))
        except Exception as e:
            log.msg('LDAP search on AD service failed: %r' % str(e))
            yield self.error()
            raise _ADAuthError('LDAP search on AD service failed: %r' % str(e))

        if result[0].get('msDS-PrincipalName'):
            msds_principalname = list(result[0]['msDS-PrincipalName'])[0]
            if b'\\' in msds_principalname:
                domain_bytes, username_bytes = msds_principalname.split(b'\\', 1)
                domain = domain_bytes.decode()
                username = username_bytes.decode()

        # authenticate as the user
        try:
            yield self.perform_bind(
                self.factory.auth_type,
                result[0].dn.getText(), username,
                password,
                domain=domain,
                workstation=self.factory.ntlm_workstation,
            )
        except ldaperrors.LDAPException as e:
            log.msg('LDAP Authentication Failed: %r' % str(e))
            yield self.finish()
            defer.returnValue(AuthResult(False, 'User Authentication Failed'))
            return

        yield self.finish()
        defer.returnValue(AuthResult(
            success=True,
            msg='Active Directory authentication succeeded',
        ))

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
            self.factory.deferred.errback(
                _ADAuthError('AD connection timed out'))
        except defer.AlreadyCalledError:
            pass
        self.transport.abortConnection()

    @defer.inlineCallbacks
    def finish(self):
        yield self.perform_unbind()

        if self.timeout_dc and self.timeout_dc.active():
            self.timeout_dc.cancel()

        # Testing suggests that, immediately after we send an unbind
        # request, the AD server will close the connection. Meanwhile,
        # if we proactively close the connection
        # (self.transport.loseConnection) with LDAPS, the AD server
        # will actually send us an error back - not the end of the
        # world, but it makes the logs ugly. So, we don't bother to
        # actively close the connection here. We'll still abort it if
        # the timeout fires, though.
        if self.cleanup_connections:
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

    def __init__(self,
                 bind_dn,
                 service_account_username,
                 service_account_password,
                 search_dn,
                 auth_type,
                 ntlm_domain,
                 ntlm_workstation,
                 **kwargs):
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

    # For testing
    cleanup_connections = False

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
        p.cleanup_connections = self.cleanup_connections
        return p

    def clientConnectionFailed(self, connector, reason):
        log.msg('AD Connection failed: %r' % reason)
        self.deferred.errback(_ADAuthError('AD Connection failed: %s' % reason))

    def stopFactory(self):
        protocol.ClientFactory.stopFactory(self)
        if not self.deferred.called:
            # can intercept some SSL errors, and this is a pretty poor
            # choice given that it gives absolutely no indication of
            # what happened.

            log.msg('AD Connection closed prematurely')
            self.deferred.errback(
                _ADAuthError('AD Connection closed prematurely'))


class Module(ClientModule):
    def __init__(self, config):
        log.msg('AD Client Module Configuration:')
        log.config(config, lambda x: x in ('service_account_password',
                                           'service_account_password_protected'))

        self.factory_kwargs = util.parse_ad_client(config)
        self.hosts = util.get_host_list(config)
        self.port = util.get_ldap_port(config, self.factory_kwargs['transport_type'])

    @defer.inlineCallbacks
    def authenticate(self, username, password, _client_ip, _pass_through_attrs=None):
        if not password:
            # Assume user authentication never legitimately uses anonymous bind.
            defer.returnValue(AuthResult(False, 'No password.'))

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
            result = yield self._authenticate_with_host(
                host, username, password)
            if result is not None:
                defer.returnValue(result)

        log.msg('No remaining AD fallback hosts; '
                'returning authentication failure...')
        defer.returnValue(AuthResult(False,
                                     'Failed to communicate with any'
                                     ' Active Directory server'))

    @defer.inlineCallbacks
    def _authenticate_with_host(self, host, username, password):
        log.msg('Sending AD authentication request for \'%s\' to \'%s\''
                % (username, host))
        factory = _ADAuthClientFactory(**self.factory_kwargs)
        factory.connect_ldap(host, self.port)
        try:
            client = yield factory.deferred
            result = yield client.authenticate(username, password)
            defer.returnValue(result)
        except ldap.client.ADClientError:
            log.msg('Error sending AD auth request to \'%s\'. '
                    'Trying next fallback host...' % host)
        except Exception:
            log.err(None, 'Unexpected Error sending AD auth request to \'%s\'. '
                    'Trying next fallback host...' % host)
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
                log.msg('Error connecting to AD host \'%s\'.'
                        ' Trying next fallback host...' % host)
            except Exception:
                log.err(None, 'Unexpected error connecting to AD host \'%s\'.'
                        ' Trying next fallback host...' % host)
        raise ldap.client.ADClientError('Failed to communicate with any'
                                        ' Active Directory server')
