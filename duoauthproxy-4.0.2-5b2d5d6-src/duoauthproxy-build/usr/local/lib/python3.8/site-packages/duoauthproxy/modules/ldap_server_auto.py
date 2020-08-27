#
# Copyright (c) 2012 Duo Security
# All Rights Reserved
#
import copy
import functools

from twisted.internet import reactor, defer
import twisted.internet.protocol

import ldaptor.protocols.pureldap
from ldaptor.protocols.ldap import ldaperrors
from ldaptor.protocols.ldap.distinguishedname import DistinguishedName

from . import ssl_server
from ..lib import log, duo_async, util
from ..lib.util import safe_string_decode
from ..lib.base import ServerModule
from ..lib.ldap.proxy import Proxy
from ..lib.ldap.client import DnLookupFailed
from ..lib.const import DEFAULT_LDAP_PORT, DEFAULT_LDAPS_PORT

DEFAULT_DELIM = ','


class DuoAutoLdapServer(Proxy):
    def __init__(self, factors,
                 primary_ator,
                 failmode,
                 exempt_primary_bind=True,
                 exempt_ous=None,
                 allow_searches_after_bind=True,
                 allow_unlimited_binds=False,
                 **kwargs):
        """
        Duo LDAP server with secondary auth factor pre-selected by admin.

        factors: comma-separated list of factor names like "auto,push".

        exempt_primary_bind: If True, Duo auth will not be performed
        for the first bind request in a session. Otherwise, it will be
        performed for every successful bind.

        exempt_ous: List of base DNs (DistinguishedName objects or
        strings). Duo auth will not be performed for any bind request
        with a DN under one of the listed trees.

        resolving_bind_request: True if a valid BindRequest has been
        received and a BindResponse has not yet been sent back.

        Note: there is currently no support for self-enrollment here!
        """
        if exempt_ous is None:
            exempt_ous = []
        super(DuoAutoLdapServer, self).__init__(**kwargs)
        self.primary_ator = primary_ator
        self.factors = factors
        self.failmode = failmode
        self.exempt_primary_bind = exempt_primary_bind
        self.exempt_ous = [
            DistinguishedName(str(dn).lower())
            for dn in exempt_ous
        ]
        self.no_more_binds = False
        self.allow_searches_after_bind = allow_searches_after_bind
        self.allow_unlimited_binds = allow_unlimited_binds
        self.resolving_bind_request = False

    def logPrefix(self):
        """Log messages from this Protocol will contain this prefix to help identify what section they are for"""
        return self.server_section_name

    def log_request(self, request, log_msg):
        addr = self.transport.getPeer()
        log.msg('[Request from %s:%d] %s' % (
            addr.host,
            addr.port,
            log_msg,
        ))

    @defer.inlineCallbacks
    def _request_do_concat(self, request):
        """
        Check if request is possibly a concat-type BindRequest containing a delimiter and a factor.
        """
        if not self.factory.allow_concat:
            defer.returnValue(False)

        if request.sasl:
            # Explicitly exempt SASL requests because no concat is
            # possible. They have ('SASL mechanism', 'sasl creds') for
            # auth instead of a PLAIN password string. Delim wouldn't
            # be found in the tuple anyway.
            defer.returnValue(False)
        try:
            password = request.auth.decode()
        except (UnicodeDecodeError, AttributeError):
            # If the auth segment is not utf-8 decodable then we can assume
            # the data is probably some binary data for a SASL bind and we
            # won't want to try to split on it anyways
            defer.returnValue(False)

        if not util.should_try_splitting_password(password,
                                                  self.factory.allow_concat,
                                                  self.factory.delim,
                                                  self.factory.delimited_password_length):
            defer.returnValue(False)
        if not isinstance(request,
                          ldaptor.protocols.pureldap.LDAPBindRequest):
            defer.returnValue(False)
        # Not checking exempt_primary_bind. self.bound is only
        # incremented when a bind response is received, so
        # theoretically a second bind request could come in before the
        # primary bind response is received. The equivalent can't
        # happen during response processing because the responses are
        # never received out of sequence.
        #
        # Could artificially serialize bind request processing to work
        # around this, but there are enough other solutions. Service
        # users must either be in exempt_ous, not have delim in the
        # password, or fall through to the second primary auth
        # attempt.
        is_exempt = yield self._is_under_exempt_ous(safe_string_decode(request.dn))
        if is_exempt:
            defer.returnValue(False)
        defer.returnValue(True)

    def handle(self, msg):
        """
        Inherited from Proxy, which inherited it from ldaptor's BaseLDAPServer.
        Slightly overriden to drop msg if the protocol's already servicing a BindRequest.
        """
        assert isinstance(msg.value,
                          ldaptor.protocols.pureldap.LDAPProtocolRequest)
        if self.resolving_bind_request:
            msg.value.is_logging_insecure = self.is_logging_insecure
            log.msg("Received extraneous LDAP PDU while resolving a BindRequest: {0}".format(repr(msg)))
        else:
            super(DuoAutoLdapServer, self).handle(msg)

    @defer.inlineCallbacks
    def handle_LDAPBindRequest(self, orig_request,
                               controls,
                               orig_reply_fn):
        """
        Intercept (some) bind requests and check for concat passwords.
        """
        if self.no_more_binds:
            # We already handled and 2FA'd a bindRequest.
            # Panic!
            self.log_request(orig_request, 'Attempt to bindRequest multiple times in the same LDAP connection.  Disconnecting.')
            self.transport.loseConnection()
            return
        # Verify that it's OK to ignore controls
        self.checkControls(controls)
        # ignore controls during BIND requests
        controls = None
        self.resolving_bind_request = True

        should_concat = yield self._request_do_concat(orig_request)
        if should_concat:
            def reply_fn(response, response_controls=None):
                if not isinstance(response,
                                  ldaptor.protocols.pureldap.LDAPBindResponse):
                    # Sent a bind request, didn't get a bind
                    # response... What just happened?!
                    return orig_reply_fn(response)
                if response.resultCode != ldaperrors.Success.resultCode:
                    # Maybe it wasn't concat after all? Retry with
                    # un-split password.
                    return self.handleUnknown(orig_request,
                                              controls,
                                              orig_reply_fn)
                else:
                    # Successful primary auth with split password.
                    # relay_response() performed duo_auth using the
                    # smuggled factor if applicable.
                    return orig_reply_fn(response)
            request = copy.deepcopy(orig_request)
            password, factor = util.do_password_split(request.auth.decode(), self.factory.delim,
                                                      self.factory.delimited_password_length)
            request.auth = password.encode()
            if request.auth:
                reply_fn.duo_factor = factor  # commence smuggling!
                potential_early_response = yield self.handleUnknown(request, controls, reply_fn)
                defer.returnValue(potential_early_response)
            else:
                # Treating this as concat mode would transform a bind
                # request the real client thought was not anonymous
                # (because it had, at a minimum, the delimiter) into a
                # bind the backing LDAP server thinks is anonymous.
                # This is not safe -- the real client likely doesn't
                # check the result for e.g. "NT AUTHORITY\ANONYMOUS
                # LOGON" instead of the requested DN because it
                # doesn't know it sent an anonymous bind.
                #
                # Assume either 1. this is not actually concat mode
                # and sending the split password would fail of not for
                # anonymous bind or 2. this is concat mode and
                # therefore end user auth, for which anonymous bind is
                # contraindicated. In both cases the original request
                # should be sent instead of checking for concat mode.
                potential_early_response = yield self.handleUnknown(orig_request, controls, orig_reply_fn)
                defer.returnValue(potential_early_response)
        else:
            # Allow anonymous bind if the real client did. Pass
            # through anonymous binds if it knowingly sent an empty,
            # non-concat password.
            potential_early_response = yield self.handleUnknown(orig_request, controls, orig_reply_fn)
            defer.returnValue(potential_early_response)

    @defer.inlineCallbacks
    def _response_needs_duo_auth(self, request, response):
        if not isinstance(response,
                          ldaptor.protocols.pureldap.LDAPBindResponse):
            defer.returnValue(False)
        if not isinstance(request,
                          ldaptor.protocols.pureldap.LDAPBindRequest):
            defer.returnValue(False)

        dn_str = safe_string_decode(request.dn)
        if response.resultCode != ldaperrors.Success.resultCode:
            log.auth(
                msg='Primary authentication rejected',
                dn=dn_str,
                auth_stage=log.AUTH_PRIMARY,
                status=log.AUTH_REJECT,
                server_section=self.server_section_name,
                server_section_ikey=self.server_section_ikey)
            defer.returnValue(False)
        # At this point, we know we got a successful bind response to a bind request
        log.auth(
            msg='Primary authentication successful',
            dn=dn_str,
            auth_stage=log.AUTH_PRIMARY,
            status=log.AUTH_ALLOW,
            server_section=self.server_section_name,
            server_section_ikey=self.server_section_ikey)
        if self.exempt_primary_bind and self.bound < 2:
            # E.g. the usual LDAP auth "bind, search, bind" pattern.
            msg = 'Primary bind exempted from 2FA'
            self.log_request(request, msg)
            log.auth(
                msg=msg,
                dn=dn_str,
                auth_stage=log.AUTH_SECONDARY,
                status=log.AUTH_ALLOW,
                server_section=self.server_section_name,
                server_section_ikey=self.server_section_ikey)
            defer.returnValue(False)
        if not request.dn:
            log.auth(
                msg='Duo authentication bypassed for anonymous bind',
                dn=dn_str,
                auth_stage=log.AUTH_SECONDARY,
                status=log.AUTH_ALLOW,
                server_section=self.server_section_name,
                server_section_ikey=self.server_section_ikey)
            # No username. Can't 2FA. The real client might expect
            # anonymous bind so pass it through.
            defer.returnValue(False)
        is_exempt = yield self._is_under_exempt_ous(dn_str)
        if is_exempt:
            msg = 'Exempt OU: {0}'.format(dn_str)
            log.auth(
                msg=msg,
                dn=dn_str,
                auth_stage=log.AUTH_SECONDARY,
                status=log.AUTH_ALLOW,
                server_section=self.server_section_name,
                server_section_ikey=self.server_section_ikey)
            self.log_request(request, msg)
            defer.returnValue(False)
        defer.returnValue(True)

    @defer.inlineCallbacks
    def _is_under_exempt_ous(self, dn_str):
        if not self.exempt_ous:
            defer.returnValue(False)
        dn_str = dn_str.lower()
        try:
            dn = DistinguishedName(dn_str)
        except Exception:
            # Response DNs shouldn't be invalid but a request's DN
            # field may be a "NetBIOS domain\username". Implementing
            # exempt_ous for such binds requires an additional search
            # in order to get the DN.
            log.msg("Bind Request did not have a full DN. Attempting to lookup full DN for {}".format(dn_str))
            try:
                dn = yield self.username_to_dn(dn_str)
            except DnLookupFailed as e:
                log.msg("Failed to lookup full DN. Marking as non-exempt by default. Error: {}".format(e))
                defer.returnValue(False)
        defer.returnValue(any([base_dn.contains(dn) for base_dn in self.exempt_ous]))

    @defer.inlineCallbacks
    def relay_response(self, response, reply_fn, request, **kwargs):
        """ Intercept (some) binds in a connection, and handle Duo auth. """
        needs_duo_auth = yield self._response_needs_duo_auth(request, response)
        if needs_duo_auth:
            # In concat mode the selected factor is smuggled through
            # ldaptor to this callback as an attribute of the
            # reply_fn.
            factor = getattr(reply_fn, 'duo_factor', None)
            try:
                response = yield self.duo_auth(request,
                                               response,
                                               factor=factor)
            except duo_async.DuoAPIError as e:
                log.err(None, 'Duo auth failed')

                dn_str = safe_string_decode(request.dn)
                if duo_async.should_server_fail_open(self.failmode, e.fail_open):
                    msg = duo_async.get_fail_open_msg()
                    # return primary response unchanged
                    log.auth(
                        msg=msg,
                        dn=dn_str,
                        auth_stage=log.AUTH_SECONDARY,
                        status=log.AUTH_ALLOW,
                        server_section=self.server_section_name,
                        server_section_ikey=self.server_section_ikey)
                    self.log_request(request, msg)
                else:
                    msg = duo_async.FAILMODE_SECURE_MSG
                    log.auth(
                        msg=msg,
                        dn=dn_str,
                        auth_stage=log.AUTH_SECONDARY,
                        status=log.AUTH_ERROR,
                        server_section=self.server_section_name,
                        server_section_ikey=self.server_section_ikey)
                    response = self.create_bind_response(request,
                                                         False,
                                                         msg)
            if not self.allow_unlimited_binds:
                self.no_more_binds = True
        yield super(DuoAutoLdapServer, self).relay_response(
            response=response,
            request=request,
            reply_fn=reply_fn,
            **kwargs
        )
        self.resolving_bind_request = False
        if self.no_more_binds and not self.allow_searches_after_bind:
            self.transport.loseConnection()

    def make_connected_client(self):
        return self.primary_ator.ldap_proxy()

    def create_bind_response(self, request, success, msg):
        self.log_request(request, msg)
        if success:
            code = ldaperrors.Success.resultCode
        else:
            code = ldaperrors.LDAPInvalidCredentials.resultCode
        return ldaptor.protocols.pureldap.LDAPBindResponse(
            resultCode=code,
            errorMessage=msg,
        )

    @defer.inlineCallbacks
    def duo_auth(self, request, primary_response, factor=None):
        dn_str = safe_string_decode(request.dn)
        try:
            # Get the Duo username from the DN as requested. Still
            # want to apply 2FA to anonymous binds where the matchedDN
            # is empty.
            username = yield self.dn_to_username(dn_str)
        except Exception as e:
            log.msg('Username lookup failed: ' + repr(str(e)))
            username = None
        if not username:
            msg = 'Cannot find username'
            log.auth(
                msg=msg,
                dn=dn_str,
                username=log.AUTH_UNKNOWN,
                auth_stage=log.AUTH_SECONDARY,
                status=log.AUTH_REJECT,
                client_ip=log.AUTH_UNKNOWN,
                server_section=self.server_section_name,
                server_section_ikey=self.server_section_ikey)
            response = self.create_bind_response(request, False, msg)
            defer.returnValue(response)

        client_ip = None  # LDAP doesn't allow us a way to get the client ip

        preauth_res = yield self.factory.client.preauth(username, client_ip, self.failmode)

        self.log_request(request, 'Got preauth result for %s: %r' % (
            username,
            preauth_res['result'],
        ))

        if preauth_res['result'] == duo_async.API_RESULT_ALLOW:
            msg = preauth_res['status']
            log.auth(
                msg='Duo preauth result was {0}'.format(msg),
                dn=dn_str,
                username=username,
                auth_stage=log.AUTH_SECONDARY,
                status=log.AUTH_ALLOW,
                server_section=self.server_section_name,
                server_section_ikey=self.server_section_ikey)
            self.log_request(request, msg)
            defer.returnValue(primary_response)
        elif preauth_res['result'] == duo_async.API_RESULT_DENY:
            msg = preauth_res['status']
            log.auth(
                msg='Duo preauth result was {0}'.format(msg),
                dn=dn_str,
                username=username,
                auth_stage=log.AUTH_SECONDARY,
                status=log.AUTH_REJECT,
                server_section=self.server_section_name,
                server_section_ikey=self.server_section_ikey)
            response = self.create_bind_response(request, False, msg)
            defer.returnValue(response)
        elif preauth_res['result'] == duo_async.API_RESULT_ENROLL:
            msg = preauth_res['status']
            log.auth(
                msg='User is not enrolled. Enrollment link sent.',
                dn=dn_str,
                username=username,
                auth_stage=log.AUTH_SECONDARY,
                status=log.AUTH_REJECT,
                server_section=self.server_section_name,
                server_section_ikey=self.server_section_ikey)
            response = self.create_bind_response(request, False, msg)
            defer.returnValue(response)

        if not factor:
            factor = util.factor_for_request(self.factors, preauth_res)
        if not factor or factor == 'passcode':
            msg = 'User has no Duo factors usable with this configuration'
            log.auth(
                msg=msg,
                dn=dn_str,
                username=username,
                auth_stage=log.AUTH_SECONDARY,
                status=log.AUTH_REJECT,
                server_section=self.server_section_name,
                server_section_ikey=self.server_section_ikey)
            response = self.create_bind_response(request, False, msg)
            defer.returnValue(response)

        # LDAP server never sends real client's IP (no equivalent of
        # Calling-Station-Id).
        auth_res = yield self.factory.client.auth(username,
                                                  factor,
                                                  client_ip=None)
        msg = auth_res.get('status', '')
        self.log_request(request, "Duo authentication returned '{}' for {}: '{}'".format(auth_res['result'], username, msg))
        if auth_res['result'] == duo_async.API_RESULT_ALLOW:
            self.log_request(request, msg)
            log.auth(
                msg="Duo authentication succeeded - {0}".format(msg),
                dn=dn_str,
                username=username,
                auth_stage=log.AUTH_SECONDARY,
                status=log.AUTH_ALLOW,
                server_section=self.server_section_name,
                server_section_ikey=self.server_section_ikey,
                factor=factor
            )
            defer.returnValue(primary_response)
        else:
            log.auth(
                msg="Duo authentication was rejected - {0}".format(msg),
                dn=dn_str,
                username=username,
                auth_stage=log.AUTH_SECONDARY,
                status=log.AUTH_REJECT,
                server_section=self.server_section_name,
                server_section_ikey=self.server_section_ikey,
                factor=factor)
            response = self.create_bind_response(request, False, msg)
            defer.returnValue(response)


class DuoAutoLdapServerFactory(twisted.internet.protocol.ServerFactory):
    def __init__(self, duo_client,
                 delim=',',
                 delimited_password_length=0,
                 allow_concat=True):
        """
        delim: delimiter for concat-formatted passwords.

        allow_concat: If true, will try to split concat-formatted
        passwords containing delim. Otherwise, concat-mode will not be
        tried.
        """
        self.client = duo_client
        self.delim = delim
        self.delimited_password_length = delimited_password_length
        self.allow_concat = allow_concat


class Module(ServerModule):
    def __init__(self, config, primary_ator, server_section_name):
        log.msg('LDAP Automatic Factor Server Module Configuration:')
        log.config(config, (lambda x: x in ('skey', 'skey_protected')))
        self.port = config.get_int('port', DEFAULT_LDAP_PORT)
        self.interface = config.get_str('interface', '')

        self.ssl_port = config.get_int('ssl_port', DEFAULT_LDAPS_PORT)
        self.ssl_key_path = config.get_str('ssl_key_path', '')
        self.ssl_cert_path = config.get_str('ssl_cert_path', '')
        self.cipher_list = config.get_str('cipher_list', '')
        self.minimum_tls_version = config.get_str('minimum_tls_version', '')
        if self.ssl_key_path and self.ssl_cert_path:
            self.ssl_key_path = util.resolve_file_path(self.ssl_key_path)
            self.ssl_cert_path = util.resolve_file_path(self.ssl_cert_path)
            self.sslctx = ssl_server.ChainingOpenSSLContextFactory(
                privatekey_filename=self.ssl_key_path,
                certificate_filename=self.ssl_cert_path,
                cipher_list=self.cipher_list,
                minimum_tls_version=self.minimum_tls_version,
            )
        else:
            self.sslctx = None
            log.msg('SSL disabled. No server key and certificate configured.')

        exempt_ous = [config.get_str(ou_key) for ou_key in util.get_dynamic_keys(config, 'exempt_ou')]

        exempt_primary_bind = config.get_bool('exempt_primary_bind', True)
        allow_unlimited_binds = config.get_bool('allow_unlimited_binds', False)
        self.factory = DuoAutoLdapServerFactory(
            duo_client=self.make_duo_client(config),
            delim=config.get_str('delimiter', DEFAULT_DELIM),
            delimited_password_length=config.get_int('delimited_password_length', 0),
            allow_concat=config.get_bool('allow_concat', True),
        )

        self.factory.protocol = functools.partial(
            DuoAutoLdapServer,
            primary_ator=primary_ator,
            failmode=config.get_enum('failmode', duo_async.FAILMODES,
                                     duo_async.FAILMODE_SAFE,
                                     transform=str.lower),
            factors=util.parse_factor_list(config.get_str('factors', 'auto')),
            sslctx=self.sslctx,
            network_timeout=config.get_int('network_timeout',  # 10m
                                           10 * 60),
            idle_timeout=config.get_int('idle_timeout',  # 1h
                                        60 * 60),
            debug=config.get_bool('debug', False),
            is_logging_insecure=config.get_bool('is_logging_insecure', False),
            exempt_primary_bind=exempt_primary_bind,
            exempt_ous=exempt_ous,
            allow_searches_after_bind=config.get_bool('allow_searches_after_bind', True),
            allow_unlimited_binds=allow_unlimited_binds,
            server_section_name=server_section_name,
            server_section_ikey=config.get_str('ikey', 'Unknown')
        )
        self.listener = None
        self.listener_ssl = None
        self._bind_if_necessary()

    def startService(self):
        ServerModule.startService(self)
        self._bind_if_necessary()

    @defer.inlineCallbacks
    def stopService(self):
        super(Module, self).stopService()
        if self.listener:
            yield self.listener.stopListening()
            self.listener = None
        if self.listener_ssl:
            yield self.listener_ssl.stopListening()
            self.listener_ssl = None

    def _bind_if_necessary(self):
        if self.listener is None:
            self.listener = reactor.listenTCP(
                port=self.port,
                factory=self.factory,
                interface=self.interface,
            )
        if self.sslctx and self.listener_ssl is None:
            self.listener_ssl = reactor.listenSSL(
                port=self.ssl_port,
                factory=self.factory,
                contextFactory=self.sslctx,
                interface=self.interface,
            )
