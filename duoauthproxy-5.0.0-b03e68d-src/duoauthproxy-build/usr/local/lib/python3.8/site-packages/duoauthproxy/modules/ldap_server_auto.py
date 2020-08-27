#
# Copyright (c) 2012 Duo Security
# All Rights Reserved
#
import copy
import functools
from typing import Optional

import ldaptor.protocols.pureldap
import twisted.internet.protocol
from ldaptor.protocols.ldap import ldaperrors
from ldaptor.protocols.ldap.distinguishedname import DistinguishedName
from twisted.internet import defer, reactor

from ..lib import duo_async, log, ntlm, util
from ..lib.base import ServerModule
from ..lib.const import DEFAULT_LDAP_PORT, DEFAULT_LDAPS_PORT
from ..lib.ldap import utilities
from ..lib.ldap.client import DnLookupFailed
from ..lib.ldap.proxy import Proxy
from ..lib.util import safe_string_decode
from . import ssl_server

DEFAULT_DELIM = ","


class DuoAutoLdapServer(Proxy):
    def __init__(
        self,
        factors,
        primary_ator,
        failmode,
        exempt_primary_bind=True,
        exempt_ous=None,
        allow_searches_after_bind=True,
        allow_unlimited_binds=False,
        **kwargs
    ):
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
        self.exempt_ous = [DistinguishedName(str(dn).lower()) for dn in exempt_ous]
        self.no_more_binds = False
        self.allow_searches_after_bind = allow_searches_after_bind
        self.allow_unlimited_binds = allow_unlimited_binds
        self.resolving_bind_request = False

    def logPrefix(self):
        """Log messages from this Protocol will contain this prefix to help identify what section they are for"""
        return self.server_section_name

    def log_request(self, request, log_msg):
        addr = self.transport.getPeer()
        log.msg("[Request from %s:%d] %s" % (addr.host, addr.port, log_msg,))

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

        if not util.should_try_splitting_password(
            password,
            self.factory.allow_concat,
            self.factory.delim,
            self.factory.delimited_password_length,
        ):
            defer.returnValue(False)
        if not isinstance(request, ldaptor.protocols.pureldap.LDAPBindRequest):
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
        is_exempt = yield self._is_under_exempt_ous(
            safe_string_decode(request.dn), utilities.LdapUsernameOrigin.BIND_DN
        )
        if is_exempt:
            defer.returnValue(False)
        defer.returnValue(True)

    def handle(self, msg):
        """
        Inherited from Proxy, which inherited it from ldaptor's BaseLDAPServer.
        Slightly overriden to drop msg if the protocol's already servicing a BindRequest.
        """
        assert isinstance(msg.value, ldaptor.protocols.pureldap.LDAPProtocolRequest)
        if self.resolving_bind_request:
            msg.value.is_logging_insecure = self.is_logging_insecure
            log.msg(
                "Received extraneous LDAP PDU while resolving a BindRequest: {0}".format(
                    repr(msg)
                )
            )
        else:
            super(DuoAutoLdapServer, self).handle(msg)

    @defer.inlineCallbacks
    def handle_LDAPBindRequest(self, orig_request, controls, orig_reply_fn):
        """
        Intercept (some) bind requests and check for concat passwords.
        """
        if self.no_more_binds:
            # We already handled and 2FA'd a bindRequest.
            # Panic!
            self.log_request(
                orig_request,
                "Attempt to bindRequest multiple times in the same LDAP connection.  Disconnecting.",
            )
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
                if not isinstance(
                    response, ldaptor.protocols.pureldap.LDAPBindResponse
                ):
                    # Sent a bind request, didn't get a bind
                    # response... What just happened?!
                    return orig_reply_fn(response)
                if response.resultCode != ldaperrors.Success.resultCode:
                    # Maybe it wasn't concat after all? Retry with
                    # un-split password.
                    return self.handleUnknown(orig_request, controls, orig_reply_fn)
                else:
                    # Successful primary auth with split password.
                    # relay_response() performed duo_auth using the
                    # smuggled factor if applicable.
                    return orig_reply_fn(response)

            request = copy.deepcopy(orig_request)
            password, factor = util.do_password_split(
                request.auth.decode(),
                self.factory.delim,
                self.factory.delimited_password_length,
            )
            request.auth = password.encode()
            if request.auth:
                reply_fn.duo_factor = factor  # commence smuggling!
                potential_early_response = yield self.handleUnknown(
                    request, controls, reply_fn
                )
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
                potential_early_response = yield self.handleUnknown(
                    orig_request, controls, orig_reply_fn
                )
                defer.returnValue(potential_early_response)
        else:
            # Allow anonymous bind if the real client did. Pass
            # through anonymous binds if it knowingly sent an empty,
            # non-concat password.
            potential_early_response = yield self.handleUnknown(
                orig_request, controls, orig_reply_fn
            )
            defer.returnValue(potential_early_response)

    @defer.inlineCallbacks
    def _response_needs_duo_auth(self, request, response):
        if not isinstance(response, ldaptor.protocols.pureldap.LDAPBindResponse):
            defer.returnValue(False)
        if not isinstance(request, ldaptor.protocols.pureldap.LDAPBindRequest):
            defer.returnValue(False)

        dn_str = safe_string_decode(request.dn)

        logging_kwargs = {
            "server_section": self.server_section_name,
            "server_section_ikey": self.server_section_ikey,
        }

        if dn_str:
            logging_kwargs["dn"] = dn_str

        # If a we received a challenge due to a SASL bind being in progress,
        # we'll just proxy it back to the appliance so it can respond to the
        # challenge. It's not time for 2FA yet.
        if response.resultCode == ldaperrors.LDAPSaslBindInProgress.resultCode:
            log.auth(
                msg="Primary authentication challenge received",
                auth_stage=log.AUTH_PRIMARY,
                status=log.AUTH_CHALLENGE,
                **logging_kwargs,
            )
            defer.returnValue(False)
        elif response.resultCode != ldaperrors.Success.resultCode:
            # Otherwise if the result code is anything but a Success, treat it as
            # a primary authentication failure.
            log.auth(
                msg="Primary authentication rejected",
                auth_stage=log.AUTH_PRIMARY,
                status=log.AUTH_REJECT,
                **logging_kwargs,
            )
            # log a warning message if we fail a SASL bind. We don't know for certain
            # that the user tried to concat, but if they did it won't work.
            if request.sasl and self.factory.allow_concat:
                log.error(
                    "Allow concat is configured, but is not "
                    + "supported with SASL authentications. "
                    + "Did you try to concatenate your second factor "
                    + "to your password?"
                )
            defer.returnValue(False)

        # At this point, we know we got a successful bind response to a bind request
        log.auth(
            msg="Primary authentication successful",
            auth_stage=log.AUTH_PRIMARY,
            status=log.AUTH_ALLOW,
            **logging_kwargs,
        )
        if self.exempt_primary_bind and self.bound < 2:
            # E.g. the usual LDAP auth "bind, search, bind" pattern.
            msg = "Primary bind exempted from 2FA"
            self.log_request(request, msg)
            log.auth(
                msg=msg,
                auth_stage=log.AUTH_SECONDARY,
                status=log.AUTH_ALLOW,
                **logging_kwargs,
            )
            defer.returnValue(False)

        user_identifier = dn_str
        identifier_location = utilities.LdapUsernameOrigin.BIND_DN

        if self._is_supported_sasl_bind(request):
            username, domain = self._get_username_and_domain_from_request(request)
            if not username:
                # The request is not a NTLM sasl bind. We can not extract the username from the request
                log.auth(
                    msg="Non-supported SASL bind",
                    auth_stage=log.AUTH_UNKNOWN,
                    status=log.AUTH_ALLOW,
                    **logging_kwargs,
                )
                defer.returnValue(False)
            if domain:
                user_identifier = "{domain}\\{username}".format(
                    domain=domain, username=username
                )
            else:
                user_identifier = username
            identifier_location = utilities.LdapUsernameOrigin.NTLM

            logging_kwargs["username"] = username

        if not request.sasl and not request.auth:
            # We only support Plain anonymous bind
            if not user_identifier:
                msg = "Duo authentication bypassed for LDAPv3 anonymous bind."
            else:
                msg = "Duo authentication bypassed for LDAPv2 anonymous bind. User identifier: {}".format(
                    user_identifier
                )
            log.msg(msg)
            log.auth(
                msg=msg,
                auth_stage=log.AUTH_SECONDARY,
                status=log.AUTH_ALLOW,
                **logging_kwargs,
            )
            # No username. Can't 2FA. The real client might expect
            # anonymous bind so pass it through.
            defer.returnValue(False)

        is_exempt = yield self._is_under_exempt_ous(
            user_identifier, identifier_location
        )
        if is_exempt:
            msg = "Exempt OU: {0}".format(dn_str)
            log.auth(
                msg=msg,
                auth_stage=log.AUTH_SECONDARY,
                status=log.AUTH_ALLOW,
                **logging_kwargs,
            )
            self.log_request(request, msg)
            defer.returnValue(False)
        defer.returnValue(True)

    def _get_username_and_domain_from_request(self, request):
        try:
            _, sasl_creds = request.auth

            if sasl_creds.startswith(b"NTLMSSP\x00"):
                auth_message = ntlm.AuthenticateMessage(sasl_creds)
                encoding = (
                    "utf-16le"
                    if (auth_message.NegotiateFlags & ntlm.NTLMSSP_NEGOTIATE_UNICODE)
                    else "ascii"
                )
                username = auth_message.UserName.decode(encoding)
                domainname = auth_message.DomainName.decode(encoding)
            else:
                username = None
                domainname = None

        except ValueError:
            username = None
            domainname = None
        return (username, domainname)

    def _is_supported_sasl_bind(self, request):

        if not request.sasl:
            return False

        if isinstance(request.auth, bytes):
            return False

        # There's a boat-load of SASL authentication mechanisms,
        # AuthProxy only supports GSS-SPNEGO (negotiate Kerberos or NTLM).
        #
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a98c1f56-8246-4212-8c4e-d92da1a9563b
        # https://ldapwiki.com/wiki/SASL
        # https://docs.oracle.com/javase/jndi/tutorial/ldap/security/sasl.html
        #

        auth_mechanism, _ = request.auth
        return auth_mechanism in [b"GSS-SPNEGO"]

    @defer.inlineCallbacks
    def _is_under_exempt_ous(self, user_identifier, identifier_location):
        """Returns true if the user is found to be in one of the configured exempt groups
        Args:
            user_identifier: Username or DN to lookup
            identifier_location: One of utilities.LDAP_USERNAME_FROM_*. Explain where the username came from.
                                 DN field of the LDAP packet, NTLM username field, etc.
        """
        if not self.exempt_ous:
            defer.returnValue(False)
        user_identifier = user_identifier.lower()
        try:
            dn = DistinguishedName(user_identifier)
        except Exception:
            # Response DNs shouldn't be invalid but a request's DN
            # field may be a NetBIOS (domain\username), a UPN (username@domain), a samAccountName (username), or a common name (username)".
            # Implementing exempt_ous for such binds requires an additional search
            # in order to get the DN.
            log.msg(
                "Bind Request did not have a full DN. Attempting to lookup full DN for {}".format(
                    user_identifier
                )
            )
            possible_username = utilities.LdapUsername(
                user_identifier, identifier_location
            )
            try:
                dn = yield self.username_to_dn(possible_username)
            except DnLookupFailed as e:
                log.msg(
                    "Failed to lookup full DN. Marking as non-exempt by default. Error: {}".format(
                        e
                    )
                )
                defer.returnValue(False)
        defer.returnValue(any([base_dn.contains(dn) for base_dn in self.exempt_ous]))

    def should_short_circuit(
        self, response, request
    ) -> Optional[ldaptor.protocols.pureldap.LDAPBindResponse]:
        result = None
        if (
            hasattr(request, "sasl")
            and request.sasl
            and not self._is_supported_sasl_bind(request)
        ):
            end_user_msg = "Unsupported SASL authentication mechanism was used. Only GSS-SPENGO is supported at this time."
            log.msg(end_user_msg)
            self.log_request(request, end_user_msg)
            result = ldaptor.protocols.pureldap.LDAPBindResponse(
                resultCode=ldaperrors.LDAPUnwillingToPerform.resultCode,
                matchedDN=safe_string_decode(request.dn),
                errorMessage=end_user_msg,
            )
        elif self.response_negotiated_sign_and_seal(response):
            # If the connection negotiated sign and seal we can no longer properly act as a proxy
            # so we must fail the auth
            log.msg(
                "Detected that sign and seal was negotiated. The Authentication Proxy cannot properly operate in this mode. Failing the authentication. To resolve this error please add TLS to your [ldap_server_auto] or disable sign and seal on your appliance"
            )
            end_user_msg = "Sign and seal is not a compatible security mechanism. Please contact your administrator for assistance."
            self.log_request(request, end_user_msg)
            result = ldaptor.protocols.pureldap.LDAPBindResponse(
                resultCode=ldaperrors.LDAPAuthMethodNotSupported.resultCode,
                errorMessage=end_user_msg,
            )
        return result

    @defer.inlineCallbacks
    def relay_response(self, response, reply_fn, request, **kwargs):
        """ Intercept (some) binds in a connection, and handle Duo auth. """
        short_circuit_response = self.should_short_circuit(response, request)
        if short_circuit_response:
            yield super(DuoAutoLdapServer, self).relay_response(
                response=short_circuit_response,
                request=request,
                reply_fn=reply_fn,
                **kwargs,
            )
        else:
            needs_duo_auth = yield self._response_needs_duo_auth(request, response)
            if needs_duo_auth:
                # In concat mode the selected factor is smuggled through
                # ldaptor to this callback as an attribute of the
                # reply_fn.
                factor = getattr(reply_fn, "duo_factor", None)
                response = yield self.duo_auth(request, response, factor=factor)
                if not self.allow_unlimited_binds:
                    self.no_more_binds = True
            yield super(DuoAutoLdapServer, self).relay_response(
                response=response, request=request, reply_fn=reply_fn, **kwargs
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
            resultCode=code, errorMessage=msg,
        )

    def response_negotiated_sign_and_seal(self, response):
        """ Detects of the response from the AD states that the connection is going to
        start using sign and seal """
        if (
            isinstance(response, ldaptor.protocols.pureldap.LDAPBindResponse)
            and response.resultCode == ldaperrors.LDAPSaslBindInProgress.resultCode
            and response.serverSaslCreds.value.startswith(b"NTLMSSP\x00")
        ):
            challenge_packet = ntlm.ChallengeMessage(response.serverSaslCreds.value)
            return ntlm.sign_and_seal_negotiated(challenge_packet.NegotiateFlags)
        else:
            return False

    @defer.inlineCallbacks
    def duo_auth(self, request, primary_response, factor=None):
        dn_str = safe_string_decode(request.dn)

        logging_kwargs = {
            "server_section": self.server_section_name,
            "server_section_ikey": self.server_section_ikey,
        }

        if dn_str:
            logging_kwargs["dn"] = dn_str

        if self._is_supported_sasl_bind(request):
            username, _ = self._get_username_and_domain_from_request(request)
        else:
            # If we are not able to get username from request (Non-NTLM sasl request)
            # We will try to get username from the DN
            try:
                # Get the Duo username from the DN as requested by doing bind->search->bind.
                # Still want to apply 2FA to anonymous binds where the matchedDN is empty.
                if dn_str:
                    username = yield self.dn_to_username(dn_str)

            except Exception as e:
                log.msg("Username lookup failed: " + repr(str(e)))
                username = None

        if not username:
            msg = "Cannot find username"
            log.auth(
                msg=msg,
                username=log.AUTH_UNKNOWN,
                auth_stage=log.AUTH_SECONDARY,
                status=log.AUTH_REJECT,
                client_ip=log.AUTH_UNKNOWN,
                **logging_kwargs,
            )
            response = self.create_bind_response(request, False, msg)
            defer.returnValue(response)

        logging_kwargs["username"] = username
        client_ip = None  # LDAP doesn't allow us a way to get the client ip

        try:
            preauth_res = yield self.factory.client.preauth(
                username, client_ip, self.failmode
            )
        except duo_async.DuoAPIError as e:
            log.failure("Duo auth failed")
            if duo_async.should_server_fail_open(self.failmode, e.fail_open):
                msg = duo_async.get_fail_open_msg()
                response = self._create_allow_response(
                    request, primary_response, msg, logging_kwargs
                )
                defer.returnValue(response)
            else:
                msg = duo_async.FAILMODE_SECURE_MSG
                response = self._create_deny_response(request, msg, logging_kwargs)
                defer.returnValue(response)

        self.log_request(
            request,
            "Got preauth result for %s: %r" % (username, preauth_res["result"],),
        )

        if preauth_res["result"] == duo_async.API_RESULT_ALLOW:
            msg = preauth_res["status"]
            log.auth(
                msg="Duo preauth result was {0}".format(msg),
                auth_stage=log.AUTH_SECONDARY,
                status=log.AUTH_ALLOW,
                **logging_kwargs,
            )
            self.log_request(request, msg)
            defer.returnValue(primary_response)
        elif preauth_res["result"] == duo_async.API_RESULT_DENY:
            msg = preauth_res["status"]
            log.auth(
                msg="Duo preauth result was {0}".format(msg),
                auth_stage=log.AUTH_SECONDARY,
                status=log.AUTH_REJECT,
                **logging_kwargs,
            )
            response = self.create_bind_response(request, False, msg)
            defer.returnValue(response)
        elif preauth_res["result"] == duo_async.API_RESULT_ENROLL:
            msg = preauth_res["status"]
            log.auth(
                msg="User is not enrolled. Enrollment link sent.",
                auth_stage=log.AUTH_SECONDARY,
                status=log.AUTH_REJECT,
                **logging_kwargs,
            )
            response = self.create_bind_response(request, False, msg)
            defer.returnValue(response)

        if not factor:
            factor = util.factor_for_request(self.factors, preauth_res)
        if not factor or factor == "passcode":
            msg = "User has no Duo factors usable with this configuration"
            log.auth(
                msg=msg,
                auth_stage=log.AUTH_SECONDARY,
                status=log.AUTH_REJECT,
                **logging_kwargs,
            )
            response = self.create_bind_response(request, False, msg)
            defer.returnValue(response)

        # LDAP server never sends real client's IP (no equivalent of
        # Calling-Station-Id).
        try:
            auth_res = yield self.factory.client.auth(username, factor, client_ip=None)
        except duo_async.DuoAPITimeoutError as e:
            log.msg("Duo auth call failed: {e}", e=e)
            if duo_async.should_server_fail_open(self.failmode, e.fail_open):
                msg = duo_async.get_fail_open_msg()
                response = self._create_allow_response(
                    request, primary_response, msg, logging_kwargs
                )
                defer.returnValue(response)
            else:
                msg = duo_async.FAIL_AUTH_TIMEOUT_MSG
                response = self._create_deny_response(request, msg, logging_kwargs)
                defer.returnValue(response)
        except duo_async.DuoAPIError as e:
            log.failure("Duo auth failed")
            if duo_async.should_server_fail_open(self.failmode, e.fail_open):
                msg = duo_async.get_fail_open_msg()
                response = self._create_allow_response(
                    request, primary_response, msg, logging_kwargs
                )
                defer.returnValue(response)
            else:
                msg = duo_async.FAIL_AUTH_MSG
                response = self._create_deny_response(request, msg, logging_kwargs)
                defer.returnValue(response)

        msg = auth_res.get("status", "")
        self.log_request(
            request,
            "Duo authentication returned '{}' for {}: '{}'".format(
                auth_res["result"], username, msg
            ),
        )
        if auth_res["result"] == duo_async.API_RESULT_ALLOW:
            self.log_request(request, msg)
            log.auth(
                msg="Duo authentication succeeded - {0}".format(msg),
                auth_stage=log.AUTH_SECONDARY,
                status=log.AUTH_ALLOW,
                factor=factor,
                **logging_kwargs,
            )
            defer.returnValue(primary_response)
        else:
            log.auth(
                msg="Duo authentication was rejected - {0}".format(msg),
                auth_stage=log.AUTH_SECONDARY,
                status=log.AUTH_REJECT,
                factor=factor,
                **logging_kwargs,
            )
            response = self.create_bind_response(request, False, msg)
            defer.returnValue(response)

    def _create_allow_response(self, request, primary_response, msg, logging_kwargs):
        log.auth(
            msg=msg,
            auth_stage=log.AUTH_SECONDARY,
            status=log.AUTH_ALLOW,
            **logging_kwargs,
        )
        self.log_request(request, msg)
        # return primary response unchanged
        return primary_response

    def _create_deny_response(self, request, msg, logging_kwargs):
        log.auth(
            msg=msg,
            auth_stage=log.AUTH_SECONDARY,
            status=log.AUTH_ERROR,
            **logging_kwargs,
        )
        response = self.create_bind_response(request, False, msg)
        return response


class DuoAutoLdapServerFactory(twisted.internet.protocol.ServerFactory):
    def __init__(
        self, duo_client, delim=",", delimited_password_length=0, allow_concat=True
    ):
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
        log.msg("LDAP Automatic Factor Server Module Configuration:")
        log.config(config, (lambda x: x in ("skey", "skey_protected")))
        self.port = config.get_int("port", DEFAULT_LDAP_PORT)
        self.interface = config.get_str("interface", "")

        self.ssl_port = config.get_int("ssl_port", DEFAULT_LDAPS_PORT)
        self.ssl_key_path = config.get_str("ssl_key_path", "")
        self.ssl_cert_path = config.get_str("ssl_cert_path", "")
        self.cipher_list = config.get_str("cipher_list", "")
        self.minimum_tls_version = config.get_str("minimum_tls_version", "")
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
            log.msg("SSL disabled. No server key and certificate configured.")

        exempt_ous = [
            config.get_str(ou_key)
            for ou_key in util.get_dynamic_keys(config, "exempt_ou")
        ]

        exempt_primary_bind = config.get_bool("exempt_primary_bind", True)
        allow_unlimited_binds = config.get_bool("allow_unlimited_binds", False)
        self.factory = DuoAutoLdapServerFactory(
            duo_client=self.make_duo_client(config),
            delim=config.get_str("delimiter", DEFAULT_DELIM),
            delimited_password_length=config.get_int("delimited_password_length", 0),
            allow_concat=config.get_bool("allow_concat", True),
        )

        self.factory.protocol = functools.partial(
            DuoAutoLdapServer,
            primary_ator=primary_ator,
            failmode=config.get_enum(
                "failmode",
                duo_async.FAILMODES,
                duo_async.FAILMODE_SAFE,
                transform=str.lower,
            ),
            factors=util.parse_factor_list(config.get_str("factors", "auto")),
            sslctx=self.sslctx,
            network_timeout=config.get_int("network_timeout", 10 * 60),  # 10m
            idle_timeout=config.get_int("idle_timeout", 60 * 60),  # 1h
            debug=config.get_bool("debug", False),
            is_logging_insecure=config.get_bool("is_logging_insecure", False),
            exempt_primary_bind=exempt_primary_bind,
            exempt_ous=exempt_ous,
            allow_searches_after_bind=config.get_bool(
                "allow_searches_after_bind", True
            ),
            allow_unlimited_binds=allow_unlimited_binds,
            server_section_name=server_section_name,
            server_section_ikey=config.get_str("ikey", "Unknown"),
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
                port=self.port, factory=self.factory, interface=self.interface,
            )
        if self.sslctx and self.listener_ssl is None:
            self.listener_ssl = reactor.listenSSL(
                port=self.ssl_port,
                factory=self.factory,
                contextFactory=self.sslctx,
                interface=self.interface,
            )
