#
# Copyright (c) 2012 Duo Security
# All Rights Reserved
#
# pylint: disable=E0202

from twisted.internet import defer

from pyrad import packet
import os

from duoauthproxy.lib import log, duo_async, util
from duoauthproxy.lib.base import ServerModule
from duoauthproxy.lib.radius.challenge import ChallengeResponseRadiusServer
from duoauthproxy.lib.radius.server import parse_radius_secrets, parse_client_ip_attribute
from duoauthproxy.lib.radius.duo_server import DuoSimpleRadiusServer
from duoauthproxy.lib import eap, mppe


def _format_short(preauth_res: dict) -> bytes:
    factors = preauth_res['factors']
    if factors:
        sorted_factors = ('\'%s\'' % factors[k].rstrip('1')
                          for k in sorted(factors.keys())
                          if k != 'default')
        msg = ('Choose a secondary factor from (%s) or enter passcode:'
               % ', '.join(sorted_factors))
        if len(msg) > 253:
            # sanity check. probably shouldn't ever be a problem in practice
            msg = 'Choose a secondary factor or enter passcode:'
    else:
        msg = 'Enter passcode:'
    return msg.encode()


class EAPSession(eap.EAPSession):
    def __init__(self, server, **kwargs):
        self.server = server
        super(EAPSession, self).__init__(**kwargs)

    def success(self, session):
        return self.server.accept_session(session)

    def errback(self, session, reason):
        return self.server.kill_session(session, reason)

    def gtc_received(self, session, passcode: bytes, prompt):
        return self.server.passcode_received(session, passcode.decode(), prompt)


class DuoEAPRadiusServer(DuoSimpleRadiusServer, ChallengeResponseRadiusServer):
    def __init__(self,
                 factors,
                 delim: str,
                 delimited_password_length: int,
                 prompt: str,
                 pkey_file,
                 cert_file,
                 allow_concat: bool = False,
                 cipher_list='',
                 minimum_tls_version='',
                 **kwargs):
        """
        Duo RADIUS server which attempts to start a PEAP/EAP-GTC
        session to get password/factor

        factors: comma-separated list of factor names like "auto,push".

        delim: delimiter for concat-formatted passwords.

        allow_concat: If true, will try to split concat-formatted
        passwords containing delim or delimited_password_length from the first
        GTC response, otherwise send two prompts for password and factor
        separately.

        Note: there is currently no support for self-enrollment here!
        """
        super(DuoEAPRadiusServer, self).__init__(**kwargs)
        self.factors = factors
        self.delim = delim
        self.delimited_password_length = delimited_password_length
        self.allow_concat = allow_concat
        self.prompt = prompt
        self.pkey_file = pkey_file
        self.cert_file = cert_file
        self.cipher_list = cipher_list
        self.minimum_tls_version = minimum_tls_version
        if not os.path.isfile(pkey_file):
            self.pkey_file = os.path.join('conf', pkey_file)
        if not os.path.isfile(cert_file):
            self.cert_file = os.path.join('conf', cert_file)

    def fragment(self, x: bytes):
        stuff = []
        while x:
            stuff.append(x[:253])
            x = x[253:]
        return stuff

    def _create_eap_session(self, request):
        """Creates an EAPSession object for the given request/user.
        Args:
            request (???): user's initial request to start an EAP session
        Returns:
            EAPSession object
        """
        session = EAPSession(
            self,
            pkey=self.pkey_file,
            certs=self.cert_file,
            gtc_message=self.prompt.encode(),
            cipher_list=self.cipher_list,
            minimum_tls_version=self.minimum_tls_version,
        )
        self.log_request(request, 'Creating EAP session for user %s' % (request.username))
        return session

    @defer.inlineCallbacks
    def get_initial_response(self, request):
        """Overridden from abstract method in ChallengeResponseRadiusServer."""
        session = self._create_eap_session(request)
        response = yield self.get_challenge_response(request, None, session=session)
        defer.returnValue(response)

    @defer.inlineCallbacks
    def get_challenge_response(self, request, state, session=None):
        """Overriden from abstract method in ChallengeResponseRadiusServer."""
        if 'EAP-Message' in request.packet:
            request_message = b''.join(request.packet[79])
            if session is None:
                session = state
            session.current_request = request

            add_response = yield session.add_message(request_message)
            if add_response:
                defer.returnValue(add_response)

            response_message = yield session.next_message()

            if isinstance(response_message, bytes):
                # Next EAP message
                response_packet = self.create_challenge(request, '', session)
                response_packet[79] = self.fragment(response_message)
            else:
                # response is a packet from kill_session or accept_session
                response_packet = response_message

            # EAP-Message (79) RADIUS packets MUST include a Message-Authenticator.
            response_packet.add_message_authenticator()
            defer.returnValue(response_packet)

        else:
            # If no EAP, treat it like a normal radius request
            try:
                password = request.password
            except Exception:
                password = None
            if not password:
                # Either PAP but blank or un-decryptable. (Not PAP?
                # Wrong shared secret?). Not EAP, either, or
                # EAP-Message would've been found.
                msg = 'Missing or improperly-formatted password'
                self.log_request(request, msg)
                log.auth_standard(msg=msg,
                                  username=request.username,
                                  auth_stage=log.AUTH_PRIMARY,
                                  status=log.AUTH_ERROR,
                                  client_ip=request.client_ip,
                                  server_section=self.server_section_name,
                                  server_section_ikey=self.server_section_ikey)
                defer.returnValue(
                    self.create_reject_packet(request, msg)
                )
            else:
                result = yield self.auto_auth(request, password)
                defer.returnValue(result)

    @defer.inlineCallbacks
    def passcode_received(self, session, passcode: str, prompt):
        request = session.current_request
        if self.allow_concat:
            # In concat mode, attempt auth on first password
            result = yield self.auto_auth(request, passcode)
            if result.code == packet.AccessAccept:
                session.state = eap.EAP_SESSION_PEAP_ACCEPT
            else:
                session.state = eap.EAP_SESSION_DENY
        else:
            # If we didn't get any input, just resend the last prompt
            if passcode == '':
                return

            if not session.password:
                # otherwise, if this is the first credential we got
                # from the user, then do primary auth
                session.password = passcode
                session.primary_res = yield self.primary_auth(request, session.password)

                # if primary auth fails, send back a reject
                if not session.primary_res.success:
                    session.state = eap.EAP_SESSION_DENY
                    return

                # otherwise, do preauth and proceed according to the response
                resp, preauth_res = yield self.preauth(request, session.primary_res)
                session.state = eap.EAP_SESSION_PEAP_GTC

                if preauth_res is None:
                    if resp.code == packet.AccessAccept:
                        session.state = eap.EAP_SESSION_PEAP_ACCEPT
                    else:
                        session.state = eap.EAP_SESSION_DENY
                else:
                    if preauth_res['result'] == duo_async.API_RESULT_ENROLL:
                        session.enrolling = True
                        gtc_msg = (preauth_res['status'] + ' then try again.').encode()
                        session.innerEAP.gtc_message = gtc_msg
                        session.state = eap.EAP_SESSION_PEAP_GTC
                    elif preauth_res['result'] == duo_async.API_RESULT_AUTH:
                        session.innerEAP.gtc_message = _format_short(preauth_res)
                        session.gtc_message = session.innerEAP.gtc_message
                    elif preauth_res['result'] == duo_async.API_RESULT_DENY:
                        session.state = eap.EAP_SESSION_DENY
                    elif preauth_res['result'] == duo_async.API_RESULT_ALLOW:
                        session.state = eap.EAP_SESSION_PEAP_ACCEPT

            elif session.enrolling:
                # Always deny an auth attempt after displaying enrollment link
                session.state = eap.EAP_SESSION_DENY
            else:
                result = yield self.auto_auth(
                    request,
                    session.password,
                    factor=passcode,
                    primary_res=session.primary_res
                )
                if result.code == packet.AccessAccept:
                    session.state = eap.EAP_SESSION_PEAP_ACCEPT
                elif passcode.rstrip('0123456789') == 'sms':
                    # Let them enter an SMSed passcode
                    if 'Reply-Message' in result:
                        session.innerEAP.gtc_message = (result['Reply-Message'][0] + '\n' + session.innerEAP.gtc_message).encode()
                    else:
                        # Reject result and no reply message means primary auth failed, no sms sent
                        log.auth_standard(msg="Duo authentication failed",
                                          username=request.username,
                                          auth_stage=log.AUTH_SECONDARY,
                                          status=log.AUTH_REJECT,
                                          client_ip=request.client_ip,
                                          server_section=self.server_section_name,
                                          server_section_ikey=self.server_section_ikey)
                        session.state = eap.EAP_SESSION_DENY
                else:
                    log.auth_standard(msg="Unrecognized passcode",
                                      username=request.username,
                                      auth_stage=log.AUTH_SECONDARY,
                                      status=log.AUTH_REJECT,
                                      client_ip=request.client_ip,
                                      server_section=self.server_section_name,
                                      server_section_ikey=self.server_section_ikey)
                    session.state = eap.EAP_SESSION_DENY

    def kill_session(self, session, reason):
        request = session.current_request
        self.log_request(request, 'Destroying EAP session: %s' % (reason))
        response_packet = self.create_reject_packet(request)
        return response_packet

    def accept_session(self, session: EAPSession) -> packet.Packet:
        request = session.current_request
        response_packet = self.create_accept_packet(request)
        eap_packet = eap.EAPPacket(eap.EAP_CODE_SUCCESS, session.id, 0, b'')
        response_packet[79] = [eap_packet.render()]
        mppe_keys = mppe.get_mppe_keys(
            session.mk,
            session.cr,
            session.sr,
            b'client EAP encryption',
            session.ssl_con
        )
        mppe.add_mppe(
            response_packet,
            mppe_keys,
            self.secret_for_host(request.source[0]).encode(),
            request.packet.authenticator
        )
        self.kill_session(session, 'Success')
        self.log_request(request, 'Authentication successful')
        return response_packet

    @defer.inlineCallbacks
    def auto_auth(self, request, password: str, factor=None, primary_res=None):
        if not factor:
            if util.should_try_splitting_password(password,
                                                  self.allow_concat,
                                                  self.delim,
                                                  self.delimited_password_length):
                # User may specify passcode or factor with concat.
                # Speculatively split the password. If primary auth
                # succeeds, it was concat.
                #
                # Could reduce false-positives by checking if the part
                # after the last delim actually looks like a factor.
                # However, the general case is difficult because of
                # e.g. ModHex passcodes.
                password_part, factor = util.do_password_split(password,
                                                               self.delim,
                                                               self.delimited_password_length)
                if not factor:
                    factor = None
                    self.log_request(request, 'attempting authentication with factor auto')
                else:
                    self.log_request(request, 'attempting authentication with factor %s' % (factor))
                if primary_res is None:
                    primary_res = yield self.primary_auth(
                        request,
                        password_part
                    )
            else:
                primary_res = None
                factor = None

            if not (primary_res and primary_res.success):
                # (Re)try primary auth with the whole password if:
                # * No delim or delimited_password_length for concat.
                # * Delim found, but primary auth failed indicating it
                #   was not really concat.
                # * Concat was intended but the primary auth password
                #   part was wrong. If so, this will fail, too.
                primary_res = yield self.primary_auth(request, password)
                factor = None
        else:
            if primary_res is None:
                primary_res = yield self.primary_auth(request, password)

        if primary_res.success:
            result = yield self.duo_auth(request, primary_res, factor=factor)
        else:
            result = self.create_reject_packet(request)

        defer.returnValue(result)

    @defer.inlineCallbacks
    def duo_auth(self, request, primary_res, factor=None, preauth_res=None):
        if not preauth_res:
            # Must call preauth even if the factor is known.
            response_packet, preauth_res = yield self.preauth(request,
                                                              primary_res)
            if response_packet is not None:
                # E.g. enroll policy of deny or allow.
                defer.returnValue(response_packet)
        if factor is None:
            factor = util.factor_for_request(self.factors, preauth_res)
            if factor is None:
                msg = 'User has no Duo factors usable with this configuration'
                log.auth_standard(msg=msg,
                                  username=request.username,
                                  auth_stage=log.AUTH_SECONDARY,
                                  status=log.AUTH_ERROR,
                                  client_ip=request.client_ip,
                                  server_section=self.server_section_name,
                                  server_section_ikey=self.server_section_ikey)
                self.log_request(request, msg)
                defer.returnValue(self.create_reject_packet(request, msg))

        # Factor was either passed in or found above auto-push
        response_packet = yield super(DuoEAPRadiusServer, self).duo_auth(
            request,
            primary_res,
            factor,
        )
        defer.returnValue(response_packet)


class Module(ServerModule):
    def __init__(self, config, primary_ator, server_section_name):
        log.msg('RADIUS PEAP/EAP-GTC Automatic Factor Server Module Configuration:')
        log.config(
            config, lambda x: x.startswith('radius_secret') or
            x in ('skey', 'skey_protected'))

        self.protocol = DuoEAPRadiusServer(
            secrets=parse_radius_secrets(config),
            primary_ator=primary_ator,
            duo_client=self.make_duo_client(config),
            failmode=config.get_enum('failmode', duo_async.FAILMODES,
                                     duo_async.FAILMODE_SAFE,
                                     transform=str.lower),
            factors=util.parse_factor_list(config.get_str('factors', 'auto')),
            delim=config.get_str('delimiter', ','),
            delimited_password_length=config.get_int('delimited_password_length', 0),
            allow_concat=config.get_bool('allow_concat', False),
            debug=config.get_bool('debug', False),
            pass_through_attr_names=config.get_str('pass_through_attr_names', ''),
            prompt=config.get_str('prompt', 'Enter your password: '),
            pkey_file=config.get_str('pkey'),
            cert_file=config.get_str('certs'),
            cipher_list=config.get_str('cipher_list', ''),
            minimum_tls_version=config.get_str('minimum_tls_version', ''),
            pw_codec=config.get_str('pw_codec', 'utf-8'),
            client_ip_attr=parse_client_ip_attribute(config),
            server_section_name=server_section_name,
            pass_through_all=config.get_bool('pass_through_all', False),
        )
