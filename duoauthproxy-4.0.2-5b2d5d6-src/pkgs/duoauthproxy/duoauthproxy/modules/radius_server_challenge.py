#
# Copyright (c) 2011 Duo Security
# All Rights Reserved
#

import re
import xml.sax.saxutils

from twisted.internet import defer

from ..lib.base import ServerModule
from ..lib.radius.challenge import ChallengeResponseRadiusServer, RADIUS_CHALLENGE_PROMPT_FORMATS
from ..lib.radius.server import parse_radius_secrets
from ..lib.radius.server import parse_exempt_usernames
from ..lib.radius.server import parse_client_ip_attribute
from ..lib import duo_async, log, util
from ..lib.radius.base import MS_CHAP2_REQUEST_ATTRS


def _format_console(preauth_res):
    return preauth_res['prompt']


def _format_html(preauth_res):
    lines = (xml.sax.saxutils.escape(x.strip()) for x
             in preauth_res['prompt'].splitlines())
    return '<br>'.join(lines)


def _format_short(preauth_res):
    factors = preauth_res['factors']
    if factors:
        sorted_factors = ('\'%s\'' % factors[k]
                          for k in sorted(factors.keys())
                          if k != 'default')
        msg = ('Choose a secondary factor from (%s) or enter passcode:'
               % ', '.join(sorted_factors))
        if len(msg) > 253:
            # sanity check. probably shouldn't ever be a problem in practice
            msg = 'Choose a secondary factor or enter passcode:'
    else:
        msg = 'Enter passcode:'
    return msg


class DuoTextChallengeRadiusServer(ChallengeResponseRadiusServer):
    SMSREFRESH_RE = re.compile(r'sms\d+')

    FORMATTERS = {
        'console': _format_console,
        'html': _format_html,
        'short': _format_short
    }

    def __init__(self, prompt_format, enroll_challenge, failmode,
                 duo_client,
                 **kwargs):
        """Generic Duo text-based RADIUS Challenge-Response server

        duo_client: AuthDuoClient.
        prompt_format: 'console', 'html', or 'short':
            - 'console' will provide the unmodified prompt text from the
               preauth api endpoint
            - 'html' will replace all line breaks in the prompt text with
               '<br>' tags
            - 'short' will just list the factor names without any description
              if 'console' or 'html' is selected and the text will overflow
              the 253-character RADIUS limit, then we automatically fall back
              on 'short' instead.
        enroll_challenge: If True, then we will send enrollment messages
            in AccessChallenge packets instead of AccessReject packets.
            AccessReject is the correct logical case here, but in many (most?)
            cases, devices will only pass the Reply-Message attribute through
            to users if we have sent an AccessChallenge message. Note that
            we will automatically reject any replies to the challenge; after
            enrolling, users will need to start over
        failmode: 'safe' or 'secure' - 'safe' will allow users to bypass duo
            authentication if the service is unavailable, 'secure' will not"""

        super(DuoTextChallengeRadiusServer, self).__init__(**kwargs)

        self.client = duo_client
        if prompt_format not in self.FORMATTERS:
            raise ValueError("Invalid prompt_format")
        self.formatter = self.FORMATTERS[prompt_format]
        self.enroll_challenge = enroll_challenge
        self.failmode = failmode

    def _format_msg(self, preauth_res):
        """ Format the msg, and ensure it will fit in the RADIUS message. """
        msg = self.formatter(preauth_res)
        if len(msg) > 253:
            # force short format
            msg = _format_short(preauth_res)
        return msg

    def _is_chap2_req(self, request):
        """ Return True iff the request is MS-CHAP2. """
        return any(a in request for a in MS_CHAP2_REQUEST_ATTRS)

    def _error_attrs(self, request):
        """ Return the MS-CHAP-Error attribute, if this is MS-CHAP2 request """
        if self._is_chap2_req(request):
            return {'MS-CHAP-Error': self.MS_AUTH_FAILED_ERROR}
        else:
            return {}

    def _create_proxy_response(self, request, primary_res, msg=None):
        """ Given a primary_auth response, build an accept/reject packet """
        if msg is None:
            msg = primary_res.msg

        if primary_res.success:
            self.log_request(request, 'Sending access accept packet')
            response = self.create_accept_packet(
                request,
                msg,
                primary_res.radius_attrs
            )
        else:
            self.log_request(request, 'Sending access reject packet')
            response = self.create_reject_packet(
                request,
                msg,
                primary_res.radius_attrs
            )

        return response

    @defer.inlineCallbacks
    def _preauth_cpw_response(self, request, preauth_res):
        """
        Handle the Preauth results, when the RADIUS request includes a MS-CHAPv2
        Change Password attribute.

        request -- Client RADIUS Access Request message
        preauth_res -- Duo PreAuth value for the user specified in the request

        Returns a RADIUS response to send to the client.  This could be a RADIUS
        rejection message if preauth failed, a RADIUS challenge, or a RADIUS
        access-accept.
        """
        if preauth_res['result'] == duo_async.API_RESULT_ALLOW:
            # User is configured to bypass AUTH.
            # Forward the request to the RADIUS server.
            primary_res = yield self.primary_auth(
                request,
                request.password
            )
            defer.returnValue(self._create_proxy_response(request, primary_res))

        elif preauth_res['result'] == duo_async.API_RESULT_DENY:
            # User is not permitted to authenticate at this time
            msg = preauth_res['status']
            # Clients expect an MS-CHAP-Error attribute
            radius_attrs = {'MS-CHAP-Error': self.MS_AUTH_FAILED_ERROR}
            self.log_request(request, msg)
            self.log_request(request, 'Sending deny access reject packet')
            log.auth_standard(
                msg=msg,
                username=request.username,
                auth_stage=log.AUTH_SECONDARY,
                status=log.AUTH_REJECT,
                client_ip=request.client_ip,
                server_section=self.server_section_name,
                server_section_ikey=self.server_section_ikey
            )
            defer.returnValue(self.create_reject_packet(request, msg, radius_attrs))
        elif preauth_res['result'] == duo_async.API_RESULT_ENROLL:
            # User is not known to the system.  Give the user enrollment
            # instructions, and deny access.
            msg = preauth_res['status']

            if self.enroll_challenge:
                state = {
                    'challenge_handler': self.handle_enroll_challenge,
                    'cpw': request,
                    'is_chap2': True
                }
                challenge_packet = self.create_challenge(request, msg, state)
                msg_enroll_challenge = log.AUTH_ENROLL_MSG
                self.log_request(request, 'Sending enrollment challenge packet')
                log.auth_standard(
                    msg=msg_enroll_challenge,
                    username=request.username,
                    auth_stage=log.AUTH_SECONDARY,
                    status=log.AUTH_REJECT,
                    client_ip=request.client_ip,
                    server_section=self.server_section_name,
                    server_section_ikey=self.server_section_ikey
                )
                defer.returnValue(challenge_packet)
            else:
                # Clients expect an MS-CHAP-Error attribute
                radius_attrs = {'MS-CHAP-Error': self.MS_AUTH_FAILED_ERROR}
                reject_packet = self.create_reject_packet(request, msg, radius_attrs)

                msg_enroll_reject = log.AUTH_ENROLL_MSG
                self.log_request(request, 'Sending enrollment reject packet')
                log.auth_standard(
                    msg=msg_enroll_reject,
                    username=request.username,
                    auth_stage=log.AUTH_SECONDARY,
                    status=log.AUTH_REJECT,
                    client_ip=request.client_ip,
                    server_section=self.server_section_name,
                    server_section_ikey=self.server_section_ikey
                )
                defer.returnValue(reject_packet)
        elif preauth_res['result'] == duo_async.API_RESULT_AUTH:
            # User is all set to 2fa.  Send a challenge, so they can
            # choose which 2fa method to use.
            msg = self._format_msg(preauth_res)

            # store state, create challenge
            state = {
                'challenge_handler': self.handle_cpw_auth_challenge,
                'cpw': request,
                'is_chap2': True,
                'factors': preauth_res['factors'],
                'prompt': msg
            }
            challenge_packet = self.create_challenge(request, msg, state)
            self.log_request(request, 'Sending authentication challenge packet')
            defer.returnValue(challenge_packet)
        raise RuntimeError("Unexpected preauth result")

    def _preauth_response(self, request, primary_res, preauth_res):
        """
        Handle preauth results, for all non-CHAP2 Change Password RADIUS requests.

        request -- Client Radius Access Request
        primary_res -- Primary authentication response, from the RADIUS server
        preauth_res -- Duo PreAuth response for the user named in the RADIUS request

        Return a RADIUS response to send to the client.
        """
        if preauth_res['result'] == duo_async.API_RESULT_ALLOW:
            msg = preauth_res['status']
            self.log_request(request, msg)
            log.auth_standard(
                msg=msg,
                username=request.username,
                auth_stage=log.AUTH_SECONDARY,
                status=log.AUTH_ALLOW,
                client_ip=request.client_ip,
                server_section=self.server_section_name,
                server_section_ikey=self.server_section_ikey
            )
            return self._create_proxy_response(
                request,
                primary_res,
                preauth_res['status']
            )

        elif preauth_res['result'] == duo_async.API_RESULT_DENY:
            if preauth_res['status'] == duo_async.FAILMODE_SECURE_MSG:
                deny_status = log.AUTH_ERROR
            else:
                deny_status = log.AUTH_REJECT
            msg = preauth_res['status']
            self.log_request(request, msg)
            self.log_request(request, 'Sending auth deny access reject packet')
            log.auth_standard(
                msg=msg,
                username=request.username,
                auth_stage=log.AUTH_SECONDARY,
                status=deny_status,
                client_ip=request.client_ip,
                server_section=self.server_section_name,
                server_section_ikey=self.server_section_ikey
            )
            radius_attrs = self._error_attrs(request)
            return self.create_reject_packet(request, msg, radius_attrs)

        elif preauth_res['result'] == duo_async.API_RESULT_ENROLL:
            msg = preauth_res['status']
            if self.enroll_challenge:
                state = {
                    'challenge_handler': self.handle_enroll_challenge,
                    'primary_res': primary_res,
                    'is_chap2': self._is_chap2_req(request)
                }
                self.log_request(request, 'Sending enrollment challenge packet')
                return self.create_challenge(request, msg, state)
            else:
                radius_attrs = self._error_attrs(request)
                msg_enroll_reject = log.AUTH_ENROLL_MSG
                self.log_request(request, 'Sending enrollment reject packet')
                log.auth_standard(
                    msg=msg_enroll_reject,
                    username=request.username,
                    auth_stage=log.AUTH_SECONDARY,
                    status=log.AUTH_REJECT,
                    client_ip=request.client_ip,
                    server_section=self.server_section_name,
                    server_section_ikey=self.server_section_ikey
                )
                return self.create_reject_packet(request, msg, radius_attrs)

        elif preauth_res['result'] == duo_async.API_RESULT_AUTH:
            msg = self._format_msg(preauth_res)

            # store state, create challenge
            state = {
                'challenge_handler': self.handle_auth_challenge,
                'primary_res': primary_res,
                'is_chap2': self._is_chap2_req(request),
                'factors': preauth_res['factors'],
                'prompt': msg
            }
            self.log_request(request, 'Sending authentication challenge packet')
            return self.create_challenge(request, msg, state)
        raise RuntimeError("Unexpected preauth result")

    @defer.inlineCallbacks
    def preauth(self, request):
        """
        Get the user's duo auth status, and return it.  On API error,
        this builds an appropriate fake response.

        request -- The user's RADIUS request

        Returns the preauth result.
        """
        if request.username in self.exempt_usernames:
            exempt_msg = 'User exempted from 2FA'
            preauth_res = {
                'result': duo_async.API_RESULT_ALLOW,
                'status': exempt_msg,
            }
            defer.returnValue(preauth_res)

        try:
            preauth_res = yield self.client.preauth(request.username, request.client_ip, self.failmode)
        except duo_async.DuoAPIError as e:
            log.err(None, 'Duo preauth call failed')
            if duo_async.should_server_fail_open(self.failmode, e.fail_open):
                preauth_res = {
                    'result': duo_async.API_RESULT_ALLOW,
                    'status': duo_async.get_fail_open_msg(),
                }
            else:
                preauth_res = {
                    'result': duo_async.API_RESULT_DENY,
                    'status': duo_async.FAILMODE_SECURE_MSG,
                }
        else:
            if 'status' in preauth_res:
                self.log_request(request, 'Duo preauth returned \'%s\': \'%s\''
                                 % (preauth_res['result'], preauth_res['status']))
            else:
                self.log_request(request, 'Duo preauth returned \'%s\''
                                 % preauth_res['result'])
        defer.returnValue(preauth_res)

    @defer.inlineCallbacks
    def get_initial_response(self, request):
        """
        Called when a RADIUS Access Request without a State attribute
        is received.

        Returns a RADIUS message to send to the client.
        """
        if request.username is None:
            msg = 'No username provided'
            self.log_request(request, msg)
            log.auth_standard(
                msg=msg,
                username=request.username,
                auth_stage=log.AUTH_PRIMARY,
                status=log.AUTH_ERROR,
                client_ip=request.client_ip,
                server_section=self.server_section_name,
                server_section_ikey=self.server_section_ikey
            )
            radius_attrs = self._error_attrs(request)
            defer.returnValue(self.create_reject_packet(request, msg, radius_attrs=radius_attrs))

        self.log_request(request, 'login attempt for username %r'
                         % request.username)

        if 'MS-CHAP2-CPW' in request:
            # The user is trying to change their password.  Users should not be
            # allowed to change their password unless they have successfully
            # 2-Factored first.
            preauth_res = yield self.preauth(request)
            response_packet = yield self._preauth_cpw_response(request, preauth_res)

            defer.returnValue(response_packet)

        if (request.password is None and
                not self._is_chap2_req(request)):
            # Neither password nor MS-CHAP2 attributes present
            self.log_request(
                request,
                'Only PAP with a Shared Secret format or CHAP2 are'
                ' supported. Is the system communicating with'
                ' the Authentication Proxy using CHAP or'
                ' something else instead?'
            )
            msg = 'No password or CHAP2 attributes provided'
            self.log_request(request, msg)
            log.auth_standard(
                msg=msg,
                username=request.username,
                auth_stage=log.AUTH_PRIMARY,
                status=log.AUTH_ERROR,
                client_ip=request.client_ip,
                server_section=self.server_section_name,
                server_section_ikey=self.server_section_ikey
            )
            defer.returnValue(self.create_reject_packet(request, msg))

        # perform primary authentication
        primary_res = yield self.primary_auth(request, request.password)

        if not primary_res.success:
            # If the error is Password Expired, then preauth.
            # Otherwise, send the Access Reject to the user
            if ('MS-CHAP-Error' in primary_res.radius_attrs):
                m = self.MS_ERRCODE_RE.match(primary_res.radius_attrs['MS-CHAP-Error'][0])
                if (m is not None and
                        int(m.group('E')) == self.ERROR_PASSWORD_EXPIRED):

                    preauth_res = yield self.preauth(request)
                    if preauth_res['result'] == duo_async.API_RESULT_DENY:
                        msg = preauth_res['status']
                        log.auth_standard(
                            msg=msg,
                            username=request.username,
                            auth_stage=log.AUTH_SECONDARY,
                            status=log.AUTH_REJECT,
                            client_ip=request.client_ip,
                            server_section=self.server_section_name,
                            server_section_ikey=self.server_section_ikey
                        )
                        self.log_request(request, 'Sending auth deny access reject packet')
                        radius_attrs = {'MS-CHAP-Error': self.MS_AUTH_FAILED_ERROR}
                        defer.returnValue(self.create_reject_packet(request,
                                                                    radius_attrs=radius_attrs))

                    elif preauth_res['result'] == duo_async.API_RESULT_ENROLL:
                        if self.enroll_challenge:
                            state = {
                                'challenge_handler': self.handle_enroll_challenge,
                                'cpw': request,
                                'is_chap2': True,
                                'primary_res': primary_res
                            }
                            challenge_packet = self.create_challenge(
                                request,
                                preauth_res['status'],
                                state
                            )
                            msg_challenge = log.AUTH_ENROLL_MSG
                            self.log_request(request, 'Sending enrollment challenge packet')
                            log.auth_standard(
                                msg=msg_challenge,
                                username=request.username,
                                auth_stage=log.AUTH_SECONDARY,
                                status=log.AUTH_REJECT,
                                client_ip=request.client_ip,
                                server_section=self.server_section_name,
                                server_section_ikey=self.server_section_ikey
                            )
                            defer.returnValue(challenge_packet)

                        # Clients expect an MS-CHAP-Error attribute
                        msg = preauth_res['status']
                        radius_attrs = {'MS-CHAP-Error': self.MS_AUTH_FAILED_ERROR}
                        reject_packet = self.create_reject_packet(request, msg, radius_attrs)

                        msg_reject = log.AUTH_ENROLL_MSG
                        self.log_request(request, 'Sending enrollment reject packet')
                        log.auth_standard(
                            msg=msg_reject,
                            username=request.username,
                            auth_stage=log.AUTH_SECONDARY,
                            status=log.AUTH_REJECT,
                            client_ip=request.client_ip,
                            server_section=self.server_section_name,
                            server_section_ikey=self.server_section_ikey
                        )
                        defer.returnValue(reject_packet)

            defer.returnValue(self._create_proxy_response(
                request,
                primary_res
            ))

        # do duo preauth to get factor list, authorization status
        preauth_res = yield self.preauth(request)
        response_packet = self._preauth_response(
            request,
            primary_res,
            preauth_res
        )
        defer.returnValue(response_packet)

    def handle_enroll_challenge(self, request, state):
        """ Intended to act as a challenge handler
        For users who must enroll we need to send an Access-Reject and require then to auth again after enrolling
        """
        msg = 'Please complete the enrollment process and login again'
        radius_attrs = self._error_attrs(request)
        log.auth_standard(
            msg=msg,
            username=request.username,
            auth_stage=log.AUTH_SECONDARY,
            status=log.AUTH_REJECT,
            client_ip=request.client_ip,
            server_section=self.server_section_name,
            server_section_ikey=self.server_section_ikey
        )
        return self.create_reject_packet(request, msg, radius_attrs)

    @defer.inlineCallbacks
    def handle_cpw_auth_challenge(self, request, state):
        """ Handle the user's auth challenge response, in the change password case """

        res = yield self.handle_auth_challenge(request, state, cpw_auth=True)
        defer.returnValue(res)

    @defer.inlineCallbacks
    def handle_auth_challenge(self, request, state, cpw_auth=False):
        """
        Handle the user's auth challenge.

        request -- Initial request that triggered the challenge response
        state -- State kept during challenge, and looked up during the
                 client's corresponding Access Request reply to the Challenge
        cpw_auth -- True if we still need to execute the change password primary auth

        Builds a RADIUS response to be sent to the client.
        """
        passcode = request.password

        if passcode is None:
            # E.g. CHAP requests.
            passcode = ''
        # see if we were provided a factor number
        if passcode in state['factors']:
            passcode = state['factors'][request.password]

        # we never want to log non factor data! (eg. passcodes)
        factor = passcode if util.is_factor(passcode) else None

        # do auth request
        try:
            auth_res = yield self.client.auth(request.username,
                                              passcode,
                                              request.client_ip)
        except duo_async.DuoAPIError as e:
            log.err(None, 'Duo auth call failed')
            if duo_async.should_server_fail_open(self.failmode, e.fail_open):
                if cpw_auth:
                    primary_res = yield self.primary_auth(state['cpw'], None)
                    response_packet = self._create_proxy_response(request, primary_res)
                else:
                    if 'primary_res' in state:
                        radius_attrs = state['primary_res'].radius_attrs
                    else:
                        radius_attrs = {}
                    msg = duo_async.get_fail_open_msg()
                    response_packet = self.create_accept_packet(
                        request,
                        msg,
                        radius_attrs
                    )
                    log.auth_standard(
                        msg=msg,
                        username=request.username,
                        auth_stage=log.AUTH_SECONDARY,
                        status=log.AUTH_ALLOW,
                        client_ip=request.client_ip,
                        server_section=self.server_section_name,
                        server_section_ikey=self.server_section_ikey,
                        factor=factor
                    )
            else:
                if 'primary_res' in state:
                    radius_attrs = state['primary_res'].radius_attrs
                else:
                    radius_attrs = {}
                if state['is_chap2']:
                    radius_attrs['MS-CHAP-Error'] = self.MS_AUTH_FAILED_ERROR
                response_packet = self.create_reject_packet(
                    request,
                    duo_async.FAILMODE_SECURE_MSG,
                    radius_attrs
                )
                log.auth_standard(
                    msg=duo_async.FAILMODE_SECURE_MSG,
                    username=request.username,
                    auth_stage=log.AUTH_SECONDARY,
                    status=log.AUTH_REJECT,
                    client_ip=request.client_ip,
                    server_section=self.server_section_name,
                    server_section_ikey=self.server_section_ikey,
                    factor=factor
                )
            defer.returnValue(response_packet)
        if self.SMSREFRESH_RE.match(passcode):
            response_packet = self.create_challenge(request, state['prompt'],
                                                    state)
            self.log_request(request, 'Re-sending challenge after sms refresh')
        else:
            msg = auth_res['status']
            self.log_request(request,
                             'Duo authentication returned \'%s\': \'%s\''
                             % (auth_res['result'], msg))
            if auth_res['result'] == duo_async.API_RESULT_ALLOW:
                log.auth_standard(
                    msg=msg,
                    username=request.username,
                    auth_stage=log.AUTH_SECONDARY,
                    status=log.AUTH_ALLOW,
                    client_ip=request.client_ip,
                    server_section=self.server_section_name,
                    server_section_ikey=self.server_section_ikey,
                    factor=factor
                )
                if cpw_auth:
                    primary_res = yield self.primary_auth(state['cpw'], None)
                    response_packet = self._create_proxy_response(request, primary_res)
                else:
                    response_packet = self._create_proxy_response(
                        request,
                        state['primary_res'],
                        msg
                    )
            else:
                if (cpw_auth or state['is_chap2']):
                    radius_attrs = {'MS-CHAP-Error': self.MS_AUTH_FAILED_ERROR}
                else:
                    radius_attrs = {}
                response_packet = self.create_reject_packet(request, msg, radius_attrs)
                log.auth_standard(
                    msg=msg,
                    username=request.username,
                    auth_stage=log.AUTH_SECONDARY,
                    status=log.AUTH_REJECT,
                    client_ip=request.client_ip,
                    server_section=self.server_section_name,
                    server_section_ikey=self.server_section_ikey,
                    factor=factor
                )
        defer.returnValue(response_packet)

    def get_challenge_response(self, request, state):
        """
        Call the callback registered in the state's 'challenge_handler' key.
        Return the response generated by the callback.
        """
        response_packet = state['challenge_handler'](request, state)
        return response_packet


class Module(ServerModule):
    def __init__(self, config, primary_client, server_section_name):
        log.msg('RADIUS Challenge Server Module Configuration:')
        log.config(
            config, lambda x: x.startswith('radius_secret') or
            x in ('skey', 'skey_protected'))
        prompt_format = config.get_enum('prompt_format',
                                        RADIUS_CHALLENGE_PROMPT_FORMATS,
                                        'console',
                                        transform=str.lower)
        enroll_challenge = config.get_bool('enroll_challenge', True)
        failmode = config.get_enum('failmode', duo_async.FAILMODES,
                                   duo_async.FAILMODE_SAFE,
                                   transform=str.lower)
        secrets = parse_radius_secrets(config)

        self.protocol = DuoTextChallengeRadiusServer(
            prompt_format, enroll_challenge, failmode,
            duo_client=self.make_duo_client(config),
            exempt_usernames=parse_exempt_usernames(config),
            secrets=secrets,
            primary_ator=primary_client,
            pass_through_attr_names=config.get_str('pass_through_attr_names', ''),
            pass_through_all=config.get_bool('pass_through_all', False),
            pw_codec=config.get_str('pw_codec', 'utf-8'),
            client_ip_attr=parse_client_ip_attribute(config),
            server_section_name=server_section_name,
            server_section_ikey=config.get_str('ikey', '')
        )
