#
# Copyright (c) 2011 Duo Security
# All Rights Reserved
#

from twisted.internet import defer

from duoauthproxy.lib import duo_async, log, ip_util
from duoauthproxy.lib.radius.server import SimpleRadiusServer
from duoauthproxy.lib.radius.api_error_handling import ApiErrorHandling


class DuoSimpleRadiusServer(SimpleRadiusServer, ApiErrorHandling):

    def __init__(self, duo_client, failmode,
                 exempt_usernames=None, **kwargs):
        """Mixin for Duo RADIUS server w/o challenges for factor or enrollment.

        Child classes that inherit from this should implement get_response()
        from SimpleRadiusServer.

        duo_client: AuthDuoClient
        failmode: 'safe' or 'secure' - 'safe' will allow users to bypass duo
            authentication if the service is unavailable, 'secure' will not
        """
        super(DuoSimpleRadiusServer, self).__init__(**kwargs)
        self.client = duo_client
        self.failmode = failmode
        if exempt_usernames is None:
            self.exempt_usernames = []
        else:
            self.exempt_usernames = exempt_usernames

    @defer.inlineCallbacks
    def duo_preauth(self, request):
        """
        Get the user's duo auth status, and return it.  On API error,
        this builds an appropriate failure return.

        request -- The user's RADIUS request

        Returns the preauth JSON result.
        """
        try:
            if request.username in self.exempt_usernames:
                preauth_message = 'User exempted from 2FA'
                preauth_res = {
                    'result': duo_async.API_RESULT_ALLOW,
                    'status': preauth_message
                }
            else:
                preauth_res = yield self.client.preauth(request.username, request.client_ip, self.failmode)
        except duo_async.DuoAPIError as e:
            log.err(None, 'Duo preauth call failed')
            if duo_async.should_server_fail_open(self.failmode, e.fail_open):
                preauth_message = duo_async.get_fail_open_msg()
                preauth_res = {
                    'result': duo_async.API_RESULT_ALLOW,
                    'status': 'API call failed'
                }
            else:
                preauth_message = duo_async.FAILMODE_SECURE_MSG
                preauth_res = {
                    'result': duo_async.API_RESULT_DENY,
                    'status': 'API call failed'
                }
        else:
            if 'status' in preauth_res:
                preauth_message = 'Duo preauth returned \'%s\': \'%s\'' % (preauth_res['result'], preauth_res['status'])
                self.log_request(request, preauth_message)
            else:
                preauth_message = 'Duo preauth returned \'%s\'' % preauth_res['result']
                self.log_request(request, preauth_message)

        if preauth_res['result'] == duo_async.API_RESULT_ALLOW:
            log.auth_standard(msg=preauth_message,
                              username=request.username,
                              auth_stage=log.AUTH_SECONDARY,
                              status=log.AUTH_ALLOW,
                              client_ip=request.client_ip,
                              server_section=self.server_section_name,
                              server_section_ikey=self.server_section_ikey)
        elif preauth_res['result'] == duo_async.API_RESULT_DENY:
            log.auth_standard(msg=preauth_message,
                              username=request.username,
                              auth_stage=log.AUTH_SECONDARY,
                              status=log.AUTH_REJECT,
                              client_ip=request.client_ip,
                              server_section=self.server_section_name,
                              server_section_ikey=self.server_section_ikey)
        elif preauth_res['result'] == duo_async.API_RESULT_ENROLL:
            log.auth_standard(msg=log.AUTH_ENROLL_MSG,
                              username=request.username,
                              auth_stage=log.AUTH_SECONDARY,
                              status=log.AUTH_REJECT,
                              client_ip=request.client_ip,
                              server_section=self.server_section_name,
                              server_section_ikey=self.server_section_ikey)

        defer.returnValue(preauth_res)

    @defer.inlineCallbacks
    def preauth(self, request, primary_res, radius_reject_attrs=None):
        # perform preauth request
        if radius_reject_attrs is None:
            radius_reject_attrs = {}
        try:
            if request.username in self.exempt_usernames:
                preauth_res = {
                    'result': duo_async.API_RESULT_ALLOW,
                    'status': 'User exempted from 2FA'
                }
            else:
                preauth_res = yield self.client.preauth(request.username, request.client_ip, self.failmode)
        except duo_async.DuoAPIError as e:
            log.err(None, 'Duo preauth call failed')
            response = self.response_for_api_error(request,
                                                   primary_res,
                                                   e,
                                                   radius_reject_attrs)
            defer.returnValue((response, None))

        self.log_request(request, 'Got preauth result for: %r'
                         % (preauth_res['result'],))

        if preauth_res['result'] == duo_async.API_RESULT_ALLOW:
            msg = preauth_res['status']
            log.auth_standard(msg=msg,
                              username=request.username,
                              auth_stage=log.AUTH_SECONDARY,
                              status=log.AUTH_ALLOW,
                              client_ip=request.client_ip,
                              server_section=self.server_section_name,
                              server_section_ikey=self.server_section_ikey)
            response = self.create_accept_packet(
                request,
                msg,
                primary_res.radius_attrs,
            )
        elif preauth_res['result'] == duo_async.API_RESULT_DENY:
            msg = preauth_res['status']
            log.auth_standard(msg=msg,
                              username=request.username,
                              auth_stage=log.AUTH_SECONDARY,
                              status=log.AUTH_REJECT,
                              client_ip=request.client_ip,
                              server_section=self.server_section_name,
                              server_section_ikey=self.server_section_ikey)
            response = self.create_reject_packet(request, msg, radius_attrs=radius_reject_attrs)
        elif preauth_res['result'] == duo_async.API_RESULT_ENROLL:
            msg = preauth_res['status']
            log.auth_standard(msg=log.AUTH_ENROLL_MSG,
                              username=request.username,
                              auth_stage=log.AUTH_SECONDARY,
                              status=log.AUTH_REJECT,
                              client_ip=request.client_ip,
                              server_section=self.server_section_name,
                              server_section_ikey=self.server_section_ikey)
            response = self.create_reject_packet(request, msg, radius_attrs=radius_reject_attrs)
        else:
            # duo_async.API_RESULT_AUTH - return a sentinel value
            # saying we should continue
            response = None
        defer.returnValue((response, preauth_res))

    @defer.inlineCallbacks
    def duo_auth_only(self, request, factor):
        """
        duo_auth and return its result.  On failure, generate an appropriate
        response based on the configured failmode.
        """
        try:
            client_ip = request.client_ip
            if not ip_util.is_valid_ip(client_ip):
                client_ip = None
            auth_res = yield self.client.auth(request.username,
                                              factor,
                                              client_ip)
        except duo_async.DuoAPIError as e:
            log.err(None, 'Duo auth call failed')
            if duo_async.should_server_fail_open(self.failmode, e.fail_open):
                msg = duo_async.get_fail_open_msg()
                self.log_request(request, msg)
                log.auth_standard(msg=msg,
                                  username=request.username,
                                  auth_stage=log.AUTH_SECONDARY,
                                  status=log.AUTH_ALLOW,
                                  client_ip=request.client_ip,
                                  server_section=self.server_section_name,
                                  server_section_ikey=self.server_section_ikey)
                ret = {
                    'result': duo_async.API_RESULT_ALLOW,
                    'status': msg
                }
                defer.returnValue(ret)
            else:
                msg = duo_async.FAILMODE_SECURE_MSG
                self.log_request(request, msg)
                log.auth_standard(msg=msg,
                                  username=request.username,
                                  auth_stage=log.AUTH_SECONDARY,
                                  status=log.AUTH_ERROR,
                                  client_ip=request.client_ip,
                                  server_section=self.server_section_name,
                                  server_section_ikey=self.server_section_ikey)
                ret = {
                    'result': duo_async.API_RESULT_DENY,
                    'status': msg
                }
                defer.returnValue(ret)

        if auth_res['result'] == duo_async.API_RESULT_ALLOW:
            log.auth_standard(msg=auth_res['status'],
                              username=request.username,
                              auth_stage=log.AUTH_SECONDARY,
                              status=log.AUTH_ALLOW,
                              client_ip=request.client_ip,
                              server_section=self.server_section_name,
                              server_section_ikey=self.server_section_ikey)
        else:
            log.auth_standard(msg=auth_res['status'],
                              username=request.username,
                              auth_stage=log.AUTH_SECONDARY,
                              status=log.AUTH_REJECT,
                              client_ip=request.client_ip,
                              server_section=self.server_section_name,
                              server_section_ikey=self.server_section_ikey)

        defer.returnValue(auth_res)

    @defer.inlineCallbacks
    def duo_auth(self, request, primary_res, factor, radius_reject_attrs=None):
        """
        Do preauth before calling or unenrolled users aren't handled!
        """
        auth_res = yield self.duo_auth_only(request, factor)
        msg = auth_res['status']

        self.log_request(request, 'Duo authentication returned \'%s\': \'%s\''
                         % (auth_res['result'], msg))
        if auth_res['result'] == duo_async.API_RESULT_ALLOW:
            defer.returnValue(self.create_accept_packet(
                request,
                msg,
                primary_res.radius_attrs,
            ))
        else:
            if radius_reject_attrs is None:
                radius_reject_attrs = {}
            defer.returnValue(self.create_reject_packet(request, msg, radius_attrs=radius_reject_attrs))
