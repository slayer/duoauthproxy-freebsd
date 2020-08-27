#
# Copyright (c) 2011 Duo Security
# All Rights Reserved
#

import urllib.parse

from twisted.internet import defer

from duoauthproxy.lib.radius.api_error_handling import ApiErrorHandling
from duoauthproxy.lib.radius.challenge import ChallengeResponseRadiusServer
from duoauthproxy.lib.radius.server import parse_radius_secrets
from duoauthproxy.lib.radius.server import parse_exempt_usernames
from duoauthproxy.lib.radius.server import parse_client_ip_attribute
from duoauthproxy.lib import log
from duoauthproxy.lib import duo_async
from duoauthproxy.lib.base import ServerModule


# known device types from which we can select
JS_TYPE_ARRAY = 'array'
JS_TYPE_BARRACUDA = 'barracuda'
JS_TYPE_CITRIX = 'citrix'
JS_TYPE_CITRIXNS = 'citrix_netscaler'
JS_TYPE_CITRIXNS_RFWEBUI = 'citrix_netscaler_rfwebui'
JS_TYPE_F5 = 'f5'
JS_TYPE_F5_BIGIP = 'f5_bigip'
JS_TYPE_FORTINET = 'fortinet'
JS_TYPE_JUNIPER = 'juniper'
JS_TYPE_PALOALTO = 'paloalto'
JS_TYPE_SONICWALLSRA = 'sonicwall_sra'

JS_TYPES = [
    JS_TYPE_ARRAY,
    JS_TYPE_BARRACUDA,
    JS_TYPE_CITRIX,
    JS_TYPE_CITRIXNS,
    JS_TYPE_CITRIXNS_RFWEBUI,
    JS_TYPE_F5,
    JS_TYPE_F5_BIGIP,
    JS_TYPE_FORTINET,
    JS_TYPE_JUNIPER,
    JS_TYPE_PALOALTO,
    JS_TYPE_SONICWALLSRA,
]

SCRIPT_FILES = {
    JS_TYPE_ARRAY: 'Duo-Array-v1.js',
    JS_TYPE_BARRACUDA: 'Duo-Barracuda-v1.js',
    JS_TYPE_CITRIX: 'Duo-Citrix-v1.js',
    JS_TYPE_CITRIXNS: 'Duo-Citrix-NetScaler-v1.js',
    JS_TYPE_CITRIXNS_RFWEBUI: 'Duo-Citrix-NetScaler-RfWebUI-v1.js',
    JS_TYPE_F5: '',  # we don't inject a script link for f5
    JS_TYPE_F5_BIGIP: '',  # we don't inject a script link for f5_bigip
    JS_TYPE_FORTINET: 'Duo-Fortinet-v1.js',
    JS_TYPE_JUNIPER: 'Duo-Juniper-v1.js',
    JS_TYPE_PALOALTO: 'Duo-PA-v1.js',
    JS_TYPE_SONICWALLSRA: ''  # we don't inject a script link for sonicwallsra
}

SCRIPT_INJECT = {
    JS_TYPE_ARRAY:
        ("<script src='%(script_uri)s'></script>"
         "<script>"
         "Duo_Init('%(proxy_txid)s', '%(api_host)s');"
         "</script>"),

    JS_TYPE_BARRACUDA:
        ("<script src='%(script_uri)s'></script>"
         "<script>"
         "Duo_Init('%(proxy_txid)s', '%(api_host)s');"
         "</script>"),

    JS_TYPE_CITRIX:
        ("<iframe src=\"https://%(api_host)s/frame\" height=\"0\" "
         "onload=\"var d=document,s=d.createElement('script');"
         "s.src='%(script_uri)s#%(proxy_txid)s';"
         "d.body.appendChild(s);\"></iframe>"),

    JS_TYPE_CITRIXNS:
        ("<script src='%(script_uri)s'></script>"
         "<script>"
         "Duo_Init('%(proxy_txid)s', '%(api_host)s');"
         "</script>"),

    JS_TYPE_CITRIXNS_RFWEBUI:
        ("<script id=\"duo_netscaler_rfwebui_js\" data-txid=\"%(proxy_txid)s\" data-host=\"%(api_host)s\" "
         "src=\"%(script_uri)s\" />"),

    JS_TYPE_F5:
        ("Initializing two-factor authentication... "
         "DUO-TXID(%(api_host)s|%(proxy_txid)s|%(state)s)"),

    JS_TYPE_F5_BIGIP:
        ("Initializing two-factor authentication... "
         "DUO-TXID(%(api_host)s|%(proxy_txid)s)"),

    JS_TYPE_FORTINET:
        ("<iframe src=\"https://%(api_host)s/frame\" height=\"0\" "
         "onload=\"var d=document,s=d.createElement('script');"
         "s.src='%(script_uri)s#%(proxy_txid)s';"
         "d.body.appendChild(s);\"></iframe>"),

    JS_TYPE_JUNIPER:
        ("<script src='%(script_uri)s'></script>"
         "<script>"
         "Duo_Init('%(proxy_txid)s', '%(api_host)s');"
         "</script>"),

    JS_TYPE_PALOALTO:
        ("\";var d=document,s=d.createElement('script');"
         "s.src='%(script_uri)s#Duo-PA-v1&%(proxy_txid)s&%(api_host)s';"
         "d.body.appendChild(s);"
         "var b=\""),

    JS_TYPE_SONICWALLSRA:
        ("<script>Duo_Init(\"%(proxy_txid)s\", \"%(api_host)s\");"
         "</script>"),
}

F5_STATE_DELIM = '-----DUO STATE-----'


class DuoIFrameRadiusServer(ChallengeResponseRadiusServer, ApiErrorHandling):

    def __init__(self, type, script_uri, script_inject, failmode,
                 duo_client,
                 **kwargs):
        super(DuoIFrameRadiusServer, self).__init__(**kwargs)

        self.client = duo_client
        self.type = type
        self.script_uri = script_uri
        self.script_inject = script_inject
        self.failmode = failmode

    def _find_challenge(self, request):
        """F5 Firepass devices violate the RADIUS spec, and fail to
        return the 'State' RADIUS attribute when sending responses to
        AccessChallenge packets.

        We work around this by transmitting the 'State' contents as
        part of the 'Reply-Message'. The Duo-F5 Javascript reads out
        the 'State' when parsing the reply message, and later
        concatenates it to the authcookie."""

        if self.type != JS_TYPE_F5:
            # standard challenge-response behavior for non-F5
            return ChallengeResponseRadiusServer._find_challenge(
                self, request)

        password = request.password
        if password.find(F5_STATE_DELIM) == -1:
            return None

        # we'll be conservative here, and return None at validation
        # failure, rather than raising an exception, in case some user
        # has a crazy password that collides with our stuff. but this
        # should basically never happen.
        split_pass = password.split(F5_STATE_DELIM)
        if len(split_pass) != 2:
            return None

        (authcookie, state) = split_pass
        if state in self.challenges:
            return self.challenges[state]

        return None

    def _get_authcookie(self, request):
        if self.type != JS_TYPE_F5:
            return request.password

        password = request.password
        return password.split(F5_STATE_DELIM)[0]

    @defer.inlineCallbacks
    def get_initial_response(self, request):
        # make sure username, password were provided
        if request.username is None:
            msg = 'No username provided'
            self.log_request(request, msg)
            log.auth_standard(msg=msg,
                              username=request.username,
                              auth_stage="Unknown",
                              status=log.AUTH_ERROR,
                              server_section=self.server_section_name,
                              server_section_ikey=self.server_section_ikey,
                              client_ip=request.client_ip)
            defer.returnValue(self.create_reject_packet(request, msg))

        self.log_request(request, 'login attempt for username %r'
                         % request.username)

        if request.password is None:
            self.log_request(request,
                             'Only the PAP with a Shared Secret format is'
                             ' supported. Is the system communicating with'
                             ' the Authentication Proxy using CHAP or'
                             ' MSCHAPv2 instead?')
            msg = 'No password provided'
            self.log_request(request, msg)
            log.auth_standard(msg=msg,
                              username=request.username,
                              auth_stage=log.AUTH_PRIMARY,
                              status=log.AUTH_ERROR,
                              server_section=self.server_section_name,
                              server_section_ikey=self.server_section_ikey,
                              client_ip=request.client_ip)
            defer.returnValue(self.create_reject_packet(request, msg))

        # perform primary authentication
        primary_res = yield self.primary_auth(request, request.password)
        if not primary_res.success:
            defer.returnValue(self.create_reject_packet(request,
                                                        primary_res.msg))

        if request.username in self.exempt_usernames:
            msg = 'User exempted from 2FA'
            log.auth_standard(msg=msg,
                              username=request.username,
                              auth_stage=log.AUTH_SECONDARY,
                              status=log.AUTH_ALLOW,
                              server_section=self.server_section_name,
                              server_section_ikey=self.server_section_ikey,
                              client_ip=request.client_ip)
            defer.returnValue(self.create_accept_packet(request, msg, radius_attrs=primary_res.radius_attrs))

        # get a txid from duo service
        try:
            init_res = yield self.client.proxy_init(request.username)
        except duo_async.DuoAPIError as e:
            log.err(None, 'Duo proxy_init call failed')
            response_packet = self.response_for_api_error(
                request,
                primary_res,
                e,
                primary_res.radius_attrs,
            )
            defer.returnValue(response_packet)

        # Note: MUST NOT YIELD between calling _create_challenge_id
        # and calling create_challenge()
        challenge_id = self._create_challenge_id()

        # build script injection with the txid
        params = {
            'script_uri': self.script_uri,
            'proxy_txid': init_res['proxy_txid'],
            'api_host': self.client.host,
            'state': challenge_id
        }
        challenge_msg = self.script_inject % params
        if len(challenge_msg) > 253:
            raise ValueError(
                'response string is %d chars long, but cannot exceed 253 '
                'chars. If you specified a custom iframe_script_uri, you '
                'may need to shorten it by at least %d chars'
                % (len(challenge_msg), len(challenge_msg) - 253))

        self.log_request(request, 'Sending authentication challenge packet')
        state = {
            'primary_res': primary_res,
        }
        challenge_packet = self.create_challenge(request, challenge_msg,
                                                 state=state,
                                                 challenge_id=challenge_id)
        defer.returnValue(challenge_packet)

    @defer.inlineCallbacks
    def get_challenge_response(self, request, state):
        # Do not have access to factor - request.password is users cookie
        success = False
        self.log_request(request, 'Challenge Response: %r' % request.password)

        if state and 'primary_res' in state:
            radius_attrs = state['primary_res'].radius_attrs
        else:
            radius_attrs = {}

        auth_cookie = urllib.parse.unquote(self._get_authcookie(request))
        try:
            finish_res = yield self.client.proxy_finish(auth_cookie)
        except duo_async.DuoAPIError as e:
            log.err(None, 'Duo proxy_finish call failed')
            response_packet = self.response_for_api_error(
                request,
                state['primary_res'],
                e,
                state['primary_res'].radius_attrs,
            )
            defer.returnValue(response_packet)

        self.log_request(request, 'Authcookie validation result: %r'
                         % finish_res)
        if (finish_res['valid_cookie'] and
                (finish_res['user'] == request.username)):
            success = True

        if success:
            log.auth_standard(msg='Valid login from iframe',
                              username=request.username,
                              auth_stage=log.AUTH_SECONDARY,
                              status=log.AUTH_ALLOW,
                              server_section=self.server_section_name,
                              server_section_ikey=self.server_section_ikey,
                              client_ip=request.client_ip)
            defer.returnValue(self.create_accept_packet(
                request,
                radius_attrs=radius_attrs,
            ))
        else:
            log.auth_standard(msg='Invalid login from iframe',
                              username=request.username,
                              auth_stage=log.AUTH_SECONDARY,
                              status=log.AUTH_REJECT,
                              server_section=self.server_section_name,
                              server_section_ikey=self.server_section_ikey,
                              client_ip=request.client_ip)
            defer.returnValue(self.create_reject_packet(request))


class Module(ServerModule):
    def __init__(self, config, primary_client, server_section_name):
        log.msg('RADIUS IFrame Server Module Configuration:')
        log.config(
            config, lambda x: x.startswith('radius_secret') or
            x in ('skey', 'skey_protected'))

        failmode = config.get_enum('failmode', duo_async.FAILMODES,
                                   duo_async.FAILMODE_SAFE,
                                   transform=str.lower)
        secrets = parse_radius_secrets(config)
        type = config.get_enum('type', JS_TYPES)

        if type != JS_TYPE_CITRIX:
            api_timeout = 15
        else:
            # citrix devices don't retransmit correctly,
            # and can't do timeouts > 10 seconds
            api_timeout = 8
        duo_client = self.make_duo_client(config, default_timeout=api_timeout)

        # script injection snippet, js file
        script_file_default = SCRIPT_FILES[type]
        if duo_client.port == 443:
            script_uri_default = ('https://%s/frame/hosted/%s'
                                  % (duo_client.host, script_file_default))
        else:
            script_uri_default = ('https://%s:%d/frame/hosted/%s'
                                  % (duo_client.host,
                                     duo_client.port,
                                     script_file_default))
        script_uri = config.get_str('iframe_script_uri', script_uri_default)
        script_inject_default = SCRIPT_INJECT[type]
        script_inject = config.get_str('script_inject', script_inject_default)

        self.protocol = DuoIFrameRadiusServer(
            type, script_uri, script_inject, failmode,
            duo_client=duo_client,
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
