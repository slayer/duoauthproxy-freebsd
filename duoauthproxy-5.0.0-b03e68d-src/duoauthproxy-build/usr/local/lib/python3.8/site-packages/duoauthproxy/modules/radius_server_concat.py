#
# Copyright (c) 2011 Duo Security
# All Rights Reserved
#

from twisted.internet import defer

from ..lib import base, duo_async, log, util
from ..lib.base import ServerModule
from ..lib.radius.duo_server import DuoSimpleRadiusServer
from ..lib.radius.server import (
    parse_client_ip_attribute,
    parse_exempt_usernames,
    parse_radius_secrets,
)


class DuoConcatRadiusServer(DuoSimpleRadiusServer):
    def __init__(self, delim, delimited_password_length, **kwargs):
        """Generic Duo RADIUS password-concatenation server

        delim: delimiter character (string) to separate the user's password
            from the Duo passcode / factor name. It MUST be a character/string
            that will NEVER appear in a Duo passcode or factor name!

        Note: there is currently no support for self-enrollment here!"""

        super(DuoConcatRadiusServer, self).__init__(**kwargs)
        self.delim = delim
        self.delimited_password_length = delimited_password_length

    def split_password(self, request):
        password = request.password
        if not password:
            self.log_request(request, base.NOT_PAP_PASSWORD_CLIENT_MSG)
            raise ValueError("No password provided")
        components = util.do_password_split(
            password, self.delim, self.delimited_password_length
        )
        if len(components) != 2 or not all(components):
            raise ValueError("Invalid Password")
        return components

    @defer.inlineCallbacks
    def get_response(self, request):
        # check username
        if request.username is None:
            msg = "No username provided"
            self.log_request(request, msg)
            log.auth_standard(
                msg=msg,
                username=request.username,
                auth_stage=log.AUTH_UNKNOWN,
                status=log.AUTH_ERROR,
                client_ip=request.client_ip,
                server_section=self.server_section_name,
                server_section_ikey=self.server_section_ikey,
            )
            defer.returnValue(self.create_reject_packet(request, msg))

        self.log_request(request, "login attempt for username %r" % request.username)

        # split password
        try:
            password, factor = self.split_password(request)
        except ValueError as e:
            msg = "Missing or improperly-formatted password - {0}".format(str(e))
            self.log_request(request, msg)
            log.auth_standard(
                msg=msg,
                username=request.username,
                auth_stage=log.AUTH_PRIMARY,
                status=log.AUTH_ERROR,
                client_ip=request.client_ip,
                server_section=self.server_section_name,
                server_section_ikey=self.server_section_ikey,
            )
            defer.returnValue(self.create_reject_packet(request, str(e)))

        # perform primary authentication with the first piece of the password
        # auth_standard logging is done on success/fail in self.primary_auth()
        primary_res = yield self.primary_auth(request, password)
        if not primary_res.success:
            defer.returnValue(self.create_reject_packet(request, primary_res.msg))

        # perform duo auth with the rest of the password
        response_packet, preauth_res = yield self.preauth(request, primary_res)
        if response_packet is None:
            response_packet = yield self.duo_auth(request, primary_res, factor)
        defer.returnValue(response_packet)


class Module(ServerModule):
    def __init__(self, config, primary_client, server_section_name):
        log.msg("RADIUS Concat Server Module Configuration:")
        log.config(
            config,
            lambda x: x.startswith("radius_secret") or x in ("skey", "skey_protected"),
        )

        delim = config.get_str(
            "delimiter",
            # Fall back to alternate spelling.
            config.get_str("delimeter", ","),
        )

        self.protocol = DuoConcatRadiusServer(
            secrets=parse_radius_secrets(config),
            primary_ator=primary_client,
            duo_client=self.make_duo_client(config),
            failmode=config.get_enum(
                "failmode",
                duo_async.FAILMODES,
                duo_async.FAILMODE_SAFE,
                transform=str.lower,
            ),
            delim=delim,
            delimited_password_length=config.get_int("delimited_password_length", 0),
            exempt_usernames=parse_exempt_usernames(config),
            pass_through_attr_names=config.get_str("pass_through_attr_names", ""),
            pass_through_all=config.get_bool("pass_through_all", False),
            pw_codec=config.get_str("pw_codec", "utf-8"),
            client_ip_attr=parse_client_ip_attribute(config),
            server_section_name=server_section_name,
            server_section_ikey=config.get_str("ikey", ""),
        )
