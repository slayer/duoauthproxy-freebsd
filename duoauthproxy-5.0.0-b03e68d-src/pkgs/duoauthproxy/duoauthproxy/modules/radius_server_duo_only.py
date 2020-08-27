#
# Copyright (c) 2013-2015 Duo Security
# All Rights Reserved
#

from pyrad import packet
from twisted.internet import defer

from ..lib import base, duo_async, log
from ..lib.base import ServerModule
from ..lib.radius.duo_server import DuoSimpleRadiusServer
from ..lib.radius.server import (
    parse_client_ip_attribute,
    parse_exempt_usernames,
    parse_radius_secrets,
)


class DuoOnlyRadiusServer(DuoSimpleRadiusServer):
    def __init__(self, **kwargs):
        """Generic Duo RADIUS Duo-factor-only server

        Note: there is currently no support for self-enrollment here!"""
        super(DuoOnlyRadiusServer, self).__init__(**kwargs)

    @defer.inlineCallbacks
    def get_response(self, request):
        # Username required.
        if request.username is None:
            msg = "No username provided"
            self.log_request(request, msg)
            log.auth_standard(
                msg=msg,
                username=request.username,
                auth_stage=log.AUTH_SECONDARY,
                status=log.AUTH_ERROR,
                server_section=self.server_section_name,
                server_section_ikey=self.server_section_ikey,
                client_ip=request.client_ip,
            )
            defer.returnValue(self.create_reject_packet(request, msg))

        self.log_request(request, "login attempt for username %r" % request.username)

        # RADIUS password = Duo passcode or factor.
        try:
            factor = request.password
        except Exception:
            factor = None

        if not factor:
            msg = "Missing or improperly-formatted password"
            self.log_request(request, msg)
            log.auth_standard(
                msg=msg,
                username=request.username,
                auth_stage=log.AUTH_SECONDARY,
                status=log.AUTH_ERROR,
                server_section=self.server_section_name,
                server_section_ikey=self.server_section_ikey,
                client_ip=request.client_ip,
            )
            defer.returnValue(self.create_reject_packet(request, msg))

        # No primary_res; empty pass-through RADIUS attrs.
        primary_res = base.AuthResult(success=True, msg="Success. Logging you in...",)

        # perform duo auth with the rest of the password
        response_packet, preauth_res = yield self.preauth(request, primary_res)
        if response_packet is None:
            response_packet = yield self.duo_auth(request, primary_res, factor)
        # Return groups info on success
        if (
            preauth_res is not None
            and "groups" in preauth_res
            and len(preauth_res["groups"])
            and response_packet.code == packet.AccessAccept
        ):
            # Ensure the string is not unicode type when setting the attribute
            group_policy = preauth_res["groups"][0]
            class_value = "OU={0};".format(group_policy)
            response_packet["Class"] = class_value.encode()

        defer.returnValue(response_packet)


class Module(ServerModule):
    no_client = True

    def __init__(self, config, primary_client, server_section_name):
        log.msg("RADIUS Duo-Only Server Module Configuration:")
        log.config(
            config,
            lambda x: x.startswith("radius_secret") or x in ("skey", "skey_protected"),
        )

        self.protocol = DuoOnlyRadiusServer(
            secrets=parse_radius_secrets(config),
            primary_ator=primary_client,
            duo_client=self.make_duo_client(config),
            failmode=config.get_enum(
                "failmode",
                duo_async.FAILMODES,
                duo_async.FAILMODE_SAFE,
                transform=str.lower,
            ),
            exempt_usernames=parse_exempt_usernames(config),
            pass_through_attr_names=config.get_str("pass_through_attr_names", ""),
            pass_through_all=config.get_bool("pass_through_all", False),
            pw_codec=config.get_str("pw_codec", "utf-8"),
            client_ip_attr=parse_client_ip_attribute(config),
            server_section_name=server_section_name,
            server_section_ikey=config.get_str("ikey", ""),
        )
