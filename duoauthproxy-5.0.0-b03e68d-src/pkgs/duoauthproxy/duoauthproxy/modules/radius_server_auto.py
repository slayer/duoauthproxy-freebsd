#
# Copyright (c) 2012 Duo Security
# All Rights Reserved
#
from typing import Any, Dict

from pyrad import packet
from twisted.internet import defer

from ..lib import base, duo_async, log, util
from ..lib.base import AuthError, AuthResult, ServerModule
from ..lib.radius.base import MS_CHAP2_REQUEST_ATTRS
from ..lib.radius.challenge import ChallengeResponseRadiusServer
from ..lib.radius.duo_server import DuoSimpleRadiusServer
from ..lib.radius.server import (
    _ProxyRequest,
    parse_client_ip_attribute,
    parse_exempt_usernames,
    parse_radius_secrets,
)


class DuoAutoRadiusServer(ChallengeResponseRadiusServer, DuoSimpleRadiusServer):
    def __init__(
        self, factors, delim, delimited_password_length, allow_concat=True, **kwargs
    ):
        """
        Duo RADIUS server with secondary auth factor pre-selected by admin.

        factors: comma-separated list of factor names like "auto,push".

        delim: delimiter for concat-formatted passwords.

        allow_concat: If true, will try to split concat-formatted
        passwords containing delim. Otherwise, concat-mode will not be
        tried.

        Note: there is currently no support for self-enrollment here!
        """
        super(DuoAutoRadiusServer, self).__init__(**kwargs)
        self.factors = factors
        self.delim = delim
        self.delimited_password_length = delimited_password_length
        self.allow_concat = allow_concat

    @defer.inlineCallbacks
    def get_initial_response(self, request: _ProxyRequest):
        """
        Gets a response to the initial request from an appliance

        Returns:
            packet.Packet: The response to the request
        """
        # check username
        if request.username is None:
            msg = "No username provided"
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
            radius_attrs = {}
            if any(a in request for a in MS_CHAP2_REQUEST_ATTRS):
                radius_attrs = {"MS-CHAP-Error": self.MS_AUTH_FAILED_ERROR}
            defer.returnValue(
                self.create_reject_packet(request, msg, radius_attrs=radius_attrs)
            )

        self.log_request(request, "login attempt for username %r" % request.username)

        if "EAP-Message" in request.packet:
            # Proxy a challenge/response dialog until primary auth is complete
            response_packet = yield self.radius_proxy_challenge(request)
        elif "MS-CHAP2-CPW" in request:
            # Handle this case before other MS-CHAP2 cases.
            # If the packet wants to change the password, run duo_auth first
            # and then forward the RADIUS request to the RADIUS server.
            preauth_res = yield self.duo_preauth(request)
            if preauth_res["result"] == duo_async.API_RESULT_ALLOW:
                # Allow w/o 2fa
                primary_res = yield self.primary_auth(request, password=None)
                if primary_res.success:
                    response_packet = self.create_accept_packet(
                        request, radius_attrs=primary_res.radius_attrs
                    )
                else:
                    response_packet = self.create_reject_packet(
                        request, None, primary_res.radius_attrs
                    )
            elif preauth_res["result"] in (
                duo_async.API_RESULT_DENY,
                duo_async.API_RESULT_ENROLL,
            ):
                # Deny access
                radius_attrs = {"MS-CHAP-Error": self.MS_AUTH_FAILED_ERROR}
                response_packet = self.create_reject_packet(request, None, radius_attrs)
            elif preauth_res["result"] == duo_async.API_RESULT_AUTH:
                # 2FA before forwarding this packet, because it will change the user's password
                factor = util.factor_for_request(self.factors, preauth_res)
                if factor == "passcode":
                    msg = "Enter passcode:"
                    state = {"is_chap2": True, "cpw_req": request}
                    self.log_request(request, "Sending authentication challenge packet")
                    response_packet = self.create_challenge(request, msg, state)
                elif factor is None:
                    msg = "User has no Duo factors usable with this configuration"
                    self.log_request(request, msg)
                    log.auth_standard(
                        msg=msg,
                        username=request.username,
                        auth_stage=log.AUTH_SECONDARY,
                        status=log.AUTH_REJECT,
                        client_ip=request.client_ip,
                        server_section=self.server_section_name,
                        server_section_ikey=self.server_section_ikey,
                    )
                    radius_attrs = {"MS-CHAP-Error": self.MS_AUTH_FAILED_ERROR}
                    response_packet = self.create_reject_packet(
                        request, None, radius_attrs
                    )
                else:
                    auth_resp = yield self.duo_auth_only(request, factor)
                    if auth_resp["result"] == duo_async.API_RESULT_ALLOW:
                        # Primary auth, this will change the user's password if successful
                        primary_res = yield self.primary_auth(request, password=None)
                        if primary_res.success:
                            response_packet = self.create_accept_packet(
                                request, radius_attrs=primary_res.radius_attrs
                            )
                        else:
                            response_packet = self.create_reject_packet(
                                request, None, radius_attrs=primary_res.radius_attrs
                            )
                    else:
                        radius_attrs = {"MS-CHAP-Error": self.MS_AUTH_FAILED_ERROR}
                        msg = auth_resp["status"]
                        response_packet = self.create_reject_packet(
                            request, msg, radius_attrs=radius_attrs
                        )
        elif any(a in request for a in MS_CHAP2_REQUEST_ATTRS):
            # Proxy MS-CHAPv2 requests
            primary_res = yield self.primary_auth(request, None)
            if primary_res.success:
                radius_reject_attrs = {"MS-CHAP-Error": self.MS_AUTH_FAILED_ERROR}
                response_packet = yield self.duo_auth(
                    request,
                    primary_res,
                    factor=None,
                    radius_reject_attrs=radius_reject_attrs,
                )
            else:
                # Log if the MS-CHAPv2 primary failed and concat is enabled.
                if self.allow_concat:
                    log.msg(
                        "Allow concat is configured, but is not "
                        + "supported with MS-CHAPv2 authentications. "
                        + "Did you try to concatenate your second factor "
                        + "to your password?"
                    )

                # Look for change password
                if "MS-CHAP-Error" not in primary_res.radius_attrs:
                    primary_res.radius_attrs[
                        "MS-CHAP-Error"
                    ] = self.MS_AUTH_FAILED_ERROR
                else:
                    m = self.MS_ERRCODE_RE.match(
                        primary_res.radius_attrs["MS-CHAP-Error"][0]
                    )
                    if (
                        m is not None
                        and int(m.group("E")) == self.ERROR_PASSWORD_EXPIRED
                    ):
                        log.msg(
                            "{0} Rejected due to password expiration".format(
                                request.username
                            )
                        )
                        preauth_res = yield self.duo_preauth(request)
                        if preauth_res["result"] in (
                            duo_async.API_RESULT_DENY,
                            duo_async.API_RESULT_ENROLL,
                        ):
                            # The user is configured to DENY or ENROLL in DUO's service.
                            # Prevent the user from seeing the change password dialog in their client by
                            # changing the error to auth_failed.
                            primary_res.radius_attrs[
                                "MS-CHAP-Error"
                            ] = self.MS_AUTH_FAILED_ERROR

                response_packet = self.create_reject_packet(
                    request, primary_res.msg, radius_attrs=primary_res.radius_attrs
                )
        else:
            # This request has enough info to perform primary and Duo
            # auth. Do so.
            try:
                password = request.password
            except Exception:
                password = None
            if not password:
                # Either PAP but blank or un-decryptable. (Not PAP?
                # Wrong shared secret?). Not EAP, either, or
                # EAP-Message would've been found.
                msg = "Missing or improperly-formatted password"
                log.auth_standard(
                    msg=msg,
                    username=request.username,
                    auth_stage=log.AUTH_PRIMARY,
                    status=log.AUTH_ERROR,
                    client_ip=request.client_ip,
                    server_section=self.server_section_name,
                    server_section_ikey=self.server_section_ikey,
                )
                self.log_request(request, msg)
                defer.returnValue(self.create_reject_packet(request, msg))
            # Successfully decrypted password.
            if util.should_try_splitting_password(
                password, self.allow_concat, self.delim, self.delimited_password_length
            ):
                # User may specify passcode or factor with concat.
                # Speculatively split the password. If primary auth
                # succeeds, it was concat.
                #
                # Could reduce false-positives by checking if the part
                # after the last delim actually looks like a factor.
                # However, the general case is difficult because of
                # e.g. ModHex passcodes.
                password_part, factor = util.do_password_split(
                    password, self.delim, self.delimited_password_length
                )
                if not factor:
                    factor = None
                primary_res = yield self.primary_auth(request, password_part)
            else:
                primary_res = None
                factor = None
            if not (primary_res and primary_res.success):
                # (Re)try primary auth with the whole password if:
                # * allow_concat is False.
                # * No delim for concat.
                # * Delim found, but primary auth failed indicating it
                #   was not really concat.
                # * Concat was intended but the primary auth password
                #   part was wrong. If so, this will fail, too.
                primary_res = yield self.primary_auth(request, password)
                factor = None
            if primary_res.success:
                response_packet = yield self.duo_auth(
                    request, primary_res, factor=factor
                )
            else:
                response_packet = self.create_reject_packet(request, primary_res.msg)
        defer.returnValue(response_packet)

    @defer.inlineCallbacks
    def radius_proxy_challenge(self, request: _ProxyRequest):
        """
        Send request to the RADIUS server and get the result.

        Returns:
            packet.Packet: The response to the proxied request
        """
        #
        try:
            primary_res = yield self.primary_ator.radius_proxy(request)
        except NotImplementedError:
            self.log_request(request, base.RADIUS_PROXY_NOT_IMPLEMENTED_LOG_MSG)
            msg = base.RADIUS_PROXY_NOT_IMPLEMENTED_CLIENT_MSG
            log.auth_standard(
                msg=msg,
                username=request.username,
                auth_stage=log.AUTH_PRIMARY,
                status=log.AUTH_ERROR,
                client_ip=request.client_ip,
                server_section=self.server_section_name,
                server_section_ikey=self.server_section_ikey,
            )
            defer.returnValue(self.create_reject_packet(request, msg))
        except (AuthError, packet.PacketError) as e:
            msg = "Error performing primary authentication: %s" % e
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
            defer.returnValue(self.create_reject_packet(request, msg))

        if primary_res.response.code == packet.AccessReject:
            res_msg = "Primary credentials rejected - {0}".format(primary_res.msg)
            log.auth_standard(
                msg=res_msg,
                username=request.username,
                auth_stage=log.AUTH_PRIMARY,
                status=log.AUTH_REJECT,
                client_ip=request.client_ip,
                server_section=self.server_section_name,
                server_section_ikey=self.server_section_ikey,
            )
            self.log_request(request, res_msg)
            response_packet = primary_res.response
        elif primary_res.response.code == packet.AccessAccept:
            log.auth_standard(
                msg="Primary authentication successful - {0}".format(primary_res.msg),
                username=request.username,
                auth_stage=log.AUTH_PRIMARY,
                status=log.AUTH_ALLOW,
                client_ip=request.client_ip,
                server_section=self.server_section_name,
                server_section_ikey=self.server_section_ikey,
            )
            response_packet = yield self.duo_auth(request, primary_res)
        elif (
            primary_res.response.code == packet.AccessChallenge
            and "State" in primary_res.response
        ):
            # Proxy the challenge back.
            self.store_challenge_state(
                request, primary_res.response["State"][0], state=None,
            )
            response_packet = primary_res.response
        else:
            self.log_request(
                request,
                "Response packet is not Access-Accept, Access-Reject,"
                " or Access-Challenge (code %s)" % primary_res.response.code,
            )
            msg = "Unexpected packet in primary authentication"
            log.auth_standard(
                msg=msg,
                username=request.username,
                auth_stage=log.AUTH_PRIMARY,
                status=log.AUTH_ERROR,
                client_ip=request.client_ip,
                server_section=self.server_section_name,
                server_section_ikey=self.server_section_ikey,
            )
            response_packet = self.create_reject_packet(request, msg)

        defer.returnValue(response_packet)

    @defer.inlineCallbacks
    def get_challenge_response(self, request: _ProxyRequest, state: Dict[str, Any]):
        """
        Gets a challenge response for the given request

        Returns:
            packet.Packet: The challenge response

        """
        if state is None:
            # response for proxied challenge
            response_packet = yield self.radius_proxy_challenge(request)
        else:
            radius_reject_attrs = {}
            if state.get("is_chap2", False):
                radius_reject_attrs = {"MS-CHAP-Error": self.MS_AUTH_FAILED_ERROR}
            response_packet = yield self.get_passcode_challenge_response(
                request, state, radius_reject_attrs=radius_reject_attrs
            )
        defer.returnValue(response_packet)

    @defer.inlineCallbacks
    def duo_auth(
        self,
        request: _ProxyRequest,
        primary_res: AuthResult,
        factor: str = None,
        preauth_res: Dict[str, Any] = None,
        radius_reject_attrs: Dict[str, Any] = None,
    ):
        """
        Does a second-factor authentication against Duo

        Returns:
            packet.Packet: A response packet to send back to the appliance
        """

        if radius_reject_attrs is None:
            radius_reject_attrs = {}

        if not preauth_res:
            # Must call preauth even if the factor is known.
            response_packet, preauth_res = yield self.preauth(
                request, primary_res, radius_reject_attrs
            )
            if response_packet is not None:
                # E.g. enroll policy of deny or allow.
                defer.returnValue(response_packet)
        if factor is None:
            factor = util.factor_for_request(self.factors, preauth_res)
            if factor == "passcode" and "EAP-Message" not in request.packet:
                # Not a factor for the Duo auth API until the passcode
                # value is entered. Send passcode challenge.
                #
                # Sending a passcode prompt Access-Challenge is
                # mutually exclusive with EAP passthrough. Most EAP
                # clients ignore challenges without EAP-Message
                # attributes, and the tunneled EAP-Messages contain
                # their own Accept and Reject attributes which
                # override whatever code is on the outer RADIUS
                # packet.
                msg = "Enter passcode:"
                state = {
                    "primary_res": primary_res,
                    "is_chap2": bool(radius_reject_attrs),
                    "cpw_req": request,
                }
                challenge_packet = self.create_challenge(request, msg, state)
                self.log_request(request, "Sending authentication challenge packet")
                defer.returnValue(challenge_packet)

            if factor is None:
                msg = "User has no Duo factors usable with this configuration"
                log.auth_standard(
                    msg=msg,
                    username=request.username,
                    auth_stage=log.AUTH_SECONDARY,
                    status=log.AUTH_REJECT,
                    client_ip=request.client_ip,
                    server_section=self.server_section_name,
                    server_section_ikey=self.server_section_ikey,
                )
                self.log_request(request, msg)
                defer.returnValue(self.create_reject_packet(request, msg))

        # Factor was either passed in or found above auto-push if this
        # is reached without returning.
        response_packet = yield super(DuoAutoRadiusServer, self).duo_auth(
            request, primary_res, factor, radius_reject_attrs=radius_reject_attrs
        )
        defer.returnValue(response_packet)

    @defer.inlineCallbacks
    def get_passcode_challenge_response(
        self,
        request: _ProxyRequest,
        state: Dict[str, Any],
        radius_reject_attrs: Dict[str, Any] = None,
    ):
        """
        Gets the response to the challenge for a second-factor passcode

        Returns:
            packet.Packet
        """

        if radius_reject_attrs is None:
            radius_reject_attrs = {}
        try:
            passcode = request.password
        except Exception:
            passcode = None
        if passcode:
            if state.get("is_chap2", False) and "cpw_req" in state:
                cpw_request = state["cpw_req"]
                # In the change password case, we send the RADIUS packet after the 2fa
                auth_resp = yield self.duo_auth_only(cpw_request, passcode)
                if auth_resp["result"] == duo_async.API_RESULT_ALLOW:
                    # Primary auth will change the user's password if successful
                    primary_res = yield self.primary_auth(cpw_request, password=None)
                    if primary_res.success:
                        response_packet = self.create_accept_packet(
                            request, radius_attrs=primary_res.radius_attrs
                        )
                    else:
                        response_packet = self.create_reject_packet(
                            request, None, radius_attrs=primary_res.radius_attrs
                        )
                else:
                    radius_attrs = {"MS-CHAP-Error": self.MS_AUTH_FAILED_ERROR}
                    msg = auth_resp["status"]
                    response_packet = self.create_reject_packet(
                        request, msg, radius_attrs=radius_attrs
                    )
            else:
                response_packet = yield self.duo_auth(
                    request,
                    state["primary_res"],
                    passcode,
                    radius_reject_attrs=radius_reject_attrs,
                )
        else:
            self.log_request(request, base.NOT_PAP_PASSWORD_CLIENT_MSG)
            msg = "Missing or improperly-formatted password"
            log.auth_standard(
                msg=msg,
                username=request.username,
                auth_stage=log.AUTH_SECONDARY,
                status=log.AUTH_ERROR,
                client_ip=request.client_ip,
                server_section=self.server_section_name,
                server_section_ikey=self.server_section_ikey,
            )
            response_packet = self.create_reject_packet(
                request, msg, radius_attrs=radius_reject_attrs
            )
        defer.returnValue(response_packet)


class Module(ServerModule):
    def __init__(self, config, primary_ator, server_section_name):
        log.msg("RADIUS Automatic Factor Server Module Configuration:")
        log.config(
            config,
            lambda x: x.startswith("radius_secret") or x in ("skey", "skey_protected"),
        )

        self.protocol = DuoAutoRadiusServer(
            secrets=parse_radius_secrets(config),
            primary_ator=primary_ator,
            duo_client=self.make_duo_client(config),
            failmode=config.get_enum(
                "failmode",
                duo_async.FAILMODES,
                duo_async.FAILMODE_SAFE,
                transform=str.lower,
            ),
            factors=util.parse_factor_list(config.get_str("factors", "auto")),
            delim=config.get_str("delimiter", ","),
            delimited_password_length=config.get_int("delimited_password_length", 0),
            allow_concat=config.get_bool("allow_concat", True),
            exempt_usernames=parse_exempt_usernames(config),
            debug=config.get_bool("debug", False),
            pass_through_attr_names=config.get_str("pass_through_attr_names", ""),
            pass_through_all=config.get_bool("pass_through_all", False),
            pw_codec=config.get_str("pw_codec", "utf-8"),
            client_ip_attr=parse_client_ip_attribute(config),
            server_section_name=server_section_name,
            server_section_ikey=config.get_str("ikey", ""),
        )
