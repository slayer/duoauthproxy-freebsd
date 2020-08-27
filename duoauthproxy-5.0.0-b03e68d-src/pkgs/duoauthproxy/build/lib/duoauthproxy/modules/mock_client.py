#
# Copyright (c) 2011 Duo Security
# All Rights Reserved
#

import copy
from typing import Any, Dict

from pyrad import packet
from twisted.internet import defer

from duoauthproxy.lib import mppe
from duoauthproxy.lib.radius import base
from duoauthproxy.lib.radius.base import MS_CHAP2_RESPONSE_ATTRS, add_packet_attributes
from duoauthproxy.lib.radius.client import _IdentifierList

from ..lib import log
from ..lib.base import AuthResult, ClientModule


class Module(ClientModule):
    def __init__(self, config):
        log.msg("Mock Client Module Configuration:")
        log.config(config, lambda x: x == "password")
        self.username = config.get_str("username")
        self.password = config.get_str("password")
        self.id_list = _IdentifierList()
        self.secret = config.get("secret", "")

        # Read in CHAP2 values which, if sent, are returned as SUCCESS
        self.chap_challenge = config.get_str("chap_challenge", "")
        self.chap2_response = config.get_str("chap2_response", "")

        # CHAP2 value which, if seen in MS-CHAP2-Response, generates
        # a REJECT / Password Expired result
        self.chap2_response_expired = config.get_str("chap2_expired", "")

        # CHAP2 Change Password attribute value that will generate
        # Access Accept, all other values generate Access Reject
        self.chap2_cpw = config.get_str("chap2_cpw", "")

        # MPPE Keys are added if the request is an MS-CHAPv2 request
        self.ms_mppe_send_key = config.get("mppe_send_key", b"testsendkey")
        self.ms_mppe_recv_key = config.get("mppe_recv_key", b"testrecvkey")

        self.pass_through_radius_attrs = {}

    @defer.inlineCallbacks
    def authenticate(self, username, password, client_ip, radius_attrs=None):
        if radius_attrs is None:
            radius_attrs = {}
        success = False
        if username == self.username:
            if password is not None and password == self.password:
                success = True
            elif radius_attrs.get("MS-CHAP-Challenge") == [
                self.chap_challenge.encode()
            ] and radius_attrs.get("MS-CHAP2-Response") == [
                self.chap2_response.encode()
            ]:
                success = True
            elif "MS-CHAP2-CPW" in radius_attrs and radius_attrs.get(
                "MS-CHAP2-CPW"
            ) == [self.chap2_cpw.encode()]:
                success = True

        # Create a fake request
        request_packet = yield self._create_request(radius_attrs)
        # Create an auth_result response based on the fake request
        auth_result = self._create_reply(request_packet, success)
        return auth_result

    @defer.inlineCallbacks
    def _create_request(self, radius_attrs: Dict[str, Any]):
        """
        Creates a fake request packet used to generate a fake response

        Args:
            radius_attrs: The attributes to add to the created request

        Returns:
            packet.AuthPacket
        """
        request_id = yield self.id_list.request()
        request_packet = packet.AuthPacket(
            code=packet.AccessRequest,
            id=request_id,
            secret=self.secret.encode(),
            dict=base.radius_dictionary(),
        )
        add_packet_attributes(packet=request_packet, attrs=radius_attrs)

        # Turn the request packet into bytes for the wire even though we're not
        # sending it anywhere because that's when the authenticator gets
        # generated and set
        request_packet.RequestPacket()

        defer.returnValue(request_packet)

    def _create_reply(
        self, request_packet: packet.AuthPacket, success: bool
    ) -> AuthResult:
        """
        Creates an AuthResult as a reply the given request_packet
        Args:
            request_packet: The request to create a reply to
            success: True if the reply should have code AccessAccept, false for AccessReject
        """
        pass_through_attrs = copy.copy(self.pass_through_radius_attrs)

        reply = request_packet.CreateReply()
        reply.code = packet.AccessAccept if success else packet.AccessReject
        reply.authenticator = request_packet.authenticator
        reply.AddAttribute("Reply-Message", "Hello")

        # If it's an MS-CHAPv2 request, add the MS-MPPE-Send-Key and MS-MPPE-Recv-Key
        if (
            "MS-CHAP-Challenge" in request_packet
            or "MS-CHAP2-Response" in request_packet
        ):
            mppe.add_mppe(
                reply,
                self.ms_mppe_send_key,
                self.ms_mppe_recv_key,
                self.secret.encode(),
                request_packet.authenticator,
            )

        # Include error info in response, if it's MS-CHAP2 and an error
        if not success and self.chap_challenge:
            pass_through_attrs["MS-CHAP-Error"] = [b"\x00E=691 R=0 V=3"]
        if request_packet.get("MS-CHAP2-Response") == [
            self.chap2_response_expired.encode()
        ]:
            pass_through_attrs["MS-CHAP-Error"] = [b"\x00E=648 R=0 V=3"]

        add_packet_attributes(reply, pass_through_attrs)

        # Wrap the reply in an AuthResult
        pass_through_attr_names = (
            list(pass_through_attrs.keys()) + MS_CHAP2_RESPONSE_ATTRS
        )
        auth_result = AuthResult.from_radius_packet(reply, pass_through_attr_names)

        return auth_result
