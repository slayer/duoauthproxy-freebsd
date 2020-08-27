#
# Copyright (c) 2011 Duo Security
# All Rights Reserved
#

from __future__ import annotations

from typing import Any, Dict, Iterable, NamedTuple, Optional

import twisted.internet.error
from pyrad import packet
from twisted.application.service import Service
from twisted.internet import defer, reactor

from duoauthproxy.lib import mppe
from duoauthproxy.lib.duo_creds import DuoCreds
from duoauthproxy.lib.radius.base import MS_MPPE_KEY_ATTRS

from . import duo_async

RADIUS_PROXY_NOT_IMPLEMENTED_LOG_MSG = (
    "Cannot proxy RADIUS requests to this primary authenticator. Try using"
    " PAP on the system communicating with the Authentication Proxy."
)

RADIUS_PROXY_NOT_IMPLEMENTED_CLIENT_MSG = (
    "A client which cannot proxy radius requests has been configured.  "
    "Check the proxy configuration"
)

NOT_PAP_PASSWORD_CLIENT_MSG = (
    "Only the PAP with Shared Secret format is"
    " supported. Is the system communicating with"
    " the Authentication Proxy using CHAP or EAP instead?"
)

NO_REPLY_MESSAGE = "No reply message in packet"


class ClientModule(Service):
    def __init__(self, config):
        raise NotImplementedError()

    @defer.inlineCallbacks
    def authenticate(self, username, password, client_ip, pass_through_attrs):
        raise NotImplementedError()

    @defer.inlineCallbacks
    def radius_proxy(self, request):
        raise NotImplementedError()

    @defer.inlineCallbacks
    def ldap_proxy(self):
        """
        Return a connected _ADClientProtocol instance.
        """
        raise NotImplementedError()


class ServerModule(Service, object):
    # If a subclass does not require a primary authentication client,
    # override no_client with True. Otherwise, a config without one
    # will produce an error.
    no_client = False

    def __init__(self, config, primary_client, server_section_name):
        raise NotImplementedError()

    @staticmethod
    def make_duo_client(
        config, duo_creds=None, default_timeout=0, client_type=duo_async.AuthDuoClient
    ):
        if not duo_creds:
            duo_creds = DuoCreds(
                config.get_str("ikey"),
                config.get_protected_str("skey_protected", "skey").encode(),
            )

        return client_type(
            host=config.get_str("api_host", "api.duosecurity.com"),
            duo_creds=duo_creds,
            port=config.get_int("api_port", 443),
            # no explicit timeout, API calls may block on OOB factors,
            # so we need to tread very carefully here
            timeout_default=config.get_int("api_timeout", default_timeout),
        )


class AuthError(Exception):
    pass


# Private class that lets us get away with overriding __new__ for a NamedTuple
class _AuthResult(NamedTuple):
    success: bool
    msg: str
    radius_attrs: Dict[str, Any]
    response: Optional[packet.Packet]


class AuthResult(_AuthResult):
    @staticmethod
    def __new__(cls, success, msg, radius_attrs=None, response=None):
        if not radius_attrs:
            radius_attrs = {}
        return super(AuthResult, cls).__new__(cls, success, msg, radius_attrs, response)

    @staticmethod
    def from_radius_packet(
        response_packet: packet.AuthPacket, radius_attr_names: Iterable[str] = None
    ) -> AuthResult:
        """
        Builds an AuthResponse from an AuthPacket.

        Args:
            response_packet: The AuthPacket to create the AuthResponse from
            radius_attr_names: The names of attributes to be copied from response_packet
                to the AuthResult's radius_attrs.
        """
        try:
            msg = response_packet["Reply-Message"][0]
        except (KeyError, IndexError):
            msg = NO_REPLY_MESSAGE

        auth_result = AuthResult(
            success=(response_packet.code == packet.AccessAccept),
            msg=msg,
            response=response_packet,
        )

        if radius_attr_names:
            auth_result.copy_response_attrs_to_radius_attrs(radius_attr_names)

        return auth_result

    def copy_response_attrs_to_radius_attrs(self, attr_names: Iterable[str]):
        """Copies the specified attributes from the response packet to radius_attrs.
        If a value for a given attribute already exists, it will be overwritten"""

        # Do nothing if there's no response to copy values over from
        if not self.response:
            return

        for attr in attr_names:
            if attr in self.response:
                value = self.response[attr]

                # If the value is an encrypted MPPE send or recv key, decrypt
                # it so the server module can re-encrypt it later. The keys need
                # to be re-encrypted with the secret and authenticator shared
                # between the appliance and the auth proxy's RADIUS server section
                # so the appliance can decrypt them.
                if attr in MS_MPPE_KEY_ATTRS:
                    key_salt = value[0][:2]
                    encrypted_mppe_key = value[0][2:]
                    decrypted_key = mppe.decrypt_and_extract_mppe_key(
                        encrypted_mppe_key,
                        self.response.secret,
                        self.response.authenticator,
                        key_salt,
                    )
                    value = [decrypted_key]

                self.radius_attrs[attr] = value


class TimeoutException(Exception):
    """Exception type used by addTimeout"""

    pass


def addTimeout(deferred, timeout_secs, exc_params=("Timed Out",)):
    """Adds a timeout condition to a deferred instance. If, after
    timeout_secs has passed, the deferred has not been called
    (i.e. callback() or errback()), then call errback() on the
    deferred instance with a TimeoutException().

    If exc_params is provided, then its contents will be passed
    as *args to the TimeoutException constructor

    USE THIS WITH CAUTION! Most likely, you will need to clean up some
    state after something times out..."""

    # build the DelayedCall to perform the timeout operation
    def timeout_handler():
        if not deferred.called:
            deferred.errback(TimeoutException(*exc_params))

    timeout_dc = reactor.callLater(timeout_secs, timeout_handler)

    # attach a callback/errback handler to the chain, to clear the
    # timeout handler upon a successful callback (or errback) before
    # the timeout is triggered
    def clear_timeout(r):
        try:
            timeout_dc.cancel()
        except twisted.internet.error.AlreadyCalled:
            pass
        return r

    deferred.addBoth(clear_timeout)

    # return the deferred for syntactical convenience
    # (i.e. you could do 'yield addTimeout(...)')
    return deferred
