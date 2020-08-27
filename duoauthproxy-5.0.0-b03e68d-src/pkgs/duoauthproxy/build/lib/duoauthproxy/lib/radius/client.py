#
# Copyright (c) 2011 Duo Security
# All Rights Reserved
#

import copy
import random

import twisted.internet.error
from pyrad import packet
from twisted.internet import defer, protocol, reactor

from duoauthproxy.lib import log
from duoauthproxy.lib.base import AuthError
from duoauthproxy.lib.radius import base

from .base import add_packet_attributes

# create a strong PRNG
_GENERATOR = random.SystemRandom()


class ClientRequest(base.RadiusRequest):
    def __init__(self, request_packet, pw_codec="utf-8"):
        base.RadiusRequest.__init__(self, request_packet, pw_codec)

        # delayed call to resend
        self.retry_forward_dc = None

        # deferred for callback
        self.deferred = defer.Deferred()


class _IdentifierList(object):
    MAX_WAITING = 256

    def __init__(self):
        # not sure if deterministic id choice would be bad here, but
        # let's make it random
        self.unused_ids = list(range(0, 256))
        _GENERATOR.shuffle(self.unused_ids)

        # so that we can block if we run out of IDs
        self.wait_queue = []

    @defer.inlineCallbacks
    def request(self):
        # get an identifier for use with the dest server
        # this may not strictly be necessary, but should prevent collisions in cases
        # where the proxy may be serving multiple client devices...
        if len(self.unused_ids) < 1:
            # wait until an id becomes available. unless we've got way too many waiting already.
            if len(self.wait_queue) >= self.MAX_WAITING:
                raise Exception("Too many concurrent requests!")
            deferred = defer.Deferred()
            self.wait_queue += [deferred]
            yield deferred

        next_id = self.unused_ids.pop(0)
        defer.returnValue(next_id)

    def release(self, id):
        # If the ID isn't in use by any in-flight request, do nothing.
        if id in self.unused_ids:
            return

        insert_pos = _GENERATOR.randrange(len(self.unused_ids) + 1)
        self.unused_ids.insert(insert_pos, id)

        if len(self.wait_queue) > 0:
            deferred = self.wait_queue[0]
            self.wait_queue = self.wait_queue[1:]
            deferred.callback(None)


class RadiusClient(protocol.DatagramProtocol):
    def __init__(
        self, addrs, nas_ip, secret, retries, retry_wait, debug, pw_codec="utf-8"
    ):
        self.addrs = addrs
        if len(self.addrs) < 1:
            raise Exception("Need at least one destination (host, port)!")
        self.nas_ip = nas_ip
        self.secret = secret
        self.retries = retries
        self.retry_wait = retry_wait
        self.pw_codec = pw_codec

        self.requests = {}
        self.id_list = _IdentifierList()
        self.debug = debug

    @defer.inlineCallbacks
    def authenticate(self, username, password, client_ip, pass_through_attrs=None):
        if pass_through_attrs is None:
            pass_through_attrs = {}

        request = yield self._create_auth_request(
            username, password, client_ip, pass_through_attrs
        )

        # Send request; wait for response
        log.msg(
            "Sending request for user %r to %r with id %r"
            % (username, self.addrs[0], request.packet.id)
        )
        try:
            self.requests[request.packet.id] = request
            self._send_request(request)
            response_packet = yield request.deferred
            defer.returnValue(response_packet)
        except Exception as e:
            # Something went wrong. Clean up the request and raise.
            self._request_done(request)
            raise e

    @defer.inlineCallbacks
    def _create_auth_request(self, username, password, client_ip, pass_through_attrs):
        request_id = yield self.id_list.request()
        try:
            request_packet = packet.AuthPacket(
                code=packet.AccessRequest,
                id=request_id,
                secret=self.secret.encode(),
                dict=base.radius_dictionary(),
            )
            request_packet["NAS-IP-Address"] = self.nas_ip
            add_packet_attributes(packet=request_packet, attrs=pass_through_attrs)
            request = ClientRequest(request_packet, self.pw_codec)
            request.username = username
            if password is not None:
                request.password = password
            if client_ip:
                request.client_ip = client_ip

            defer.returnValue(request)
        except Exception as e:
            # If anything went wrong while building the request, release the ID
            self.id_list.release(request_id)
            raise e

    @defer.inlineCallbacks
    def radius_proxy(self, orig_request):
        """Send the given RADIUS packet and return the response received.
        """
        # Create a new request packet with a different ID but the same
        # type and attributes.
        request_packet = copy.deepcopy(orig_request.packet)
        request_packet.secret = self.secret.encode()
        request = ClientRequest(request_packet, self.pw_codec)

        # Assign the ID after building the request. Because we need to release
        # the ID if anything goes wrong, we need the try/except block to come
        # immediately after requesting the ID.
        request.packet.id = yield self.id_list.request()

        # Send onward; wait for reply.
        log.msg(
            "Sending proxied request for id %r to %r with id %r"
            % (orig_request.id, self.addrs[0], request_packet.id)
        )
        try:
            self.requests[request_packet.id] = request
            self._send_request(request)

            # Make response match principal's expectations.
            response_packet = yield request.deferred
            response_packet.id = orig_request.id
            response_packet.secret = orig_request.secret
            defer.returnValue(response_packet)
        except Exception as e:
            # Something went wrong. Clean up the request and raise.
            self._request_done(request)
            raise e

    def cleanup_all(self):
        # flatten values because it could be modified during this call
        for request in list(self.requests.values()):
            self._request_done(request)
            request.deferred.errback(AuthError("RADIUS client shutting down"))

    def _send_request(self, request, addrs=None, retry=0):
        if not addrs:
            # cycle through configured addresses
            addrs = self.addrs
        if retry > self.retries:
            log.msg(
                "Request timeout for (outgoing) id %r to %r" % (request.id, addrs[0])
            )
            self._request_done(request)
            request.deferred.errback(AuthError("RADIUS auth request timed out"))
            return

        # send request to first address
        raw = request.packet.RequestPacket()
        self.transport.write(raw, addrs[0])
        if self.debug:
            log.msg("Packet dump - sent to %s:" % (addrs[0][0]))
            log.msg(repr(raw))

        # set retry timer to re-send with next address
        request.retry_forward_dc = reactor.callLater(
            self.retry_wait, self._send_request, request, addrs[1:], retry + 1
        )

    def handle_response(self, datagram, source):
        response_packet = packet.AuthPacket(
            packet=datagram, dict=base.radius_dictionary()
        )
        response_packet.source = source

        # make sure it's from the correct host (or properly ip-spoofed :)
        if (source[0], int(source[1])) not in self.addrs:
            raise packet.PacketError(
                "response packet from unknown address: %s:%s" % source,
            )

        # look up id
        try:
            request = self.requests[response_packet.id]
        except KeyError:
            raise packet.PacketError(
                "unrecognized id in response packet: %s" % response_packet.id
            )

        # verify reply authentication
        if not request.packet.VerifyReply(response_packet, datagram):
            raise packet.PacketError("response packet has invalid authenticator")
        response_packet.secret = self.secret.encode()
        # Validate Message-Authenticator, if any
        if response_packet.message_authenticator:
            if not response_packet.verify_message_authenticator(
                original_authenticator=request.packet.authenticator
            ):
                raise packet.PacketError(
                    "Invalid Message-Authenticator from {0}".format(source[0])
                )
        response_packet.authenticator = request.packet.authenticator

        # clear request state
        self._request_done(request)

        log.msg(
            "Got response for id %r from %r; code %r"
            % (response_packet.id, response_packet.source, response_packet.code)
        )

        # callback
        request.deferred.callback(response_packet)

    def _request_done(self, request):
        try:
            # Check if the retry_forward_dc exists, because if something went
            # wrong before it could be assigned then _request_call will be called
            # to clean up the request.
            if request.retry_forward_dc:
                request.retry_forward_dc.cancel()
        except twisted.internet.error.AlreadyCalled:
            pass
        request.retry_forward_dc = None

        if request.id in self.requests:
            del self.requests[request.id]
        self.id_list.release(request.id)

    def datagramReceived(self, datagram, addr):
        """addr is a tuple of (host, port). If calling from a test case, you
        probably want to call handle_response instead so exceptions aren't
        lost."""
        host, port = addr
        if self.debug:
            log.msg("Packet dump - received from %s:" % (host))
            log.msg(repr(datagram))
        try:
            self.handle_response(datagram, (host, port))
        except packet.PacketError as err:
            log.msg("dropping packet from %s:%s - %s" % (host, port, err))
        except Exception:
            log.failure("Error receiving datagram")
