#
# Copyright (c) 2011 Duo Security
# All Rights Reserved
#
# pylint: disable=no-member

import base64
import os

import twisted.internet.error
from twisted.internet import reactor, defer
from pyrad import packet

from duoauthproxy.lib import log

from duoauthproxy.lib.radius.server import SimpleRadiusServer

RADIUS_CHALLENGE_PROMPT_FORMAT_CONSOLE = "console"
RADIUS_CHALLENGE_PROMPT_FORMAT_HTML = "html"
RADIUS_CHALLENGE_PROMPT_FORMAT_SHORT = "short"
RADIUS_CHALLENGE_PROMPT_FORMATS = [
    RADIUS_CHALLENGE_PROMPT_FORMAT_CONSOLE,
    RADIUS_CHALLENGE_PROMPT_FORMAT_HTML,
    RADIUS_CHALLENGE_PROMPT_FORMAT_SHORT,
]


class BadStateError(Exception):
    pass


class _ChallengeState(object):
    def __init__(self, initial_request, challenge_id, state=None):
        self.initial_request = initial_request
        self.challenge_id = challenge_id
        self.state = state

        # delayed call to cleanup state
        self.cleanup_dc = None

    @property
    def source(self):
        return self.initial_request.source


class ChallengeResponseRadiusServer(SimpleRadiusServer):
    """Abstract base class for a Challenge-Response Radius server as a
    Twisted Protocol.

    Subclasses should implement the 'get_initial_response()' and
    'get_challenge_response()' functions to construct (raw data)
    reply packets to return to the radius client. If sending an
    AccessChallenge back to the client, subclasses should call
    'create_challenge()' to create the challenge, and store state."""
    CHALLENGE_WAIT = 300

    def __init__(self, exempt_usernames=None, **kwargs):
        super(ChallengeResponseRadiusServer, self).__init__(**kwargs)
        self.challenges = {}
        if exempt_usernames is None:
            self.exempt_usernames = []
        else:
            self.exempt_usernames = exempt_usernames

    def _create_challenge_id(self):
        """ Generate an unused id to store as the 'state' in a new AccessChallenge"""
        while True:
            challenge_id = base64.b64encode(os.urandom(33))
            if challenge_id not in self.challenges:
                return challenge_id

    def create_challenge(self, request, msg, state=None, challenge_id=None):
        """Create an AccessChallenge response to a given request, and record
        state associated with it.

        An opaque identifier will be stored as the 'State' attribute
        of the response packet, which will be used to reference and
        return the provided 'state' data upon receiving a subsequent
        request.

        If no response is received to an AccessChallenge after a given
        period of time passes, the challenge state will be discarded"""
        challenge_id = challenge_id or self._create_challenge_id()

        radius_attrs = {
            'State': challenge_id
        }

        response_packet = self._create_response_packet(request, packet.AccessChallenge, msg, radius_attrs)

        # store challenge state so we can look it up
        self.store_challenge_state(
            request,
            challenge_id,
            state=state
        )

        return response_packet

    def store_challenge_state(self, request, challenge_id, state=None):
        """
        Remember challenge_id as a valid challenge to accept responses for.

        If any state object is given it will be passed to
        get_challenge_response() if a response is received to this
        challenge.
        """
        challenge_state = _ChallengeState(request, challenge_id,
                                          state=state)
        challenge_state.cleanup_dc = reactor.callLater(self.CHALLENGE_WAIT,
                                                       self._cleanup_challenge,
                                                       challenge_state)
        self.challenges[challenge_id] = challenge_state
        return challenge_state

    def _cleanup_challenge(self, challenge_state):
        if challenge_state.cleanup_dc is not None:
            try:
                challenge_state.cleanup_dc.cancel()
            except twisted.internet.error.AlreadyCalled:
                pass
        del self.challenges[challenge_state.challenge_id]

    def cleanup_all(self):
        for challenge in list(self.challenges.values()):
            self._cleanup_challenge(challenge)
        SimpleRadiusServer.cleanup_all(self)

    def _find_challenge(self, request):
        """Determine whether a request is a response to an
        AccessChallenge, or a new (initial) request

        If the request appears to be a valid challenge-response,
        return the associated state object. If appears to be a new
        request, return None. (If it is a response to an unknown
        challenge, the function may also raise an exception)

        (This function was split out from get_response so that
        certain subclasses can override it to work around noncompliant
        client devices)"""

        if 'State' in request.packet:
            # it's a challenge-response. look it up.
            try:
                challenge_state = self.challenges[request.get_first('State')]
            except KeyError:
                raise BadStateError(
                    'Response to unknown AccessChallenge!'
                    ' state %r' % request.get_first('State')
                )
            return challenge_state
        else:
            return None

    @defer.inlineCallbacks
    def get_response(self, request: packet.AuthPacket):
        """Constructs a response packet to a given Radius request

        If the request is an 'initial' request (i.e. has no 'State'
        attribute, so it did not arrive in response to an
        AccessChallenge), then we simply call get_initial_response()

        If the request is a response to an AccessChallenge, then
        lookup the challenge state, perform some consistency checks
        (username, source ip), then we call self.get_challenge_response()
        """
        try:
            challenge_state = self._find_challenge(request)
            if challenge_state:
                # sanity check on src ip
                expected_source = challenge_state.source
                if expected_source[0] != request.source[0]:
                    raise BadStateError(
                        'Response to AccessChallenge from '
                        'wrong source ip: %r' % request.source[0]
                    )

                # sanity check on username
                if challenge_state.initial_request.username != request.username:
                    raise BadStateError(
                        'Response to AccessChallenge with '
                        'incorrect username: %r' % request.username
                    )

                # everything checks out OK so far
                self.log_request(request,
                                 'Valid response to challenge issued at id %r'
                                 % challenge_state.initial_request.id)

                # clear challenge state (it has been consumed)
                self._cleanup_challenge(challenge_state)

                # build response
                ret = yield self.get_challenge_response(request,
                                                        challenge_state.state)
            else:
                ret = yield self.get_initial_response(request)
        except BadStateError as e:
            msg = str(e)
            self.log_request(request, msg)
            log.auth_standard(msg=msg,
                              username=request.username,
                              auth_stage='Unknown',
                              status=log.AUTH_REJECT,
                              server_section=self.server_section_name,
                              client_ip=request.client_ip,
                              server_section_ikey=self.server_section_ikey)
            ret = yield self.create_reject_packet(request, 'Unknown Challenge')

        defer.returnValue(ret)

    @defer.inlineCallbacks
    def get_initial_response(self, request):
        raise NotImplementedError(
            '%s is an abstract base class' % self.__class__.__name__
        )

    @defer.inlineCallbacks
    def get_challenge_response(self, request, state):
        raise NotImplementedError(
            '%s is an abstract base class' % self.__class__.__name__
        )
