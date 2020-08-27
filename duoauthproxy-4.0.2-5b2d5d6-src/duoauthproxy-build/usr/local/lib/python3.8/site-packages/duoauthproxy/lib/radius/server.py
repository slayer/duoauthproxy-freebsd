#
# Copyright (c) 2011 Duo Security
# All Rights Reserved
#

import itertools
import re

import twisted.internet.error
from twisted.internet import protocol, reactor, defer
from pyrad import packet
import netaddr

from duoauthproxy.lib import ip_util, log, util
from duoauthproxy.lib.base import AuthError, AuthResult
from duoauthproxy.lib.config_error import ConfigError
from duoauthproxy.lib.radius import base

from .base import add_packet_attributes


class _ProxyRequest(base.RadiusRequest):
    def __init__(self, packet, pw_codec='utf-8', client_ip_attr='Calling-Station-Id'):
        base.RadiusRequest.__init__(self, packet, pw_codec, client_ip_attr)

        # response to send back to client
        self.response = None
        # delayed call to cleanup state
        self.cleanup_dc = None

    @property
    def source(self):
        return self.packet.source

    @source.setter
    def source(self, val):
        self.packet.source = val


# sentinel values for comparision below
_s1 = object()
_s2 = object()


def _match_request_packets(p1, p2):
    """Return true if p1 and p2 are (probably) the same request, and
    we should just retransmit an existing cached response

    We assume here that the caller has already matched up the source
    IP address"""

    # check ID
    if p1.id != p2.id:
        return False

    # check authenticator
    if p1.authenticator != p2.authenticator:
        return False

    # check username. return False if either packet doesn't have one
    if not p1.get(1) or not p2.get(1) or p1[1] != p2[1]:
        return False

    # check password.
    if p1.get(2) != p2.get(2):
        return False

    return True


class SimpleForwardServer(protocol.DatagramProtocol, object):
    def __init__(self, servers, debug, **kwargs):
        super(SimpleForwardServer, self).__init__()

        self.server_networks = {}
        for server in servers:
            for ip_net in servers[server]:
                self.server_networks[ip_net] = server

        self.debug = debug

    @defer.inlineCallbacks
    def datagramReceived(self, datagram, addr):
        """addr is a tuple of (host, port). If calling from a test case, you
        probably want to call handle_datagram_received instead so exceptions
        aren't lost."""
        host, port = addr
        try:
            yield self.handle_datagram_received(datagram, host, port)
        except packet.PacketError as err:
            log.msg("dropping packet from %s:%s - %s" % (host, port, err))
        except Exception:
            log.err(None, "unhandled error processing request from %s:%s" % (host, port))

    @defer.inlineCallbacks
    def handle_datagram_received(self, datagram, host, port):
        if self.debug:
            log.msg("Packet dump - received from %s:" % host)
            log.msg(repr(datagram))

        server = self.filter(host)
        log.msg("Sending request from %s to %s" % (host, self.server_names[server]))
        request = yield server.protocol._handle_request(datagram, (host, port))
        if request.response:
            self.transport.write(request.response, request.source)
            if self.debug:
                log.msg("Packet dump - sent to %s:" % (request.source[0]))
                log.msg(repr(request.response))

    def filter(self, host):
        net = netaddr.smallest_matching_cidr(
            netaddr.IPNetwork(host), list(self.server_networks.keys()))
        if net is not None:
            return self.server_networks[net]

        raise packet.PacketError('Unknown Client: %s' % host)


class SimpleRadiusServer(object):
    """Abstract base class for a Radius server as a Twisted Protocol. Retains
    request state until a given timeout is reached, in order to handle
    duplicate requests / retransmissions.

    Subclasses should implement the 'get_response()' function to construct
    a (raw data) packet to return to the radius client"""
    CLEANUP_WAIT = 30

    RADIUS_CODE_NAMES = {
        packet.AccessRequest: "AccessRequest",
        packet.AccessAccept: "AccessAccept",
        packet.AccessReject: "AccessReject",
        packet.AccountingRequest: "AccountingRequest",
        packet.AccountingResponse: "AccountingResponse",
        packet.AccessChallenge: "AccessChallenge",
        packet.StatusServer: "StatusServer",
        packet.StatusClient: "StatusClient",
        packet.DisconnectRequest: "DisconnectRequest",
        packet.DisconnectACK: "DisconnectACK",
        packet.DisconnectNAK: "DisconnectNAK",
        packet.CoARequest: "CoARequest",
        packet.CoAACK: "CoAACK",
        packet.CoANAK: "CoANAK",
    }

    # MS CHAPv2
    MS_ERRCODE_RE = re.compile(b'^\x00E=(?P<E>[0-9]+)')
    ERROR_PASSWORD_EXPIRED = 648
    MS_AUTH_FAILED_ERROR = [b'\x00E=691 R=0 V=3']

    def __init__(self, secrets, primary_ator, pass_through_attr_names, **kwargs):
        """Initialize the Radius Server instance.

        secrets: dictionary mapping from ip address to radius secret
                 (e.g. '{"127.0.0.1": "s3cr3t"}')
        primary_ator: client module with which to perform primary auth
        """
        super(SimpleRadiusServer, self).__init__()
        self.requests = {}
        self.secrets = secrets
        self.primary_ator = primary_ator
        pass_through_attr_names = pass_through_attr_names.strip()
        if pass_through_attr_names:
            self._pass_through_attr_names = util.parse_delimited_set(
                pass_through_attr_names)
        else:
            self._pass_through_attr_names = []
        self.pass_through_all = kwargs.get('pass_through_all', False)
        self.pw_codec = kwargs.get('pw_codec', 'utf-8')
        self.client_ip_attr = kwargs.get('client_ip_attr', 'Calling-Station-Id')
        self.server_section_name = kwargs.get('server_section_name', 'Unknown')
        self.server_section_ikey = kwargs.get('server_section_ikey', 'Unknown')

    @defer.inlineCallbacks
    def _handle_request(self, datagram, host_port):
        host, port = host_port
        request_pkt = packet.AuthPacket(packet=datagram,
                                        dict=base.radius_dictionary())
        request_pkt.source = (host, port)

        # make sure it's an AccessRequest
        if request_pkt.code != packet.AccessRequest:
            raise packet.PacketError('non-AccessRequest packet received')

        # lookup secret
        secret_for_host = self.secret_for_host(host)
        if secret_for_host is not None:
            request_pkt.secret = secret_for_host.encode()
        else:
            raise packet.PacketError('Unknown Client: %s' % host)

        # Validate Message-Authenticator, if any
        if request_pkt.message_authenticator:
            if not request_pkt.verify_message_authenticator():
                raise packet.PacketError('Invalid Message-Authenticator from {0}'.format(host))

        # check to see if it's a resend (i.e. client retry)
        old_request = self.requests.get((request_pkt.source, request_pkt.id))
        if old_request:
            old_request_pkt = old_request.packet
            if _match_request_packets(request_pkt, old_request_pkt):
                # enough things (src, id, authenticator, username,
                # password) match that it's probably safe to assume
                # it's a resend. so send our result back (if we have
                # one); otherwise ignore
                self.log_request(old_request, 'Received duplicate request')
                self._resend_response(old_request)
                defer.returnValue(old_request)
            else:
                self._cleanup_request(old_request)

        # create request state
        log.msg('Received new request id %r from %r'
                % (request_pkt.id, request_pkt.source))
        request = _ProxyRequest(request_pkt, self.pw_codec, self.client_ip_attr)
        self.requests[(request.source, request.id)] = request

        # Check if password property can decrypt using the current secret.
        try:
            request.password
        except UnicodeDecodeError:
            self.log_request(request,
                             'Cannot decode password using the configured'
                             ' radius_secret. Please ensure the client and'
                             ' Authentication Proxy use the same shared'
                             ' secret.')
            msg = "Cannot decode password"
            log.auth_standard(msg=msg,
                              username=request.username,
                              auth_stage=log.AUTH_UNKNOWN,
                              status=log.AUTH_ERROR,
                              server_section=self.server_section_name,
                              client_ip=request.client_ip,
                              server_section_ikey=self.server_section_ikey)
            response = self.create_reject_packet(request, msg)
            request.response = response.ReplyPacket()
        else:
            # authenticate the user
            request.response = yield self._get_response(request)
        self._send_response(request)
        defer.returnValue(request)

    def _send_response(self, request):
        self._resend_response(request)
        request.cleanup_dc = reactor.callLater(self.CLEANUP_WAIT, self._cleanup_request, request)

    def _resend_response(self, request):
        if request.response:
            self.log_request(request, 'Sending response')

    def _cleanup_request(self, request):
        try:
            if request.cleanup_dc is not None:
                request.cleanup_dc.cancel()
        except twisted.internet.error.AlreadyCalled:
            pass

        if self.requests.get((request.source, request.id)) is request:
            del self.requests[(request.source, request.id)]

    def log_request(self, request, msg):
        try:
            log.msg('({}, {}, {}): {}'.format(request.source, request.username, request.id, msg))
        except UnicodeEncodeError:
            log.msg('({}, {}): {}'.format(request.source, request.id, msg))

    def cleanup_all(self):
        """Immediately clean up all request state (including cleanup
        delayed calls).

        This method is intended primarily for testing scenarios, but
        generally can be used when shutting down the radius server
        (e.g. without also terminating the process)"""
        for request in list(self.requests.values()):
            self._cleanup_request(request)

    def code_to_string(self, code):
        """Return a string representation of a radius packet code

        e.g. for code 2, returns 'AccessAccept' """
        return self.RADIUS_CODE_NAMES.get(code, '(Unknown)')

    def create_accept_packet(self, request, msg=None, radius_attrs=None):
        """Create an AccessAccept response to a given request"""
        if radius_attrs is None:
            radius_attrs = {}
        return self._create_response_packet(request,
                                            packet.AccessAccept,
                                            msg,
                                            radius_attrs)

    def create_reject_packet(self, request, msg=None, radius_attrs=None):
        """Create an AccessReject response to a given request"""
        if radius_attrs is None:
            radius_attrs = {}
        return self._create_response_packet(request,
                                            packet.AccessReject,
                                            msg,
                                            radius_attrs)

    def _create_response_packet(self, request, code, msg=None, radius_attrs=None):
        """Create a response to a given request"""
        if radius_attrs is None:
            radius_attrs = {}

        response_packet = request.packet.CreateReply()
        response_packet.code = code
        add_packet_attributes(packet=response_packet, attrs=radius_attrs)
        if msg:
            response_packet['Reply-Message'] = msg.encode('utf-8')

        # RADIUS spec says:
        # If any Proxy-State attributes were present in the Access-Request,
        # they MUST be copied unmodified and in order into the response packet.
        if 'Proxy-State' in request.packet:
            for state in request.packet['Proxy-State']:
                response_packet.AddAttribute('Proxy-State', state)

        return response_packet

    @defer.inlineCallbacks
    def _get_response(self, request):
        response = yield self.get_response(request)
        self.log_request(request, 'Returning response code %r: %s'
                         % (response.code, self.code_to_string(response.code)))
        defer.returnValue(response.ReplyPacket())

    def get_response(self, request):
        """Construct a response packet to a given Radius
        request. Subclasses must override.

        This function is expected (though not strictly required) to
        return a Deferred. The Deferred callback should contain a
        Radius Packet instance, e.g. something returned by
        create_accept_packet() or create_reject_packet()"""
        raise NotImplementedError(
            '%s is an abstract base class' % self.__class__.__name__
        )

    @defer.inlineCallbacks
    def primary_auth(self, request, password):
        """
        Perform primary authentication.

        request -- Radius Access Request message
        password -- Password included in the radius request, if any

        Returns the RADIUS response to the primary authentication request.
        """
        if self.pass_through_all:
            radius_attrs = dict(request.packet)
        else:
            radius_attrs = dict(
                (attr, request[attr])
                for attr in self._pass_through_attr_names + base.MS_CHAP2_REQUEST_ATTRS
                if attr in request
            )
        try:
            primary_res = yield self.primary_ator.authenticate(
                request.username,
                password,
                request.client_ip,
                radius_attrs
            )
        except AuthError as err:
            msg = 'Error performing primary authentication: %s' % err
            self.log_request(request, msg)
            log.auth_standard(msg=msg,
                              username=request.username,
                              auth_stage=log.AUTH_PRIMARY,
                              status=log.AUTH_ERROR,
                              client_ip=request.client_ip,
                              server_section=self.server_section_name,
                              server_section_ikey=self.server_section_ikey)
            primary_res = AuthResult(False, msg)
        else:
            if not primary_res.success:
                primary_res_msg = 'Primary credentials rejected - {0}'.format(primary_res.msg)
                self.log_request(request, primary_res_msg)
                log.auth_standard(msg=primary_res_msg,
                                  username=request.username,
                                  auth_stage=log.AUTH_PRIMARY,
                                  status=log.AUTH_REJECT,
                                  client_ip=request.client_ip,
                                  server_section=self.server_section_name,
                                  server_section_ikey=self.server_section_ikey)
            else:
                log.auth_standard(msg='Primary authentication successful - {0}'.format(primary_res.msg),
                                  username=request.username,
                                  auth_stage=log.AUTH_PRIMARY,
                                  status=log.AUTH_ALLOW,
                                  client_ip=request.client_ip,
                                  server_section=self.server_section_name,
                                  server_section_ikey=self.server_section_ikey)

        defer.returnValue(primary_res)

    def secret_for_host(self, host: str) -> str:
        ipnetwork = netaddr.smallest_matching_cidr(
            netaddr.IPAddress(host),
            list(self.secrets.keys()),
        )
        return self.secrets.get(ipnetwork)


def parse_radius_secrets(config_dict):
    """
    Parse RADIUS network/secret pairs out of a ConfigDict.

    Networks can be:
    * IP
    * CIDR notation
    * IP/netmask
    * Ranges, written like "IP1-IP2"

    For example, if the ConfigDict contains the following keys/values:
    {'radius_ip_1': '1.1.1.1',
     'radius_secret_1': 'secret1',
     'radius_ip_2': '2.2.2.0/24',
     'radius_secret_2': 'secret2',
     'radius_ip_3': '3.3.3.3/255.255.0.0',
     'radius_secret_3': 'secret3',
     'radius_ip_4': '4.4.4.1-4.4.4.3',
     'radius_secret_4': 'secret4'}

    Then this function will return:
    {IPNetwork('1.1.1.1/32'): 'secret1',
     IPNetwork('2.2.2.0/24'): 'secret2',
     IPNetwork('3.3.0.0/16'): 'secret3',
     IPNetwork('4.4.4.1/32'): 'secret4',
     IPNetwork('4.4.4.2/31'): 'secret4'}
    """
    secrets = {}
    prefix = 'radius_ip_'
    for k in config_dict.keys():
        if not k.startswith(prefix):
            continue
        client_number = k[len(prefix):]
        if not client_number.isdigit():
            raise ConfigError('Expected integer as suffix for \'%s\'' % k)
        ip_config_key = 'radius_ip_' + client_number
        secret_config_key = 'radius_secret_' + client_number
        protected_secret_config_key = 'radius_secret_protected_' + client_number
        secret = config_dict.get_protected_str(
            protected_secret_config_key,
            secret_config_key
        )
        ip = config_dict.get_str(ip_config_key)

        if secret is None:
            raise ConfigError(
                "Invalid secret (None) configured for '{0}'".format(ip))
        try:
            ip_networks = ip_util.get_ip_networks(ip)
        except (TypeError, ValueError, netaddr.core.AddrFormatError) as e:
            raise ConfigError(
                "Invalid IP, network, or range for '%s': '%s' (%s)"
                % (ip_config_key, ip, e),
            )
        for network in ip_networks:
            secrets[network] = secret

    if not secrets:
        # Require at least one pair by raising ConfigError for
        # whichever setting is missing.
        config_dict.get_str('radius_ip_1')
        config_dict.get_protected_str('radius_secret_protected_1', 'radius_secret_1')
    return secrets


def parse_exempt_usernames(config_dict):
    exempt_usernames = []
    for i in itertools.count(1):
        exempt_username_key = 'exempt_username_%d' % i
        if exempt_username_key not in config_dict:
            break
        exempt_username = config_dict.get_str(exempt_username_key)
        exempt_usernames.append(exempt_username)
    return exempt_usernames


def parse_client_ip_attribute(config_dict):
    """
    Configures which RADIUS attribute is used to read the client's IP address.
    """
    attributes_map = {
        'paloalto': 'PaloAlto-Client-Source-IP',
        'default': 'Calling-Station-Id'
    }
    client_ip_attr = config_dict.get_str('client_ip_attr', 'default')
    client_ip_attr = attributes_map.get(client_ip_attr, client_ip_attr)

    if client_ip_attr not in base.radius_dictionary():
        raise ConfigError('Invalid configuration value for client_ip_attr: RADIUS attribute {0} unkonwn.'.format(client_ip_attr))
    return client_ip_attr
