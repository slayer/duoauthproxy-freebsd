#
# Copyright (c) 2011 Duo Security
# All Rights Reserved
#
from pyrad import packet

from ..lib import log
from ..lib import util
from ..lib import const
from ..lib.config_error import ConfigError
from ..lib.base import AuthResult, ClientModule
from ..lib.radius.base import MS_CHAP2_RESPONSE_ATTRS
from ..lib.radius.client import RadiusClient
from twisted.internet import defer, reactor


class Module(ClientModule):
    def __init__(self, config):
        log.msg('RADIUS Client Module Configuration:')
        log.config(config, lambda x: x.startswith('secret'))

        addrs = util.get_addr_port_pairs(config)
        secret = config.get_protected_str('secret_protected', 'secret')
        retries = config.get_int('retries', 3)
        retry_wait = config.get_int('retry_wait', const.DEFAULT_RADIUS_RETRY_WAIT)
        try:
            nas_ip = config.get_str('nas_ip')
        except ConfigError:
            nas_ip = util.get_authproxy_ip()

        pass_through_attr_names = config.get_str('pass_through_attr_names', '')
        pass_through_attr_names = pass_through_attr_names.strip()
        if pass_through_attr_names:
            self.pass_through_attr_names = util.parse_delimited_set(
                pass_through_attr_names)
        else:
            self.pass_through_attr_names = []

        self.pass_through_all = config.get_bool('pass_through_all', False)

        debug = config.get_bool('debug', False)

        pw_codec = config.get_str('pw_codec', 'utf-8')
        # build protocol
        self.protocol = RadiusClient(addrs, nas_ip, secret, retries,
                                     retry_wait, debug, pw_codec)
        self.listener = None

    def startService(self):
        ClientModule.startService(self)
        self.listener = reactor.listenUDP(0, self.protocol)

    def stopService(self):
        ClientModule.stopService(self)
        if self.listener:
            self.listener.stopListening()
            self.listener = None
        self.protocol.cleanup_all()

    @defer.inlineCallbacks
    def authenticate(self, username, password, client_ip, pass_through_attrs=None):
        if pass_through_attrs is None:
            pass_through_attrs = {}
        response_packet = yield self.protocol.authenticate(username,
                                                           password,
                                                           client_ip,
                                                           pass_through_attrs)
        # make sure it's an AccessAccept or AccessReject
        if response_packet.code not in (packet.AccessAccept,
                                        packet.AccessReject):
            raise packet.PacketError(
                'response packet is not Access-Accept or Access-Reject'
                ' (code %s)'
                % response_packet.code,
            )

        result = AuthResult.from_radius_packet(response_packet)

        if self.pass_through_all:
            for attr in result.response:
                result.radius_attrs[attr] = result.response[attr]

        for attr in self.pass_through_attr_names + MS_CHAP2_RESPONSE_ATTRS:
            if attr in result.response:
                result.radius_attrs[attr] = result.response[attr]

        defer.returnValue(result)

    @defer.inlineCallbacks
    def radius_proxy(self, request):
        response_packet = yield self.protocol.radius_proxy(request)
        # No need to pass_through_attr_names; everything's passed through!
        defer.returnValue(response_packet)
