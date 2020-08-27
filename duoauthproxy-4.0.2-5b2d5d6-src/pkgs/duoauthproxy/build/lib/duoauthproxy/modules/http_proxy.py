#
# Copyright (c) 2015 Duo Security
# All Rights Reserved
#
import functools

from twisted.internet import reactor, defer
import twisted.internet.protocol
from twisted.application.service import Service

from twisted_connect_proxy.server import ConnectProxy

from duoauthproxy.lib import log, util, ip_util, const


class Module(Service):

    def __init__(self, config):
        log.msg('HTTP Proxy Module Configuration:')
        log.config(config)
        self.port = config.get_int('port', const.DEFAULT_HTTP_PORT)
        host = config.get_str('api_host')
        self.interface = config.get_str('interface', '')
        client_ips = get_allowed_ip_networks(config)

        self.factory = twisted.web.http.HTTPFactory()
        self.factory.protocol = functools.partial(ConnectProxy, host=host, client_ips=client_ips)
        self.listener = None
        self._bind_if_necessary()

    def startService(self):
        Service.startService(self)
        self._bind_if_necessary()

    @defer.inlineCallbacks
    def stopService(self):
        Service.stopService(self)
        if self.listener is not None:
            yield self.listener.stopListening()
            self.listener = None

    def _bind_if_necessary(self):
        if self.listener is None:
            self.listener = reactor.listenTCP(
                port=self.port,
                factory=self.factory,
                interface=self.interface,
            )


def get_allowed_ip_networks(config):
    """
    Determine the list of allowed IP Networks from the given configuration, where there may be a 'client_ip' section
    with a comma-separated list, each item being either
        A single IP address
        An IP address range
        A CIDR-style IP range

    Args:
        config (ConfigDict): the section config

    Returns:
        [IPNetwork]: The allowed IP Networks from the config
    """
    client_ips = []

    for ip_string in util.parse_delimited_set(config.get_str('client_ip', '')):
        if ip_util.is_valid_ip(ip_string):
            client_ips.extend(ip_util.get_ip_networks(ip_string))

    return client_ips
