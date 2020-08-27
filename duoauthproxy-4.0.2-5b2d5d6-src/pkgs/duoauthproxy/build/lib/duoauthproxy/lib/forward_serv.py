#
# Copyright (c) 2011 Duo Security
# All Rights Reserved
#
"""
This module provides the Auth Proxy with a server that receives RADIUS packets and forwards them to one or more RADIUS servers.
"""

from twisted.internet import reactor, defer
from duoauthproxy.lib.radius.server import SimpleForwardServer
import duoauthproxy.lib.base as base


class DuoForwardServer(SimpleForwardServer):
    def __init__(self, servers, server_names, debug, **kwargs):
        super(DuoForwardServer, self).__init__(servers, debug)
        self.server_names = server_names
        self.debug = debug


class Module(base.ServerModule, object):
    def __init__(self, port, servers, server_names, interface, debug):
        self.server_names = server_names
        self.port = port
        self.protocol = DuoForwardServer(servers, server_names, debug)
        self.interface = interface
        self.listener = None
        self._bind_if_necessary()

    def startService(self):
        base.ServerModule.startService(self)
        self._bind_if_necessary()

    @defer.inlineCallbacks
    def stopService(self):
        super(Module, self).stopService()
        if self.listener:
            yield self.listener.stopListening()
            self.listener = None

    def _bind_if_necessary(self):
        if self.listener is None:
            self.listener = reactor.listenUDP(
                self.port,
                self.protocol,
                self.interface,
            )
