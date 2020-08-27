#
# Copyright (c) 2017 Duo Security
# All Rights Reserved
# All Wrongs Reversed
#
""" Module for determining if the Authproxy can reach the different
IP addresses a customer might configure."""

from twisted.internet import reactor
from twisted.internet import defer
from twisted.internet.protocol import Protocol, Factory
from twisted.internet.endpoints import TCP4ClientEndpoint
from twisted.internet.error import ConnectError, DNSLookupError
import pyrad

from ..connectivity_results import ConnectResult, RadiusConnectResult


def _connect_callback(protocol):
    """Fired when connection was successful. Closes the connection and returns success"""
    protocol.transport.loseConnection()
    return True


def _connect_errback(err):
    """Fired when connection fails. Raise underlying exception to be handled by caller"""
    err.raiseException()


def _establish_connection(endpoint):
    """Takes an endpoint and attempts to make the connection.
    Args:
        endpoint: A Twisted client endpoint object. Commonly TCP4ClientEndpoint or SSL4ClientEndpoint
    Returns:
        deferred: Callbacks will clean up connection if needed and return or raise result
    """
    connection_client_factory = Factory.forProtocol(Protocol)
    d = endpoint.connect(connection_client_factory)
    d.addCallbacks(_connect_callback, _connect_errback)
    return d


@defer.inlineCallbacks
def can_connect_tcp(host, port, connection_method=_establish_connection):
    """Attempt to open a tcp connection and return if successful
    Args:
        host (str): ip address of hostname to connect
        port (int): port to connect to
    Returns:
        ConnectResult: the result of the test
    """
    endpoint = TCP4ClientEndpoint(reactor, host, port)
    try:
        yield connection_method(endpoint)
        result = ConnectResult(True, host, port)
    except (ConnectError, DNSLookupError) as e:
        result = ConnectResult(False, host, port, exception=e)

    defer.returnValue(result)


def can_connect_radius(client, request):
    """Determines if client can connect to a radius server. Teases out issues
       with shared secrets or network issues
    Args:
        client (RadiusClient): Configured client
        request (Packet): Radius packet to send
    Returns:
        bool: RadiusConnectResult with True if we could connect or False if the network or a bad secret caused errors
    """
    try:
        client.SendPacket(request)
        result = RadiusConnectResult(True, client.server, client.authport)
    except pyrad.client.Timeout as e:
        result = RadiusConnectResult(False, client.server, client.authport, e)

    return result
