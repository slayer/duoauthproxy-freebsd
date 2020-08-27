#
# Copyright (c) 2018 Duo Security
# All Rights Reserved
# All Wrongs Reversed
#
from twisted.internet import reactor
from twisted.internet import defer
from twisted.internet.protocol import Protocol, ServerFactory, DatagramProtocol
from twisted.internet.error import CannotListenError
import psutil

from ..connectivity_results import ListenResult, AuthproxyUsingPortSkippedTestResult


@defer.inlineCallbacks
def can_listen_tcp(port, interface=''):
    """Attempts to create a tcp listener on a port/interface combo
    Args:
        port (int): Listening port
        interface (str): Hostname to bind to. If not specified binds to all
    Returns:
        ListenResult: the result of the test
    """
    connection_server_factory = ServerFactory.forProtocol(Protocol)

    try:
        listener = reactor.listenTCP(
            port=port,
            factory=connection_server_factory,
            interface=interface,
        )
        yield listener.stopListening()
        result = ListenResult(True, port, interface)
    except CannotListenError as e:
        result = _reason_port_is_used(port, interface, e, 'tcp')

    defer.returnValue(result)


@defer.inlineCallbacks
def can_listen_udp(port, interface=''):
    """Attempts to create a udp listener on a port/interface combo
    Args:
        port (int): Listening port
        interface (str): Hostname to bind to. If not specified binds to all
    Returns:
        ListenResult: the result of the test
    """
    protocol = DatagramProtocol()

    try:
        listener = reactor.listenUDP(
            port=port,
            protocol=protocol,
            interface=interface,
        )
        yield listener.stopListening()
        result = ListenResult(True, port, interface)
    except CannotListenError as e:
        result = _reason_port_is_used(port, interface, e, 'udp')

    defer.returnValue(result)


@defer.inlineCallbacks
def can_listen_ssl(port, ssl_ctx_factory, interface=''):
    """Attempts to create an ssl listener on a port/interface combo
    Args:
        port (int): Listening port
        ssl_ctx_factory (twisted.internet.ssl.ContextFactory): Factory that can create the ssl contexts to be used by the connections
        interface (str): Hostname to bind to. If not specified binds to all
    Returns:
        ListenResult: the result of the test
    """
    connection_server_factory = ServerFactory.forProtocol(Protocol)

    try:
        listener = reactor.listenSSL(
            port=port,
            factory=connection_server_factory,
            interface=interface,
            contextFactory=ssl_ctx_factory,
        )
        yield listener.stopListening()
        result = ListenResult(True, port, interface)
    except CannotListenError as e:
        result = _reason_port_is_used(port, interface, e, 'ssl')

    defer.returnValue(result)


def _reason_port_is_used(port, interface, exception, listen_type):
    """Return result based on whether actual authproxy is using port or something else
    Args:
        port (int): Listening port we want to see availability for
        interface (str): Interface to combine with above port
        exception (str): Exception from listen attempt to be logged
        type (str): one of ssl, tcp, udp
    Returns:
        AuthproxyUsingPortSkippedTestResult if authproxy is on port
        or a failed ListenResult with the process using the port
    """
    if listen_type == 'tcp' or listen_type == 'ssl':
        kind = 'tcp'
    elif listen_type == 'udp':
        kind = 'udp'
    pid = _get_listener_pid(port, interface, kind)
    port_user = None
    if pid is not None:
        port_user = _get_listener_name(pid)
        if 'twistd' in port_user.lower() or "proxy_svc" in port_user.lower():
            return AuthproxyUsingPortSkippedTestResult("listen {}".format(listen_type))
    return ListenResult(False, port, interface, port_user=port_user, pid=pid, exception=exception)


def _get_listener_name(pid):
    """Return process listening on a port
    Args:
        pid (int): Process id
    Returns:
        str: Process Name
    """
    unknown = "Unknown Process"
    if pid == -1:
        return unknown
    try:
        process = psutil.Process(pid)
        return process.name()
    except psutil.NoSuchProcess:
        return unknown


def _get_listener_pid(port, interface, kind):
    """Return the process id for the listener on a port
    Args:
        port (int): Port number to check for listener on
        interface (str): Interface to be combined with port above
        kind (str): Used by psutil to filter results inet, tcp, udp, etc.
    Returns:
        PID Value (int)
        -1 if listener but pid can't be determined by psutil
        None if no one is listening
    """
    if interface == '':
        interface = '0.0.0.0'
    for conn in psutil.net_connections(kind):
        addr = conn.laddr
        if port == addr.port and interface == addr.ip:
            if conn.pid is None:
                return -1
            else:
                return conn.pid
    return None
