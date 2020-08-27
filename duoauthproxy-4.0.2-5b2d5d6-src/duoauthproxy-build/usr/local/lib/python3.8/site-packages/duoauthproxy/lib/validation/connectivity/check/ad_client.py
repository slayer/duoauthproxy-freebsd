#
# Copyright (c) 2018 Duo Security
# All Rights Reserved
#
from twisted.internet import defer

from duoauthproxy.lib import util
from duoauthproxy.modules.ad_client import _ADServiceClientFactory
from duoauthproxy.lib.validation.connectivity.connectivity_toolbox import STANDARD_TOOLBOX
from duoauthproxy.lib.validation.connectivity.connectivity_results import (
    AdClientConnectivityResult,
    UnmetPrerequisiteSkippedTestResult,
    LdapConnectResult,
    LdapHostResult
)


@defer.inlineCallbacks
def check_ad_client(config, toolbox=STANDARD_TOOLBOX):
    """Checks an ad client section config by testing
      1) We can connect via TCP to the host
      2) We can make LDAP connection to the host
      3) We can bind as the service account user
      4. A search with a given filter and security group dn returns something
    Args:
        toolbox: a ConnectivityTestToolbox for doing individual connectivity tests
    Returns:
        AdClientConnectivityResult: The result of the testing
    """
    host_results = []

    factory_kwargs = util.parse_ad_client(config)
    hosts = util.get_host_list(config)
    port = util.get_ldap_port(config, factory_kwargs['transport_type'])

    for host in hosts:
        factory = _ADServiceClientFactory(**factory_kwargs)
        host_result = yield _test_one_host(host, port, factory, toolbox)
        host_results.append(host_result)

    defer.returnValue(AdClientConnectivityResult(host_results))


@defer.inlineCallbacks
def _test_one_host(host, port, factory, toolbox):

    tcp_connect_result = yield toolbox.test_connect_tcp(host, port)
    transport_type = factory.transport_type

    if not tcp_connect_result.is_successful():
        defer.returnValue(LdapHostResult(
            host,
            port,
            transport_type,
            tcp_connect_result,
            UnmetPrerequisiteSkippedTestResult('ldap connection', 'tcp connection'),
            UnmetPrerequisiteSkippedTestResult('bind', 'tcp connection'),
            UnmetPrerequisiteSkippedTestResult('search', 'tcp connection')
        ))

    try:
        connected_client = yield _connect_host(factory, host, port)
        ldap_connect_result = LdapConnectResult(True, host, port)
    except Exception as e:
        ldap_connect_result = LdapConnectResult(False, host, port, exception=e)
        defer.returnValue(LdapHostResult(
            host,
            port,
            transport_type,
            tcp_connect_result,
            ldap_connect_result,
            UnmetPrerequisiteSkippedTestResult('bind', 'ldap connection'),
            UnmetPrerequisiteSkippedTestResult('search', 'ldap connection')
        ))

    bind_result = yield _test_bind(connected_client, toolbox)
    if not bind_result.is_successful():
        defer.returnValue(LdapHostResult(
            host,
            port,
            transport_type,
            tcp_connect_result,
            ldap_connect_result,
            bind_result,
            UnmetPrerequisiteSkippedTestResult('search', 'bind')
        ))

    search_result = yield _test_search(connected_client, toolbox)

    connected_client.perform_unbind()

    defer.returnValue(LdapHostResult(
        host,
        port,
        transport_type,
        tcp_connect_result,
        ldap_connect_result,
        bind_result,
        search_result
    ))


@defer.inlineCallbacks
def _connect_host(factory, host, port):
    """Helper function that connects to the host/port
    Args:
        factory (_ADServiceClientFactory)
        host (str)
        port (int)
    Returns:
        _ADServiceClientProtocol if connection succeeded.
    Raises:
        Yield on factory.deferred raises exception if failed to connect to host
    """
    factory.connect_ldap(host, port)
    client = yield factory.deferred
    defer.returnValue(client)


@defer.inlineCallbacks
def _test_bind(client, toolbox):
    result = yield toolbox.test_bind_service_account(client, keep_bound=True)
    defer.returnValue(result)


@defer.inlineCallbacks
def _test_search(client, toolbox):
    filter_object = yield client.user_filter_object()
    search_result = yield toolbox.test_ldap_search_has_results(
        client,
        client.factory.search_dn,
        filter_object)
    defer.returnValue(search_result)
