#
# Copyright (c) 2018 Duo Security
# All Rights Reserved
#
from twisted.internet import defer

from duoauthproxy.lib import const, ip_util, util
from duoauthproxy.lib.validation.connectivity.connectivity_results import (
    ConfigCheckResult,
    HttpProxyResult,
    InvalidConfigKeyProblem,
    MissingConfigKeyProblem,
)
from duoauthproxy.lib.validation.connectivity.connectivity_toolbox import (
    STANDARD_TOOLBOX,
)

from . import base_duo_check


@defer.inlineCallbacks
def check_http_proxy(config, toolbox=STANDARD_TOOLBOX):
    """
    Checks an http_proxy section config by testing
      1) The config is valid
      2) We can listen via TCP on the configured port
      3) We can /ping Duo at the provided api host

    Args:
        config: A ConfigDict for an http_proxy module
        toolbox: a ConnectivityTestToolbox for doing individual connectivity tests

    Returns:
        HttpProxyResult with the results of the testing
    """
    config_result = validate_http_proxy_config(config)

    port = config.get_int("port", const.DEFAULT_HTTP_PORT)
    interface = config.get_str("interface", "")
    can_listen_result = yield toolbox.test_listen_tcp(port, interface=interface)

    api_host = config.get_str("api_host", "")
    ca_certs = config.get_str("http_ca_certs_file", const.DEFAULT_HTTP_CERTS_FILE)
    ca_certs_path = util.resolve_file_path(ca_certs)

    can_ping_result = base_duo_check.perform_duo_ping(
        toolbox, api_host, "", "", ca_certs_path
    )
    time_drift_result = base_duo_check.perform_time_drift(
        toolbox, can_ping_result, api_host, "", "", ca_certs_path
    )

    result = HttpProxyResult(
        config_result, can_listen_result, can_ping_result, time_drift_result
    )
    defer.returnValue(result)


def validate_http_proxy_config(config):
    """
    Validate an 'http_proxy' configuration, checking that
    1) All required values are present (currently only 'api_host' is required)
    2) Any IPs provided in 'client_ip' are valid

    Args:
        config: A ConfigDict for an http_proxy module

    Returns:
        ConfigCheckResult with any config problems
    """

    problems = []

    if "api_host" not in config:
        problems.append(MissingConfigKeyProblem("api_host"))

    for client_ip in util.parse_delimited_set(config.get_str("client_ip", "")):
        is_valid = ip_util.is_valid_ip(client_ip)
        if not is_valid:
            problems.append(InvalidConfigKeyProblem("client_ip", client_ip))

    return ConfigCheckResult(problems)
