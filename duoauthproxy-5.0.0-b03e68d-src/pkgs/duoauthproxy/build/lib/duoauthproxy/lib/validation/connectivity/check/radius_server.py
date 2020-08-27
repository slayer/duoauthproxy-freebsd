#
# Copyright (c) 2018 Duo Security
# All Rights Reserved
#
from twisted.internet import defer

from duoauthproxy.lib import const, ip_util, util
from duoauthproxy.lib.validation.connectivity.connectivity_results import (
    ConfigCheckResult,
    InvalidConfigKeyProblem,
    MissingConfigKeyProblem,
    RadiusServerResult,
)
from duoauthproxy.lib.validation.connectivity.connectivity_toolbox import (
    STANDARD_TOOLBOX,
)

from . import base_duo_check


@defer.inlineCallbacks
def check_radius_server(config, toolbox=STANDARD_TOOLBOX):
    """
    Checks a radius_server section config by checking
      1) The config is valid
      2) We can /ping and /check Duo with the provided api host and credentials
      3) We can listen on the specified port + interface

    Args:
        config: A ConfigDict with the section config
        toolbox: a ConnectivityTestToolbox for doing individual connectivity tests

    Returns:
        RadiusServerResult with the results of the testing

    """
    config_result = validate_radius_server_config(config)

    ikey = config.get_str("ikey", "")
    skey = config.get_protected_str("skey_protected", "skey", "")
    api_host = config.get_str("api_host", "")

    ca_certs = config.get_str("http_ca_certs_file", const.DEFAULT_HTTP_CERTS_FILE)
    ca_certs_path = util.resolve_file_path(ca_certs)
    http_proxy = None
    http_proxy_host = config.get_str("http_proxy_host", "")
    if http_proxy_host:
        http_proxy_port = config.get_int("http_proxy_port", 80)
        http_proxy = (http_proxy_host, http_proxy_port)

    ping_result = base_duo_check.perform_duo_ping(
        toolbox, api_host, "", "", ca_certs_path, http_proxy=http_proxy
    )
    time_drift_result = base_duo_check.perform_time_drift(
        toolbox, ping_result, api_host, "", "", ca_certs_path, http_proxy=http_proxy
    )
    check_result = base_duo_check.perform_credentials_check(
        toolbox, api_host, skey, ikey, ca_certs_path, http_proxy=http_proxy
    )

    port = config.get_int("port", const.DEFAULT_RADIUS_PORT)
    interface = config.get_str("interface", "")
    listen_result = yield toolbox.test_listen_udp(port, interface)

    result = RadiusServerResult(
        config_result, ping_result, time_drift_result, check_result, listen_result
    )
    defer.returnValue(result)


def validate_radius_server_config(config):
    """
    Check the configuration of a radius_server module:
      Make sure required keys are present (ikey, skey or skey_protected, api_host, radius_ip_1, radius_secret_1)
      All radius_ip entries are valid IPs.

    Args:
        config: the ConfigDict for the module

    Returns:
        ConfigCheckResult with any config problems

    """
    problems = []

    for required_key in ["ikey", "api_host"]:
        if required_key not in config:
            problems.append(MissingConfigKeyProblem(required_key))

    if not ("skey" in config or "skey_protected" in config):
        problems.append(MissingConfigKeyProblem("skey / skey_protected"))

    for radius_ip_key in [
        x for x in config.keys() if x.lower().startswith("radius_ip")
    ]:
        radius_ip_value = config[radius_ip_key]
        if not ip_util.is_valid_ip(radius_ip_value):
            problems.append(InvalidConfigKeyProblem(radius_ip_key, radius_ip_value))

    return ConfigCheckResult(problems)
