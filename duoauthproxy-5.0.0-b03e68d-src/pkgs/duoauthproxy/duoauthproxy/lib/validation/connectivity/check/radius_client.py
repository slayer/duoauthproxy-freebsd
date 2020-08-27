#
# Copyright (c) 2018 Duo Security
# All Rights Reserved
#

import pyrad
from pyrad.client import Client

from duoauthproxy.lib import const, ip_util, util
from duoauthproxy.lib.config_error import ConfigError
from duoauthproxy.lib.radius import base
from duoauthproxy.lib.validation.connectivity.connectivity_results import (
    ConfigCheckResult,
    InvalidConfigKeyProblem,
    MissingConfigKeyProblem,
    RadiusClientResult,
)
from duoauthproxy.lib.validation.connectivity.connectivity_toolbox import (
    STANDARD_TOOLBOX,
)


def check_radius_client(config, toolbox=STANDARD_TOOLBOX):
    """
    Checks a radius client section config by testing
      1) The config is valid
      2) We can connect via TCP to the host
    Args:
        config: A ConfigDict for an radius client module
        toolbox: a ConnectivityTestToolbox for doing individual connectivity tests
    Returns:
        RadiusClientResult with the results of the testing
    """
    radius_connections = []
    addrs = util.get_addr_port_pairs(config)
    for host, port in addrs:
        radius_result = _connect_radius(host, port, config, toolbox)
        radius_connections.append(radius_result)

    return RadiusClientResult(radius_connections)


def validate_radius_client_config(config):
    """Validate radius client config by ensuring that
    a host ip is provided and valid. A radius secret is given.
    Args:
        config: ConfigDict
    Returns:
        ConfigCheckResult with any config problems
    """
    problems = []

    try:
        config.get_protected_str("secret_protected", "secret")
    except ConfigError:
        problems.append(MissingConfigKeyProblem("secret / secret_protected"))

    try:
        addrs = util.get_addr_port_pairs(config)
    except ConfigError:
        problems.append(MissingConfigKeyProblem("host"))
        return ConfigCheckResult(problems)

    for host, port in addrs:
        valid_ip = ip_util.is_valid_single_ip(host)
        if not valid_ip:
            problems.append(InvalidConfigKeyProblem("radius_ip", host))

    return ConfigCheckResult(problems)


def _connect_radius(host, port, config, toolbox):
    """Spin up test client and send a Status-Server packet to check if we can reach the radius server"""
    secret = config.get_protected_str("secret_protected", "secret").encode()
    client = Client(
        server=host, authport=port, secret=secret, dict=base.radius_dictionary()
    )
    client.timeout = const.DEFAULT_RADIUS_RETRY_WAIT

    request = client.CreateAuthPacket(code=pyrad.packet.StatusServer)

    # The request must contain a message authenticator.
    request.add_message_authenticator()

    try:
        nas_ip = config.get_str("nas_ip")
    except ConfigError:
        nas_ip = util.get_authproxy_ip()
    request.AddAttribute("NAS-IP-Address", nas_ip)

    return toolbox.test_connect_radius(client, request)
