#
# Copyright (c) 2018 Duo Security
# All Rights Reserved
#

from duoauthproxy.lib import const, util
from duoauthproxy.lib.validation.connectivity.connectivity_results import CloudResult
from duoauthproxy.lib.validation.connectivity.connectivity_toolbox import (
    STANDARD_TOOLBOX,
)

from . import base_duo_check


def check_cloud(config, toolbox=STANDARD_TOOLBOX):
    """
    Checks the cloud section config by checking
    1) The config is valid
    2) We can /ping and /check Duo with the provided api host and credentials

    Args:
        config (ConfigDict): Configuration for cloud section
        toolbox (ConnectivityTestToolbox): Toolbox for doing connectivity tests

    Returns:
        CloudResult: the results of checking the cloud config
    """
    ca_certs = config.get_str("http_ca_certs_file", const.DEFAULT_HTTP_CERTS_FILE)
    ca_certs_path = util.resolve_file_path(ca_certs)
    http_proxy = None
    http_proxy_host = config.get_str("http_proxy_host", "")
    if http_proxy_host:
        http_proxy_port = config.get_int("http_proxy_port", 80)
        http_proxy = (http_proxy_host, http_proxy_port)

    api_host = config.get_str("api_host", "")
    ping_result = base_duo_check.perform_duo_ping(
        toolbox, api_host, "", "", ca_certs_path, http_proxy=http_proxy
    )
    time_drift_result = base_duo_check.perform_time_drift(
        toolbox, ping_result, api_host, "", "", ca_certs_path, http_proxy=http_proxy
    )
    # T51092: validate the credentials once an entry point for doing so
    # exists in apiserv. Also update tests exercising this method to account
    # for the additional validation.

    result = CloudResult(ping_result, time_drift_result)
    return result
