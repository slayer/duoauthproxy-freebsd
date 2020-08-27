#
# Copyright (c) 2018 Duo Security
# All Rights Reserved
#
"""
This module provides functions that performs Duo cloud specific checks
"""

import platform
import duo_client
import duoauthproxy
from duoauthproxy.lib.validation.connectivity.connectivity_results import (
    ConfigProblemSkippedTestResult,
    UnmetPrerequisiteSkippedTestResult,
    BAD_PROTECTED_SKEY_RESULT
)

# measured in seconds
DEFAULT_TIMEOUT = 10


def perform_duo_ping(toolbox,
                     api_host,
                     skey="",
                     ikey="",
                     ca_path="",
                     timeout=DEFAULT_TIMEOUT,
                     http_proxy=None):
    """
    Pings the Duo cloud service

    Args:
        toolbox (ConnectivityTestToolbox): the test toolbox
        api_host (str): a Duo host
        skey (str): a Duo skey
        ikey (str): a Duo ikey
        ca_path (str): path to certs
        timeout (float): desired timeout, in seconds, of any api calls
        http_proxy (tuple(string, int)): None, or an http proxy host and port for the Duo client to use

    Returns:
        DuoPingResult or ConfigProblemSkippedTestResult: result of ping check
    """
    client = _get_duo_api_client(api_host, skey, ikey, ca_path, timeout, http_proxy)

    if api_host:
        ping_result = toolbox.test_ping_duo(client)
    else:
        ping_result = ConfigProblemSkippedTestResult('ping', 'api_host')

    return ping_result


def perform_time_drift(toolbox,
                       ping_result,
                       api_host,
                       skey="",
                       ikey="",
                       ca_path="",
                       timeout=DEFAULT_TIMEOUT,
                       http_proxy=None):
    """
    Detects the time drift between the Duo cloud and the machine running the auth proxy

    Args:
        toolbox (ConnectivityTestToolbox): the test toolbox
        ping_result (DuoPingResult): the results of the Duo Ping
        api_host (str): a Duo host
        skey (str): a Duo skey
        ikey (str): a Duo ikey
        ca_path (str): path to certs
        timeout (float): desired timeout, in seconds, of any api calls
        http_proxy (tuple(string, int)): None, or an http proxy host and port for the Duo client to use

    Returns:
        TimeDriftResult or UnmetPrerequisiteSkippedTestResult: return of time drift check
    """
    client = _get_duo_api_client(api_host, skey, ikey, ca_path, timeout, http_proxy)

    if ping_result.is_successful():
        time_drift_result = toolbox.test_time_drift(client)
    else:
        time_drift_result = UnmetPrerequisiteSkippedTestResult('time drift', 'ping')

    return time_drift_result


def perform_credentials_check(toolbox,
                              api_host,
                              skey="",
                              ikey="",
                              ca_path="",
                              timeout=DEFAULT_TIMEOUT,
                              http_proxy=None):
    """
    Validates Duo credentials against the Duo Cloud

    Args:
        toolbox (ConnectivityTestToolbox): the test toolbox
        api_host (str): a Duo host
        skey (str): a Duo skey
        ikey (str): a Duo ikey
        ca_path (str): path to certs
        timeout (float): desired timeout, in seconds, of any api calls
        http_proxy (tuple(string, int)): None, or an http proxy host and port for the Duo client to use

    Returns:
        ValidateApiCredentialsResult or
        BAD_PROTECTED_SKEY_RESULT or
        ConfigProblemSkippedTestResult
    """
    client = _get_duo_api_client(api_host, skey, ikey, ca_path, timeout, http_proxy)

    if ikey and skey and api_host:
        credentials_check_result = toolbox.test_validate_api_credentials(client)
    elif skey is None:
        credentials_check_result = BAD_PROTECTED_SKEY_RESULT
    else:
        credentials_check_result = ConfigProblemSkippedTestResult('validate api credentials', 'api credentials')

    return credentials_check_result


def _get_duo_api_client(api_host, skey="", ikey="", ca_path="", timeout=DEFAULT_TIMEOUT, http_proxy=None):
    """
    Build a Duo api client to be used for connectivity checks

    Args:
        api_host (str): a Duo host
        skey (str): a Duo skey
        ikey (str): a Duo ikey
        ca_path (str): path to ca certs
        timeout (float): desired timeout, in seconds, of any api calls

    Returns:
        duo_client.Auth: duo api client
    """

    user_agent = "duoauthproxy connectivity tool/{0}; ({1})".format(
        duoauthproxy.__version__,
        platform.platform())

    client = duo_client.Auth(ikey, skey, api_host, user_agent=user_agent, ca_certs=ca_path, timeout=timeout)
    if http_proxy:
        proxy_host, proxy_port = http_proxy
        client.set_proxy(proxy_host, proxy_port)

    return client
