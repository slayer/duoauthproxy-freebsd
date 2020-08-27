#
# Copyright (c) 2018 Duo Security
# All Rights Reserved
#

from twisted.internet import defer

from duoauthproxy.lib import const, util
from duoauthproxy.lib.validation.connectivity.connectivity_results import (
    NOT_APPLICABLE_TEST_RESULT,
    LdapServerResult,
    UnmetPrerequisiteSkippedTestResult,
)
from duoauthproxy.lib.validation.connectivity.connectivity_toolbox import (
    STANDARD_TOOLBOX,
)
from duoauthproxy.modules.ssl_server import ChainingOpenSSLContextFactory

from . import base_duo_check

"""Module for testing the connectivity of a user's ldap_server_auto section."""


def _call_duo(ikey, skey, api_host, ca_certs_path, toolbox, http_proxy=None):
    """Makes the /ping and /validate calls to Duo API.
    Args:
        ikey, skey, api_host (str): User's Duo creds for this server section
        ca_certs_path (str): Path to user's CA certs file
        toolbox (ConnectivityTestToolbox): to do API call tests with
    Returns:
        results (tuple) containing ping, time drift and validate call results
    """
    ping_result = base_duo_check.perform_duo_ping(
        toolbox, api_host, "", "", ca_certs_path, http_proxy=http_proxy
    )
    time_drift_result = base_duo_check.perform_time_drift(
        toolbox, ping_result, api_host, "", "", ca_certs_path, http_proxy=http_proxy
    )
    check_result = base_duo_check.perform_credentials_check(
        toolbox, api_host, skey, ikey, ca_certs_path, http_proxy=http_proxy
    )

    return ping_result, time_drift_result, check_result


@defer.inlineCallbacks
def _listen_ssl(port, interface, toolbox, ssl_creds):
    """Listens ephemerally to interface:port over SSL.
    Args:
        port (int): port to listen on
        interface (str): interface to listen on
        toolbox (ConnectivityTestToolbox): to do listening tests with
        ssl_creds (dict): contains SSL key/cert paths and ciphers
    Returns:
        dict: [result] True if successful, False otherwise
    """
    key_path = ssl_creds["ssl_key_path"]
    cert_path = ssl_creds["ssl_cert_path"]
    ciphers = ssl_creds["cipher_list"]

    ssl_context_factory = ChainingOpenSSLContextFactory(
        privatekey_filename=key_path,
        certificate_filename=cert_path,
        cipher_list=ciphers,
    )
    result = yield toolbox.test_listen_ssl(port, ssl_context_factory, interface)
    defer.returnValue(result)


@defer.inlineCallbacks
def check_ldap_server_auto(config, toolbox=STANDARD_TOOLBOX):
    """Check an ldap_server_auto section config by checking:
      1) The config is valid
      2) We can /ping and /check Duo with the provided api host and credentials
      3) SSL creds are fine, if they are specified
      4) We can listen on the specified port + interface (plain TCP or SSL)
    Args:
        config (ConfigDict): config for this [ldap_server_auto] section
        toolbox (ConnectivityTestToolbox): for doing individual connectivity tests
    Returns:
        nested result (dict) of testing
    """
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

    ping_result, time_drift_result, validate_result = _call_duo(
        ikey, skey, api_host, ca_certs_path, toolbox, http_proxy=http_proxy
    )

    ssl_key_path = config.get_str("ssl_key_path", "")
    ssl_cert_path = config.get_str("ssl_cert_path", "")
    cipher_list = config.get_str("cipher_list", "")
    minimum_tls_version = config.get_str("minimum_tls_version", "")

    if ssl_key_path and ssl_cert_path:
        ssl_key_path = util.resolve_file_path(ssl_key_path)
        ssl_cert_path = util.resolve_file_path(ssl_cert_path)
        ssl_result = toolbox.test_ssl_credentials(
            ssl_key_path, ssl_cert_path, cipher_list, minimum_tls_version,
        )
        port = config.get_int("ssl_port", const.DEFAULT_LDAPS_PORT)
    else:
        ssl_result = NOT_APPLICABLE_TEST_RESULT
        port = config.get_int("port", const.DEFAULT_LDAP_PORT)

    interface = config.get_str("interface", "")

    ssl_creds = {
        "ssl_key_path": ssl_key_path,
        "ssl_cert_path": ssl_cert_path,
        "cipher_list": cipher_list,
    }

    if not (ssl_key_path and ssl_cert_path):
        listen_result = yield toolbox.test_listen_tcp(port, interface)
    elif ssl_result.is_successful():
        listen_result = yield _listen_ssl(port, interface, toolbox, ssl_creds)
    else:
        listen_result = UnmetPrerequisiteSkippedTestResult(
            "listen", "ssl configuration"
        )

    result = LdapServerResult(
        ping_result, time_drift_result, validate_result, ssl_result, listen_result
    )
    defer.returnValue(result)
