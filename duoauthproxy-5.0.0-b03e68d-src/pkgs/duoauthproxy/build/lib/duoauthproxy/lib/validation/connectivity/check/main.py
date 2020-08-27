#
# Copyright (c) 2018 Duo Security
# All Rights Reserved
#
from twisted.internet import defer

from duoauthproxy.lib import const, util
from duoauthproxy.lib.validation.connectivity.connectivity_results import (
    NOT_APPLICABLE_TEST_RESULT,
    MainSectionResult,
)
from duoauthproxy.lib.validation.connectivity.connectivity_toolbox import (
    STANDARD_TOOLBOX,
)


@defer.inlineCallbacks
def check_main(config, toolbox=STANDARD_TOOLBOX):
    """
    Test a main section configuration

    Check if the specified http certificates file (defaulted to conf/ca-bundle.crt) is
    working (can be read, valid certs, etc.)

    Args:
        config (ConfigDict): the main section configuration
        toolbox (ConnectivityTestToolbox): the testing toolbox

    Returns:
        MainSectionResult with the results of the testing

    """
    http_ca_certs = config.get_str("http_ca_certs_file", const.DEFAULT_HTTP_CERTS_FILE)
    http_ca_certs_file = util.resolve_file_path(http_ca_certs)

    cert_result = toolbox.test_ssl_certs(http_ca_certs_file)

    http_proxy_host = config.get_str("http_proxy_host", "")
    http_proxy_port = config.get_int("http_proxy_port", 80)

    if http_proxy_host:
        http_proxy_result = yield toolbox.test_connect_with_http_proxy(
            http_proxy_host, http_proxy_port
        )
    else:
        http_proxy_result = NOT_APPLICABLE_TEST_RESULT

    defer.returnValue(MainSectionResult(cert_result, http_proxy_result))
