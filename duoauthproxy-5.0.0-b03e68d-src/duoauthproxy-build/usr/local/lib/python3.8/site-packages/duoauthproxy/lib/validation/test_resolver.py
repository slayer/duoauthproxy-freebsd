#
# Copyright (c) 2018 Duo Security
# All Rights Reserved
#
import string
from typing import Callable, Dict

from duoauthproxy.lib.config_provider import ConfigDict
from duoauthproxy.lib.validation.config.check import ad_client as ad_client_config
from duoauthproxy.lib.validation.config.check import cloud as cloud_config
from duoauthproxy.lib.validation.config.check import (
    duo_only_client as duo_only_client_config,
)
from duoauthproxy.lib.validation.config.check import http_proxy as http_proxy_config
from duoauthproxy.lib.validation.config.check import (
    ldap_server_auto as ldap_server_auto_config,
)
from duoauthproxy.lib.validation.config.check import main as main_config
from duoauthproxy.lib.validation.config.check import (
    radius_client as radius_client_config,
)
from duoauthproxy.lib.validation.config.check import (
    radius_server_auto as radius_server_auto_config,
)
from duoauthproxy.lib.validation.config.check import (
    radius_server_challenge as radius_server_challenge_config,
)
from duoauthproxy.lib.validation.config.check import (
    radius_server_concat as radius_server_concat_config,
)
from duoauthproxy.lib.validation.config.check import (
    radius_server_duo_only as radius_server_duo_only_config,
)
from duoauthproxy.lib.validation.config.check import (
    radius_server_eap as radius_server_eap_config,
)
from duoauthproxy.lib.validation.config.check import (
    radius_server_iframe as radius_server_iframe_config,
)
from duoauthproxy.lib.validation.config.check import sso as sso_config
from duoauthproxy.lib.validation.config.config_toolbox import ConfigTestToolbox
from duoauthproxy.lib.validation.connectivity.check import (
    ad_client,
    cloud,
    http_proxy,
    ldap_server_auto,
    main,
    radius_client,
    radius_server,
)
from duoauthproxy.lib.validation.connectivity.connectivity_results import (
    INVALID_SECTION_RESULT,
    SKIPPED_SECTION_RESULT,
    BaseResult,
)

SectionTester = Callable[[ConfigDict, ConfigTestToolbox], BaseResult]


def skipping_tester(config: ConfigDict, toolbox: ConfigTestToolbox) -> BaseResult:
    return SKIPPED_SECTION_RESULT


def invalid_section_tester(
    config: ConfigDict, toolbox: ConfigTestToolbox
) -> BaseResult:
    return INVALID_SECTION_RESULT


class BaseTestResolver:
    """
    Abstract base class that provides a way to find a tester function for a given
    auth proxy configuration section name.

    Implementers should define the section_tester_map to tie a section name to a callable
    """

    section_tester_map: Dict[str, SectionTester] = {}

    def find_tester(self, section_name: str) -> SectionTester:
        """
        Determine the testing function to use for the given configuration section name

        Args:
            section_name (string): The name to resolve

        Returns:
            function: The testing function to use for testing the specified section

        """
        if self.section_tester_map is None:
            raise NotImplementedError("section_tester_map cannot be None")

        section_type = section_name.lower().rstrip(string.digits)
        # Unrecognized sections return appropriate warning
        if section_type in self.section_tester_map:
            return self.section_tester_map[section_type]
        else:
            return invalid_section_tester


class ConnectivityTestResolver(BaseTestResolver):
    section_tester_map = {
        "main": main.check_main,
        "cloud": cloud.check_cloud,
        "sso": skipping_tester,
        "duo_only_client": skipping_tester,
        "http_proxy": http_proxy.check_http_proxy,
        "ad_client": ad_client.check_ad_client,
        "radius_client": radius_client.check_radius_client,
        "radius_server_auto": radius_server.check_radius_server,
        "radius_server_iframe": radius_server.check_radius_server,
        "radius_server_challenge": radius_server.check_radius_server,
        "radius_server_concat": radius_server.check_radius_server,
        "radius_server_duo_only": radius_server.check_radius_server,
        "radius_server_eap": radius_server.check_radius_server,
        "ldap_server_auto": ldap_server_auto.check_ldap_server_auto,
    }


class ConfigTestResolver(BaseTestResolver):
    section_tester_map = {
        "main": main_config.check_main,
        "cloud": cloud_config.check_cloud,
        "sso": sso_config.check_sso,
        "duo_only_client": duo_only_client_config.check_duo_only_client,
        "http_proxy": http_proxy_config.check_http_proxy,
        "ad_client": ad_client_config.check_ad_client,
        "radius_client": radius_client_config.check_radius_client,
        "radius_server_auto": radius_server_auto_config.check_radius_server_auto,
        "radius_server_challenge": radius_server_challenge_config.check_radius_server_challenge,
        "radius_server_iframe": radius_server_iframe_config.check_radius_server_iframe,
        "radius_server_concat": radius_server_concat_config.check_radius_server_concat,
        "radius_server_duo_only": radius_server_duo_only_config.check_radius_server_duo_only,
        "radius_server_eap": radius_server_eap_config.check_radius_server_eap,
        "ldap_server_auto": ldap_server_auto_config.check_ldap_server_auto,
    }


STANDARD_CONFIG_RESOLVER = ConfigTestResolver()
STANDARD_CONNECTIVITY_RESOLVER = ConnectivityTestResolver()
