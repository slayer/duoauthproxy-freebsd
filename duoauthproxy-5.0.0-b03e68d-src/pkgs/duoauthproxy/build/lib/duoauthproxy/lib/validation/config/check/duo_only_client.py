#
# Copyright (c) 2018 Duo Security
# All Rights Reserved
#
from duoauthproxy.lib.validation.config.check import base
from duoauthproxy.lib.validation.config.config_toolbox import STANDARD_CONFIG_TOOLBOX
from duoauthproxy.lib.validation.connectivity.connectivity_results import (
    ConfigCheckResult,
)


def check_duo_only_client(config, toolbox=STANDARD_CONFIG_TOOLBOX):
    """Validates a [duo_only_client] section of an authproxy config.
    It should have no key-value pairs, other than possibly anything
    passed down from [main].

    Args:
        config (ConfigDict): The ad_client section config to check
        toolbox (ConfigTestToolbox): Toolbox used to execute the tests
    Returns:
        ConfigCheckResult
    """
    problems = []
    config_test_resolver = base.get_basic_config_resolver(toolbox)

    problems += base.check_for_unexpected_keys(config, toolbox, config_test_resolver)
    problems += base.run_config_value_checks(config, config_test_resolver)

    return ConfigCheckResult(problems)
