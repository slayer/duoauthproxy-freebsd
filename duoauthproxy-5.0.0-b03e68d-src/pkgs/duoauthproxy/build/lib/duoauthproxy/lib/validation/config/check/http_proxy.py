from duoauthproxy.lib.validation.config.check import base
from duoauthproxy.lib.validation.config.config_results import MissingKey
from duoauthproxy.lib.validation.config.config_toolbox import STANDARD_CONFIG_TOOLBOX
from duoauthproxy.lib.validation.connectivity.connectivity_results import (
    ConfigCheckResult,
)


def check_http_proxy(config, toolbox=STANDARD_CONFIG_TOOLBOX):
    """
    Validates the [http_proxy] section of the auth proxy config.

    Args:
        config (ConfigDict): The http proxy config to check
        toolbox (ConfigTestToolbox): Toolbox used to execute the tests

    Returns:
        ConfigCheckResult containing any configuration errors
    """
    problems = check_required_keys(config, toolbox)
    problems += check_config_values(config, toolbox)

    return ConfigCheckResult(problems)


def check_required_keys(config, toolbox):
    """
    Validates that all required keys for an [http_proxy] section
    are present in the config.

    Args:
        config (ConfigDict): The config object to check the required config for
        toolbox (ConfigTestToolbox): Toolbox used to execute the tests

    Returns:
        list of ConfigResult
    """
    problems = []
    if not toolbox.test_config_has_key(config, "api_host"):
        problems.append(MissingKey(key="api_host"))
    return problems


def check_config_values(config, toolbox):
    """
    Validates the values for provided config in the [http_proxy]
    section

    Args:
        config (ConfigDict): The config object to check the optional config for
        toolbox (ConfigTestToolbox): Toolbox used to execute the tests

    Returns:
        list of ConfigResult
    """
    problems = []
    config_test_resolver = base.get_basic_config_resolver(toolbox)

    # Add http proxy specific keys
    config_test_resolver.update(
        {
            "api_host": toolbox.test_is_string,
            "port": toolbox.test_valid_port,
            "client_ip": toolbox.test_ip_range,
            "interface": toolbox.test_is_valid_single_ip,
        }
    )

    problems += base.run_config_value_checks(config, config_test_resolver)
    problems += base.check_for_unexpected_keys(config, toolbox, config_test_resolver)
    return problems
