from duoauthproxy.lib.validation.config.check import base
from duoauthproxy.lib.validation.config.config_results import MissingKey
from duoauthproxy.lib.validation.config.config_toolbox import STANDARD_CONFIG_TOOLBOX
from duoauthproxy.lib.validation.connectivity.connectivity_results import (
    ConfigCheckResult,
)


def check_cloud(config, toolbox=STANDARD_CONFIG_TOOLBOX):
    """
    Validates the [cloud] section of the auth proxy config.

    Args:
        config (ConfigDict): The cloud config to check
        toolbox (ConfigTestToolbox): Toolbox used to execute the tests

    Returns:
        ConfigCheckResult containing any configuration errors
    """
    problems = (
        check_required_keys(config, toolbox)
        + check_optional_keys(config, toolbox)
        + check_config_values(config, toolbox)
    )
    return ConfigCheckResult(problems)


def check_required_keys(config, toolbox):
    """
    Validates that all required keys for a [cloud] section are present in
    the config.

    Args:
        config (ConfigDict): The config object to check the required config for
        toolbox (ConfigTestToolbox): Toolbox used to execute the tests

    Returns:
        list of BaseResult
    """
    problems = []
    for key in ["ikey", "api_host"]:
        if not toolbox.test_config_has_key(config, key):
            problems.append(MissingKey(key=key))

    if not toolbox.test_config_has_key(config, "skey", optionally_protected=True):
        problems.append(MissingKey(key="skey"))

    return problems


def check_optional_keys(config, toolbox):
    """
    Validates that all optional keys for a [cloud] section exist if
    any are specified.

    Args:
        config (ConfigDict): The config object to check the required config for
        toolbox (ConfigTestToolbox): Toolbox used to execute the tests

    Returns:
        list of BaseResult
    """
    problems = []
    has_username = toolbox.test_config_has_key(config, "service_account_username")
    has_password = toolbox.test_config_has_key(
        config, "service_account_password", optionally_protected=True
    )

    if has_username and not has_password:
        problems.append(MissingKey(key="service_account_password"))
    elif has_password and not has_username:
        problems.append(MissingKey(key="service_account_username"))
    return problems


def check_config_values(config, toolbox):
    """
    Validates the values for provided config in the [cloud] section

    Args:
        config (ConfigDict): The config object to check the optional config for
        toolbox (ConfigTestToolbox): Toolbox used to execute the tests

    Returns:
        list of BaseResult
    """
    config_test_resolver = base.get_basic_config_resolver(toolbox)
    config_test_resolver.update(
        {
            "ikey": toolbox.test_is_ikey,
            "skey": toolbox.test_is_skey,
            "skey_protected": toolbox.test_is_string,
            "api_host": toolbox.test_is_string,
            "service_account_username": toolbox.test_is_string,
            "service_account_password": toolbox.test_is_string,
            "service_account_password_protected": toolbox.test_is_string,
            "http_proxy_host": toolbox.test_is_string,
            "http_proxy_port": toolbox.test_valid_port,
        }
    )
    return (
        base.run_config_value_checks(config, config_test_resolver)
        + base.check_for_unexpected_keys(config, toolbox, config_test_resolver)
        + base.check_protected_usage(
            config, toolbox, ["skey_protected", "service_account_password_protected"]
        )
    )
