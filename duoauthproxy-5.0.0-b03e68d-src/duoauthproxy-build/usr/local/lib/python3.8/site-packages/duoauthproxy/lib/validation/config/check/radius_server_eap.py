import functools

from duoauthproxy.lib.validation.config.check import base
from duoauthproxy.lib.validation.config.config_results import MissingKey, UnexpectedKey
from duoauthproxy.lib.validation.config.config_toolbox import STANDARD_CONFIG_TOOLBOX
from duoauthproxy.lib.validation.connectivity.connectivity_results import (
    ConfigCheckResult,
)


def check_radius_server_eap(config, toolbox=STANDARD_CONFIG_TOOLBOX):
    """
    Validates the [radius_server_eap] section of the auth proxy config.

    Args:
        config (ConfigDict): The radius server auto config to check
        toolbox (ConfigTestToolbox): Toolbox used to execute the tests

    Returns:
        ConfigCheckResult containing any configuration errors
    """
    problems = check_required_keys(config, toolbox)
    problems += check_config_values(config, toolbox)
    problems += check_config_dependencies(config, toolbox)

    return ConfigCheckResult(problems)


def check_required_keys(config, toolbox):
    """
    Validates that all required keys for an [radius_server_eap] section
    are present in the config.

    Args:
        config (ConfigDict): The config object to check the required config for
        toolbox (ConfigTestToolbox): Toolbox used to execute the tests

    Returns:
        list of ConfigResult
    """
    problems = []
    for key in ("ikey", "api_host", "certs", "pkey"):
        if not toolbox.test_config_has_key(config, key):
            problems.append(MissingKey(key=key))

    for key in ["skey"]:
        if not toolbox.test_config_has_key(config, key, optionally_protected=True):
            problems.append(MissingKey(key=key))

    if not toolbox.test_config_has_any_dynamic_key(
        config, "radius_secret", optionally_protected=True
    ):
        problems.append(MissingKey(key="radius_secret_1"))

    if not toolbox.test_config_has_any_dynamic_key(config, "radius_ip"):
        problems.append(MissingKey(key="radius_ip_1"))

    # we can't use the base keys for these two keys because radius sections
    # are a bit quirky
    if toolbox.test_config_has_key(config, "radius_ip"):
        problems.append(UnexpectedKey(key="radius_ip"))

    if toolbox.test_config_has_key(config, "radius_secret", optionally_protected=True):
        problems.append(UnexpectedKey(key="radius_secret / radius_secret_protected"))

    return problems


def check_config_values(config, toolbox):
    """
    Validates the values for provided config in the [radius_server_eap]
    section

    Args:
        config (ConfigDict): The config object to check the optional config for
        toolbox (ConfigTestToolbox): Toolbox used to execute the tests

    Returns:
        list of ConfigResult
    """
    problems = []
    config_test_resolver = base.get_basic_config_resolver(toolbox)

    # Add radius server eap specific keys
    config_test_resolver.update(
        {
            "ikey": toolbox.test_is_ikey,
            "skey": toolbox.test_is_skey,
            "skey_protected": toolbox.test_is_string,
            "api_host": toolbox.test_is_string,
            "client": toolbox.test_is_string,
            "certs": toolbox.test_file_readable,
            "pkey": toolbox.test_file_readable,
            "port": toolbox.test_valid_port,
            "interface": toolbox.test_is_valid_single_ip,
            "factors": functools.partial(
                toolbox.test_valid_permutation,
                enum=["auto", "push", "phone", "passcode"],
                separator=",",
                repeats=False,
            ),
            "failmode": functools.partial(
                toolbox.test_valid_enum, enum=["safe", "secure"], transform=str.lower
            ),
            "minimum_tls_version": toolbox.test_is_tls_version,
            "cipher_list": toolbox.test_is_cipher_list,
            "prompt": toolbox.test_is_string,
            "allow_concat": toolbox.test_is_bool,
            "delimiter": toolbox.test_is_string,
            "delimited_password_length": toolbox.test_is_positive_int,
            "pass_through_attr_names": toolbox.test_is_string,
            "pw_codec": toolbox.test_is_codec,
            "client_ip_attr": toolbox.test_is_string,
            "http_proxy_host": toolbox.test_is_string,
            "http_proxy_port": toolbox.test_valid_port,
            "pass_through_all": toolbox.test_is_bool,
        }
    )

    dynamic_test_resolver = {
        "radius_ip": toolbox.test_is_valid_ip,
        "radius_secret": toolbox.test_is_string,
        "radius_secret_protected": toolbox.test_is_string,
    }

    base.add_dynamic_keys_to_test_resolver(
        config, config_test_resolver, dynamic_test_resolver
    )
    problems += base.run_config_value_checks(config, config_test_resolver)
    problems += base.check_for_unexpected_keys(config, toolbox, config_test_resolver)
    problems += base.check_basic_radius_server_protected_usage(config, toolbox)
    return problems


def check_config_dependencies(config, toolbox):
    problems = base.check_radius_secret_radius_ip_balance(config)
    problems += base.check_basic_server_config_dependencies(config, toolbox)
    return problems
