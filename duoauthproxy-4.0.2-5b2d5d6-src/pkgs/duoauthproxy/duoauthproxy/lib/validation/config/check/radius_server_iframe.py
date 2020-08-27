import functools

from duoauthproxy.lib.validation.connectivity.connectivity_results import ConfigCheckResult
from duoauthproxy.lib.validation.config.config_toolbox import STANDARD_CONFIG_TOOLBOX
from duoauthproxy.lib.validation.config.check import base
from duoauthproxy.lib.validation.config.config_results import MissingKey
from duoauthproxy.modules.radius_server_iframe import JS_TYPES


def check_radius_server_iframe(config, toolbox=STANDARD_CONFIG_TOOLBOX):
    """
    Validates the [radius_server_iframe] section of the auth proxy config.

    Args:
        config (ConfigDict): The radius server iframe config to check
        toolbox (ConfigTestToolbox): Toolbox used to execute the tests

    Returns:
        ConfigCheckResult containing any configuration errors
    """
    problems = check_required_keys(config, toolbox)
    problems += check_config_values(config, toolbox)
    problems += check_config_dependencies(config, toolbox)

    return ConfigCheckResult(problems)


def check_required_keys(config, toolbox):
    """ Validates that all required keys for an [radius_server_auto] section are present in the config.

    Args:
        config (ConfigDict): The config object to check the required config for
        toolbox (ConfigTestToolbox): Toolbox used to execute the tests

    Returns:
        list of ConfigResults
    """
    problems = base.check_common_required_radius_keys(config, toolbox)

    if not toolbox.test_config_has_key(config, 'type'):
        problems.append(MissingKey(key='type'))

    return problems


def check_config_values(config, toolbox):
    """ Validates the values for provided config in the [radius_server_iframe] section

    Args:
        config (ConfigDict): The config object to check the optional config for
        toolbox (ConfigTestToolbox): Toolbox used to execute the tests

    Returns:
        list of ConfigResults
    """

    problems = []
    config_test_resolver = base.get_basic_radius_server_resolver(config, toolbox)

    # Add radius server iframe specific keys
    config_test_resolver.update({
        'type': functools.partial(toolbox.test_valid_enum, enum=JS_TYPES, transform=str.lower),
        'iframe_script_uri': toolbox.test_is_string,
        'script_inject': toolbox.test_is_string,
    })

    problems += base.run_config_value_checks(config, config_test_resolver)

    problems += base.check_for_unexpected_keys(config, toolbox, config_test_resolver)

    problems += base.check_basic_radius_server_protected_usage(config, toolbox)

    return problems


def check_config_dependencies(config, toolbox):
    """ Validates dependencies between config options within an [radius_server_auto] section

    Args:
        config (ConfigDict): The config object to validate dependencies on

    Returns:
        list of ConfigResults

    """
    problems = base.check_radius_secret_radius_ip_balance(config)
    problems += base.check_basic_server_config_dependencies(config, toolbox)

    return problems
