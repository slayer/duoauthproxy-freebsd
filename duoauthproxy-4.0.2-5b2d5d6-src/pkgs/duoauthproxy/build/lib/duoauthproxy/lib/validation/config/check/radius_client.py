from duoauthproxy.lib.config_error import ConfigError
from duoauthproxy.lib import util
from duoauthproxy.lib.validation.config.config_results import MissingKey
from duoauthproxy.lib.validation.connectivity.connectivity_results import ConfigCheckResult
from duoauthproxy.lib.validation.config.config_toolbox import STANDARD_CONFIG_TOOLBOX
from duoauthproxy.lib.validation.config.check import base


def check_radius_client(config, toolbox=STANDARD_CONFIG_TOOLBOX):
    """
    Validates the [radius_client] section of the auth proxy config.

    Args:
        config (ConfigDict): The radius_client section config to check
        toolbox (ConfigTestToolbox): Toolbox used to execute the tests

    Returns:
        ConfigCheckResult containing any configuration errors
    """
    problems = check_required_keys(config, toolbox)
    problems += check_config_values(config, toolbox)
    problems += check_config_dependencies(config, toolbox)

    return ConfigCheckResult(problems)


def check_required_keys(config, toolbox):
    """ Validates that all required keys for an [radius_client] section are present in the config.

    Args:
        config (ConfigDict): The config object to check the required config for
        toolbox (ConfigTestToolbox): Toolbox used to execute the tests

    Returns:
        list of BaseResult
    """
    problems = []
    try:
        util.get_host_list(config)
    except ConfigError:
        problems.append(MissingKey(key='host'))

    if not toolbox.test_config_has_key(config, 'secret', optionally_protected=True):
        problems.append(MissingKey(key='secret/secret_protected'))

    return problems


def check_config_values(config, toolbox):
    """ Validates the values for provided config in the [radius_client] section

    Args:
        config (ConfigDict): The config object to check the optional config for
        toolbox (ConfigTestToolbox): Toolbox used to execute the tests

    Returns:
        list of BaseResult
    """
    problems = []

    config_test_resolver = base.get_basic_config_resolver(toolbox)
    config_test_resolver.update({
        'secret': toolbox.test_is_string,
        'secret_protected': toolbox.test_is_string,
        'retries': toolbox.test_is_positive_int,
        'retry_wait': toolbox.test_is_positive_int,
        'nas_ip': toolbox.test_is_valid_single_ip,
        'pass_through_attr_names': toolbox.test_is_string,
        'pass_through_all': toolbox.test_is_bool,
        'pw_codec': toolbox.test_is_codec,
    })

    dynamic_test_resolver = {
        'host': toolbox.test_is_valid_single_ip,
        'port': toolbox.test_valid_port,
    }
    base.add_dynamic_keys_to_test_resolver(config, config_test_resolver, dynamic_test_resolver)

    problems += base.run_config_value_checks(config, config_test_resolver)

    problems += base.check_for_unexpected_keys(config, toolbox, config_test_resolver)

    possible_protected_keys = ['secret_protected']
    problems += base.check_protected_usage(config, toolbox, possible_protected_keys)

    return problems


def check_config_dependencies(config, toolbox):
    """ Validates dependencies between config options within an [radius_client] section

    Args:
        config (ConfigDict): The config object to validate dependencies on
        toolbox (ConfigTestToolbox): The toolbox used to execute the tests

    Returns:
        list of zero or more MissingKey objects
    """
    problems = []

    # Check that a port given has a matching host
    for port in util.get_dynamic_keys(config, 'port'):
        host = 'host' + port.lstrip('port')
        if not toolbox.test_items_paired(config, port, host):
            problems.append(MissingKey(key=host))

    return problems
