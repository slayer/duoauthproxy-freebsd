from duoauthproxy.lib.validation.connectivity.connectivity_results import ConfigCheckResult
from duoauthproxy.lib.validation.config.config_toolbox import STANDARD_CONFIG_TOOLBOX
from duoauthproxy.lib.validation.config.check import base
from duoauthproxy.lib.validation.config.config_results import (
    MissingKey,
)


def check_main(config, toolbox=STANDARD_CONFIG_TOOLBOX):
    """
    Validates the [main] section of the auth proxy config.

    Args:
        config (ConfigDict): The radius server auto config to check
        toolbox (ConfigTestToolbox): Toolbox used to execute the tests

    Returns:
        ConfigCheckResult containing any configuration errors
    """
    problems = check_config_values(config, toolbox)
    problems += check_config_dependencies(config)

    return ConfigCheckResult(problems)


def check_config_values(config, toolbox):
    """ Validates the values for provided config in the [main] section

    Args:
        config (ConfigDict): The config object to check the optional config for
        toolbox (ConfigTestToolbox): Toolbox used to execute the tests

    Returns:
        list of BaseResult
    """
    config_test_resolver = {
        'debug': toolbox.test_is_bool,
        'log_dir': toolbox.test_is_valid_directory,
        'log_auth_events': toolbox.test_is_bool,
        'log_sso_events': toolbox.test_is_bool,
        'log_max_files': toolbox.test_is_positive_int,
        'log_max_size': toolbox.test_is_positive_int,
        'log_file': toolbox.test_is_bool,
        'log_stdout': toolbox.test_is_bool,
        'log_syslog': toolbox.test_is_bool,
        'syslog_facility': toolbox.test_is_string,
        'http_ca_certs_file': toolbox.test_file_readable,
        'interface': toolbox.test_is_valid_single_ip,
        'http_proxy_host': toolbox.test_is_string,
        'http_proxy_port': toolbox.test_valid_port,
        'test_connectivity_on_startup': toolbox.test_is_bool,
        'client': toolbox.test_is_string,
        'fips_mode': toolbox.test_is_bool,
        'server': toolbox.test_is_string,
    }

    problems = base.run_config_value_checks(config, config_test_resolver)
    problems += base.check_for_unexpected_keys(config, toolbox, config_test_resolver)
    return problems


def check_config_dependencies(config):
    """ Validates dependencies between config options within an [main] section

    Args:
        config (ConfigDict): The config object to validate dependencies on

    Returns:
        list of ConfigResults

    """
    problems = []
    if 'http_proxy_port' in config and 'http_proxy_host' not in config:
        problems.append(MissingKey(key='http_proxy_host'))

    return problems
