""" Common methods and variables shared by the check modules """
import functools

from duoauthproxy.lib import util
from duoauthproxy.lib.validation.config.config_results import (
    DeprecatedKey,
    IncompatibleKeys,
    InvalidProtectedValue,
    InvalidValue,
    MissingKey,
    ProtectUnavailable,
    UnexpectedKey,
    UnpairedKey,
)

# List of keys that were once valid, but are no longer used
DEPRECATED_KEYS = [
    "domain_discovery",
]


def get_basic_config_resolver(toolbox):
    """ Return a resolver with the config shared between all sections and the right toolbox methods attached
    Args:
        toolbox (ConfigTestToolbox): Toolbox used to execute the tests
    Returns:
        dict of config value => toolbox method
    """
    return {
        "debug": toolbox.test_is_bool,
        "http_ca_certs_file": toolbox.test_file_readable,
    }


def get_basic_radius_server_resolver(config, toolbox):
    """ Return a resolver with the shared radius server keys and the right toolbox methods attached
    Args:
        toolbox (ConfigTestToolbox): Toolbox used to execute the tests
    Returns:
        dict of config value => toolbox method
    """
    config_test_resolver = get_basic_config_resolver(toolbox)
    config_test_resolver.update(
        {
            "ikey": toolbox.test_is_ikey,
            "skey": toolbox.test_is_skey,
            "skey_protected": toolbox.test_is_string,
            "api_host": toolbox.test_is_string,
            "client": toolbox.test_is_string,
            "api_timeout": toolbox.test_is_positive_int,
            "failmode": functools.partial(
                toolbox.test_valid_enum, enum=["safe", "secure"], transform=str.lower
            ),
            "port": toolbox.test_valid_port,
            "interface": toolbox.test_is_valid_single_ip,
            "pass_through_attr_names": toolbox.test_is_string,
            "pass_through_all": toolbox.test_is_bool,
            "pw_codec": toolbox.test_is_codec,
            "client_ip_attr": toolbox.test_is_string,
            "api_port": toolbox.test_valid_port,
            "http_proxy_host": toolbox.test_is_string,
            "http_proxy_port": toolbox.test_valid_port,
        }
    )

    dynamic_test_resolver = {
        "radius_ip": toolbox.test_is_valid_ip,
        "radius_secret": toolbox.test_is_string,
        "radius_secret_protected": toolbox.test_is_string,
        "exempt_username": toolbox.test_is_string,
    }

    add_dynamic_keys_to_test_resolver(
        config, config_test_resolver, dynamic_test_resolver
    )

    return config_test_resolver


def add_dynamic_keys_to_test_resolver(
    config, config_test_resolver, dynamic_test_resolver
):
    """Add the dynamic keys and their testers to the config_test_resolver
    Args:
        config (ConfigDict): The config object to check
        config_test_resolver (Dict): All the known config options tied to their tester
        dynamic_test_resolver (Dict): The stems of the dynamic keys tied to the tester for that key
    """
    for stem in dynamic_test_resolver:
        for key in util.get_dynamic_keys(config, stem):
            config_test_resolver[key] = dynamic_test_resolver[stem]


def check_for_unexpected_keys(config, toolbox, config_test_resolver):
    """ Checks for all unexpected keys in a configuration
    Args:
        config (ConfigDict): The config object to check
        toolbox (ConfigTestToolbox): Toolbox used to execute the tests
        config_test_resolver (Dict): All the known config options tied to their tester
    Returns:
        list of ConfigProblems
    """
    problems = []
    all_keys = config_test_resolver.keys()
    unexpected_keys = toolbox.get_unexpected_keys_present(config, all_keys, [])
    for key in unexpected_keys:
        if key in DEPRECATED_KEYS:
            problems.append(DeprecatedKey(key=key))
        else:
            problems.append(UnexpectedKey(key=key))

    return problems


def check_common_required_radius_keys(config, toolbox):
    """ Validates that all required keys for an [radius_server_*] section are present in the config.
    Any radius server section specific keys must be checked after.

    Args:
        config (ConfigDict): The config object to check the required config for
        toolbox (ConfigTestToolbox): Toolbox used to execute the tests

    Returns:
        list of ConfigResults
    """
    problems = []
    for key in ("ikey", "api_host"):
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


def run_config_value_checks(config, config_test_resolver):
    """Uses a configuration_test_resolver to check all the values of a config
    Args:
        config (ConfigDict): The config object to check the required config for
        config_test_resolver (Dict): All the known config options tied to their tester
    Returns:
        list of InvalidValues
    """
    problems = []
    for key in config_test_resolver:
        if key in config:
            if not config_test_resolver[key](config, key):
                problems.append(InvalidValue(key=key, value=config.get(key)))

    return problems


def check_radius_secret_radius_ip_balance(config):
    """ Validates a perfect matching between radius_ip_# and radius_secret_#
    Args:
        config (ConfigDict): The config object to validate dependencies on
    Returns:
        list of ConfigResult

    """
    problems = []

    (
        radius_ip_numbers,
        radius_secret_numbers,
        radius_secret_protected_numbers,
    ) = get_radius_ip_secret_numbers(config)

    for overlapped_key in radius_secret_numbers.intersection(
        radius_secret_protected_numbers
    ):
        secret_key = "radius_secret_" + overlapped_key
        protected_secret_key = "radius_secret_protected_" + overlapped_key
        problems.append(IncompatibleKeys(key1=secret_key, key2=protected_secret_key))

    radius_secret_numbers.update(radius_secret_protected_numbers)
    for radius_ip in radius_ip_numbers.difference(radius_secret_numbers):
        problems.append(
            UnpairedKey(
                key1="radius_secret_" + radius_ip, key2="radius_ip_" + radius_ip
            )
        )

    for radius_secret in radius_secret_numbers.difference(radius_ip_numbers):
        problems.append(
            UnpairedKey(
                key1="radius_ip_" + radius_secret, key2="radius_secret_" + radius_secret
            )
        )

    return problems


def get_radius_ip_secret_numbers(config):
    """
    Get a set of numbers corresponding tot he radius ip and radius secret keys
    present in the config

    Args:
        config: The ConfigDict to test

    Returns:
        Set of numbers on radius ip and set of numbers on radius secret

    """
    keys = list(config.keys())
    radius_ip_numbers = util.extract_numbers(keys, "radius_ip_")
    radius_secret_numbers = util.extract_numbers(keys, "radius_secret_")
    radius_secret_protected_numbers = util.extract_numbers(
        keys, "radius_secret_protected_"
    )

    return (radius_ip_numbers, radius_secret_numbers, radius_secret_protected_numbers)


def check_basic_server_config_dependencies(config, toolbox):
    """Checks all the intra config dependencies common in server sections
    Args:
        config (ConfigDict): the section config to test
        toolbox (ConfigTestToolbox): Toolbox used to execute the tests
    Returns:
        List of ConfigResult
    """
    problems = []
    problems += check_not_both_skey_and_skey_protected(config, toolbox)

    return problems


def check_not_both_skey_and_skey_protected(config, toolbox):
    """ Test that either skey or skey_protected is in config. Not both
    Args:
        config (ConfigDict): the section config to test
        toolbox (ConfigTestToolbox): Toolbox used to execute the tests
    Returns:
        List of ConfigResult
    """
    problems = []
    if not toolbox.test_keys_unpaired(config, "skey", "skey_protected"):
        problems.append(IncompatibleKeys(key1="skey", key2="skey_protected"))

    return problems


def check_protected_usage(config, toolbox, possible_protected_keys):
    """
    1. Intersect possible protected keys and actual protected keys
    2. If that list is non empty make sure protected is even allowed
    3. For each value make sure that we can decrypt it successfully
    Args:
        config (ConfigDict): the section config to test
        toolbox (ConfigTestToolbox): Toolbox used to execute the tests
        possible_protected_keys (list): List of keys that have the option to be protected
    Returns:
        List of ConfigResult
    """
    problems = []

    protected_keys = set(config.keys()) & set(possible_protected_keys)

    if protected_keys and not toolbox.test_is_protect_enabled():
        problems.append(ProtectUnavailable(keys=list(protected_keys)))
        return problems

    for key in protected_keys:
        if not toolbox.test_is_valid_protected_value(config, key):
            problems.append(InvalidProtectedValue(key=key))
    return problems


def check_basic_radius_server_protected_usage(config, toolbox):
    """ Call check_protected_usage with all the keys that are common to any
    radius_server_* section
    """
    possible_protected_keys = ["skey_protected"]
    possible_protected_keys.extend(
        util.get_all_numbered_keys(config, "radius_secret_protected")
    )

    return check_protected_usage(config, toolbox, possible_protected_keys)
