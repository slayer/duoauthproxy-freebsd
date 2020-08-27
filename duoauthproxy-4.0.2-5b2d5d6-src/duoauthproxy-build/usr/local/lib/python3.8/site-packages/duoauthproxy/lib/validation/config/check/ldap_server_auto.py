#
# Copyright (c) 2018 Duo Security
# All Rights Reserved
#
import functools

from duoauthproxy.lib.validation.connectivity.connectivity_results import ConfigCheckResult
from duoauthproxy.lib.validation.config import config_results
from duoauthproxy.lib.validation.config.check import base

from duoauthproxy.lib.validation.config.config_toolbox import STANDARD_CONFIG_TOOLBOX


def check_ldap_server_auto(config, toolbox=STANDARD_CONFIG_TOOLBOX):
    """
    Validates an [ldap_server_auto] section config

    Args:
        config (ConfigDict): The section config
        toolbox (ConfigTestToolbox): the toolbox of tester methods

    Returns:
        ConfigCheckResult with all config problems

    """
    problems = []
    problems += _check_required_keys(config, toolbox)
    problems += _check_config_values(config, toolbox)
    problems += _check_config_dependencies(config, toolbox)

    return ConfigCheckResult(problems)


def _check_required_keys(config, toolbox):
    required_key_problems = []

    for key in ('ikey', 'api_host'):
        if not toolbox.test_config_has_key(config, key):
            required_key_problems.append(config_results.MissingKey(key=key))

    for key in ('skey',):
        if not toolbox.test_config_has_key(config, key, optionally_protected=True):
            required_key_problems.append(config_results.MissingKey(key=key))

    return required_key_problems


def _check_config_values(config, toolbox):
    config_value_tests = base.get_basic_config_resolver(toolbox)
    config_value_tests.update({
        'ikey': toolbox.test_is_ikey,
        'skey': toolbox.test_is_skey,
        'skey_protected': toolbox.test_is_string,
        'api_host': toolbox.test_is_string,
        'api_timeout': toolbox.test_is_positive_int,
        'client': toolbox.test_is_string,
        'factors': functools.partial(toolbox.test_valid_permutation,
                                     enum=['auto', 'push', 'phone', 'passcode'], separator=',', repeats=False),
        'failmode': functools.partial(toolbox.test_valid_enum,
                                      enum=['safe', 'secure'], transform=str.lower),
        'port': toolbox.test_valid_port,
        'interface': toolbox.test_is_valid_single_ip,
        'ssl_port': toolbox.test_valid_port,
        'ssl_key_path': toolbox.test_file_readable,
        'ssl_cert_path': toolbox.test_file_readable,
        'exempt_primary_bind': toolbox.test_is_bool,
        'delimiter': toolbox.test_is_string,
        'allow_concat': toolbox.test_is_bool,
        'allow_searches_after_bind': toolbox.test_is_bool,
        'allow_unlimited_binds': toolbox.test_is_bool,
        'minimum_tls_version': toolbox.test_is_tls_version,
        'cipher_list': toolbox.test_is_cipher_list,
        'network_timeout': toolbox.test_is_positive_int,
        'idle_timeout': toolbox.test_is_positive_int,
        'api_port': toolbox.test_valid_port,
        'http_proxy_host': toolbox.test_is_string,
        'http_proxy_port': toolbox.test_valid_port,
        'delimited_password_length': toolbox.test_is_positive_int,
    })

    dynamic_key_tests = {
        'exempt_ou': toolbox.test_dn,
    }

    base.add_dynamic_keys_to_test_resolver(config, config_value_tests, dynamic_key_tests)

    problems = base.run_config_value_checks(config, config_value_tests)
    problems += base.check_for_unexpected_keys(config, toolbox, config_value_tests)
    problems += base.check_protected_usage(config, toolbox, ['skey_protected'])

    return problems


def _check_config_dependencies(config, toolbox):
    dependency_problems = base.check_basic_server_config_dependencies(config, toolbox)

    # ssl_port needs ssl_key_path and ssl_cert_path to work
    if toolbox.test_config_has_value(config, 'ssl_port'):
        for key in ('ssl_key_path', 'ssl_cert_path'):
            if not toolbox.test_config_has_value(config, key):
                dependency_problems.append(config_results.MissingKey(level=config_results.ConfigResultLevel.Warning, key=key))

    # ssl_key_path and ssl_cert_path are both or neither
    if toolbox.test_config_has_value(config, 'ssl_key_path') \
            and not toolbox.test_config_has_value(config, 'ssl_cert_path'):
        dependency_problems.append(config_results.MissingKey(key='ssl_cert_path'))

    if toolbox.test_config_has_value(config, 'ssl_cert_path') \
            and not toolbox.test_config_has_value(config, 'ssl_key_path'):
        dependency_problems.append(config_results.MissingKey(key='ssl_key_path'))

    # allow_unlimited_binds = true means exempt_primary_bind must be false
    if toolbox.test_is_bool(config, 'allow_unlimited_binds') and config.get_bool('allow_unlimited_binds', False) \
            and toolbox.test_is_bool(config, 'exempt_primary_bind') and config.get_bool('exempt_primary_bind', False):
        dependency_problems.append(config_results.IncompatibleKeys(key1='allow_unlimited_binds', key2='exempt_primary_bind'))

    return dependency_problems
