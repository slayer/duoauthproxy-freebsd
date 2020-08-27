import functools

from duoauthproxy.lib import const, ip_util, util
from duoauthproxy.lib.config_error import ConfigError
from duoauthproxy.lib.validation.config.check import base
from duoauthproxy.lib.validation.config.config_results import (
    IncompatibleValues,
    InsecureConfigItem,
    MissingKey,
    SkippedTest,
    UnmetDependency,
)
from duoauthproxy.lib.validation.config.config_toolbox import STANDARD_CONFIG_TOOLBOX
from duoauthproxy.lib.validation.connectivity.connectivity_results import (
    ConfigCheckResult,
)


def check_ad_client(config, toolbox=STANDARD_CONFIG_TOOLBOX):
    """
    Validates the [ad_client] section of the auth proxy config.

    Args:
        config (ConfigDict): The ad_client section config to check
        toolbox (ConfigTestToolbox): Toolbox used to execute the tests

    Returns:
        ConfigCheckResult containing any configuration errors
    """
    problems = check_required_keys(config, toolbox)
    problems += check_config_values(config, toolbox)
    problems += check_config_dependencies(config, toolbox)
    problems += check_ineffective_config_for_auth_type(config, toolbox)

    return ConfigCheckResult(problems)


def check_required_keys(config, toolbox):
    """
    Validates that all required keys for an [ad_client] section are present
    in the config.

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
        problems.append(MissingKey(key="host"))

    # service_account_username, service_account_password are optional
    # for auth_type = AD_AUTH_TYPE_SSPI; mandatory otherwise. Just use
    # get() to fetch the auth_type here in order to bypass validation on
    # the value. Validation will happen in check_config_values and we don't
    # want duplicate errors if the auth_type config is invalid.
    auth_type = config.get("auth_type") or const.AD_AUTH_TYPE_NTLM_V2
    if auth_type.lower() != const.AD_AUTH_TYPE_SSPI:
        if not toolbox.test_config_has_key(config, "service_account_username"):
            problems.append(MissingKey(key="service_account_username"))

        if not toolbox.test_config_has_key(
            config, "service_account_password", optionally_protected=True
        ):
            problems.append(
                MissingKey(
                    key="service_account_password/" "service_account_password_protected"
                )
            )

    if not toolbox.test_config_has_key(config, "search_dn"):
        problems.append(MissingKey(key="search_dn"))

    return problems


def check_config_values(config, toolbox):
    """
    Validates the values for provided config in the [ad_client] section

    Args:
        config (ConfigDict): The config object to check the optional config for
        toolbox (ConfigTestToolbox): Toolbox used to execute the tests

    Returns:
        list of BaseResult
    """
    problems = []
    config_test_resolver = base.get_basic_config_resolver(toolbox)
    config_dict = {
        "service_account_username": toolbox.test_is_string,
        "service_account_password": toolbox.test_is_string,
        "service_account_password_protected": toolbox.test_is_string,
        "search_dn": toolbox.test_dn,
        "security_group_dn": toolbox.test_dn,
        "ldap_filter": toolbox.test_ldap_filter,
        "timeout": toolbox.test_is_int,
        "ssl_ca_certs_file": toolbox.test_file_readable,
        "ssl_verify_hostname": toolbox.test_is_bool,
        "bind_dn": toolbox.test_dn,
        "ntlm_domain": toolbox.test_is_string,
        "ntlm_workstation": toolbox.test_is_string,
        "port": toolbox.test_valid_port,
        "transport": functools.partial(
            toolbox.test_valid_enum, enum=const.AD_TRANSPORTS, transform=str.lower
        ),
        "username_attribute": toolbox.test_is_string,
        "at_attribute": toolbox.test_is_string,
    }
    if util.is_windows_os():
        config_dict["auth_type"] = functools.partial(
            toolbox.test_valid_enum, enum=const.AD_AUTH_TYPES_WIN, transform=str.lower
        )
        config_test_resolver.update(config_dict)
    else:
        config_dict["auth_type"] = functools.partial(
            toolbox.test_valid_enum, enum=const.AD_AUTH_TYPES_NIX, transform=str.lower
        )
        config_test_resolver.update(config_dict)
    dynamic_test_resolver = {
        "host": toolbox.test_is_string,
    }
    base.add_dynamic_keys_to_test_resolver(
        config, config_test_resolver, dynamic_test_resolver
    )

    problems += base.run_config_value_checks(config, config_test_resolver)

    problems += base.check_for_unexpected_keys(config, toolbox, config_test_resolver)

    possible_protected_keys = ["service_account_password_protected"]
    problems += base.check_protected_usage(config, toolbox, possible_protected_keys)

    return problems


def check_config_dependencies(config, toolbox):
    """
    Validates dependencies between config options within an [ad_client] section

    Args:
        config (ConfigDict): The config object to validate dependencies on
        toolbox (ConfigTestToolbox): The toolbox used to execute the tests

    Returns:

    """
    problems = check_valid_cert_for_transport(config, toolbox)
    problems += check_valid_bind_dn_for_auth_type(config, toolbox)
    problems += check_hostname_verification(config, toolbox)
    return problems


def check_valid_cert_for_transport(config, toolbox):
    """
    Checks that a valid value for transport has been provided and that a certs
    file has been specified if required for the configured transport type.

    Args:
        config (ConfigDict): The config object to check
        toolbox (ConfigTestToolbox): Toolbox used to execute the tests

    Returns:
        list of BaseResult
    """
    problems = []
    try:
        transport_type = config.get_enum(
            "transport", const.AD_TRANSPORTS, const.AD_TRANSPORT_CLEAR, str.lower
        )
        if transport_type in (const.AD_TRANSPORT_LDAPS, const.AD_TRANSPORT_STARTTLS):
            has_cert = toolbox.test_config_has_value(config, "ssl_ca_certs_file")
            if config.get_bool("ssl_verify_hostname", True) and not has_cert:
                problems.append(
                    UnmetDependency(
                        message="ssl_ca_certs_file is required "
                        "for transport type %s" % transport_type
                    )
                )
    except ConfigError:
        problems.append(
            SkippedTest(test=check_valid_cert_for_transport.__name__, key="transport")
        )

    return problems


def check_valid_bind_dn_for_auth_type(config, toolbox):
    """
    Checks that bind_dn has been specified if it's required for the specified
    auth_type.
    Args:
        config (ConfigDict): The config object to check
        toolbox (ConfigTestToolbox): Toolbox used to execute the tests

    Returns:
        list of BaseResult
    """
    problems = []
    try:
        if util.is_windows_os():
            auth_type = config.get_enum(
                "auth_type",
                const.AD_AUTH_TYPES_WIN,
                const.AD_AUTH_TYPE_NTLM_V2,
                str.lower,
            )
        else:
            auth_type = config.get_enum(
                "auth_type",
                const.AD_AUTH_TYPES_NIX,
                const.AD_AUTH_TYPE_NTLM_V2,
                str.lower,
            )
        has_bind_dn = toolbox.test_config_has_value(config, "bind_dn")
        if auth_type == const.AD_AUTH_TYPE_PLAIN and not has_bind_dn:
            problems.append(
                UnmetDependency(
                    message="bind_dn is required for " "auth_type %s" % auth_type
                )
            )
    except ConfigError:
        problems.append(
            SkippedTest(
                test=check_valid_bind_dn_for_auth_type.__name__, key="auth_type"
            )
        )

    return problems


def check_ineffective_config_for_auth_type(config, toolbox):
    """
    Checks if service_account_username and service_account_password provide when authproxy is SSPI.
    SSPI using windows login credentials so no service account credentials needed
    Args:
        config (ConfigDict): The config object to check
        toolbox (ConfigTestToolbox): Toolbox used to execute the tests

    Returns:
        list of BaseResult
    """
    problems = []
    try:
        has_service_account = (
            toolbox.test_config_has_value(config, "service_account_username")
            or toolbox.test_config_has_value(config, "service_account_password")
            or toolbox.test_config_has_value(
                config, "service_account_password_protected"
            )
        )

        auth_type = config.get_enum(
            "auth_type", const.AD_AUTH_TYPES_WIN, const.AD_AUTH_TYPE_NTLM_V2, str.lower
        )

        if auth_type == const.AD_AUTH_TYPE_SSPI and has_service_account:
            problems.append(
                InsecureConfigItem(
                    key="service_account_username and/or service_account_password",
                    condition="in most cases service account credentials are not needed in "
                    "the configuration file when the authentication type is SSPI. "
                    "SSPI will instead leverage the local windows "
                    "login credentials.",
                )
            )

    except ConfigError:
        problems.append(
            SkippedTest(
                test=check_ineffective_config_for_auth_type.__name__, key="auth_type"
            )
        )

    return problems


def check_hostname_verification(config, toolbox):
    """
    Checks that a user has a hostname in configured for their host if they have ssl_verify_hostname
    set to true.
    Args:
        config (ConfigDict): The config object to check
        toolbox (ConfigTestToolbox): Toolbox used to execute the tests

    Returns:
        list of BaseResult
    """
    problems = []
    try:
        transport_type = config.get_enum(
            "transport", const.AD_TRANSPORTS, const.AD_TRANSPORT_CLEAR, str.lower
        )

        if transport_type in const.AD_TRANSPORTS_WITH_SSL:
            hosts = util.get_dynamic_keys(config, "host")
            for host in hosts:
                if ip_util.is_valid_single_ip(config.get_str(host)) and config.get_bool(
                    "ssl_verify_hostname"
                ):
                    problems.append(
                        IncompatibleValues(
                            key=host,
                            type="hostname",
                            condition="ssl_verify_hostname is enabled",
                        )
                    )
    except ConfigError:
        problems.append(
            SkippedTest(test=check_hostname_verification.__name__, key="transport")
        )

    return problems
