from duoauthproxy.lib import util
from duoauthproxy.lib import ip_util
from duoauthproxy.lib import config_provider

from duoauthproxy.lib.validation.connectivity.connectivity_results import ConfigCheckResult
from duoauthproxy.lib.validation.config.config_results import (
    KeyIncompatibleWithSection,
    NetworkContention,
    InvalidClientServerMapping,
    PortCollision,
    KeyInvalidWithClient,
    IneffectiveConfig,
    SameSectionPortCollision,
)


CLIENT_KEY = 'client'


def check_cross_config(config):
    """
    Validates across sections of the auth proxy config.

    Args:
        config (ConfigDict): The full config
        toolbox (ConfigTestToolbox): Toolbox used to execute the tests

    Returns:
        ConfigCheckResult containing any configuration errors
    """
    problems = (
        check_http_proxy_cross_config(config) +
        check_network_contention(config) +
        check_server_client_mapping(config) +
        check_port_contention_for_ldap(config) +
        check_pass_through_attrs(config) +
        check_minimum_tls_version_with_fips_mode(config)
    )
    return ConfigCheckResult(problems)


def check_http_proxy_cross_config(config):
    """
    Validates that there is not both an http proxy section and an http proxy
    host specified in the main section

    Args:
        config (ConfigDict): The config object used for this check

    Returns:
        list of BaseResult
    """
    problems = []
    sections = config.get_all_sections()
    if 'main' in sections:
        if 'http_proxy_host' in sections.get('main'):
            for section in sections:
                if section.startswith('http_proxy'):
                    problems.append(KeyIncompatibleWithSection(key1='http_proxy_host', key2=section))

    return problems


def check_network_contention(config):
    problems = []
    listeners = _radius_listeners_map(config)

    # poping through this list to prevent double-counting
    while listeners:
        l1 = listeners.pop()
        for l2 in listeners:
            if l1.conflicts_with(l2):
                # Get the most specific interface conflict we can
                if l1.interface != '*':
                    conflicting_interface = l1.interface
                else:
                    conflicting_interface = l2.interface

                problems.append(
                    NetworkContention(section1=l1.section,
                                      section2=l2.section,
                                      interface=conflicting_interface,
                                      port=l1.port, ip1=l1.ip_str,
                                      ip2=l2.ip_str)
                )

    return problems


def _get_section_radius_listeners(config, section_name):
    """ Create listener object for each radius_ip entry in a section
    Args:
        config (ConfigDict): The raw config section
        section_name (str): The name of the config section
    Returns:
        A list of listener objects
    """
    port = config.get_int('port', 1812)
    interface = config.get('interface', '*')
    all_networks = []
    listeners = []
    for ip_key in util.get_dynamic_keys(config, 'radius_ip'):
        try:
            ip_str = config.get_str(ip_key)
            ip_networks = ip_util.get_ip_networks(ip_str)
            all_networks.append(ip_networks)
            listeners.append(RadiusListener(ip_networks, ip_str, port, interface, section_name))
        except Exception:
            # we just silently ignore badly formatted IP strings since that will
            # reported by other parts of the validator
            pass

    return listeners


def _radius_listeners_map(full_configuration):
    radius_listeners = []
    for section_name, config in full_configuration.get_all_sections().items():
        if section_name.startswith('radius_server'):
            radius_listeners += _get_section_radius_listeners(config, section_name)

    return radius_listeners


class RadiusListener(object):
    def __init__(self, ip_networks, ip_str, port, interface, section):
        self.ip_str = ip_str
        self.ip_networks = ip_networks
        self.port = port
        self.interface = interface
        self.section = section

    def conflicts_with(self, listener2):
        if self.section == listener2.section:
            return False

        if self.port == listener2.port:
            if self.interface == '*' or listener2.interface == '*' or self.interface == listener2.interface:
                for ip1 in self.ip_networks:
                    for ip2 in listener2.ip_networks:
                        if ip1 in ip2 or ip2 in ip1:
                            return True
        return False


class LDAPListener(object):
    def __init__(self, interface, port, section):
        self.interface = interface
        self.port = port
        self.section = section

    def conflicts_with(self, listener2):
        if self.port == listener2.port:
            if self.interface == '*' or listener2.interface == '*' or self.interface == listener2.interface:
                return True
        return False


def check_port_contention_for_ldap(full_configuration):
    """Check if the same port and interface are re-used across multiple LDAP sections
    Args:
        ConfigProvider: full_configuration
    Returns:
        List of ConfigResults
    """
    problems = []
    listeners = _get_ldap_listeners(full_configuration)

    # poping through this list to prevent double-counting
    while listeners:
        l1 = listeners.pop()
        for l2 in listeners:
            if l1.conflicts_with(l2):
                # Get the most specific interface conflict we can
                if l1.interface != '*':
                    conflicting_interface = l1.interface
                else:
                    conflicting_interface = l2.interface

                if l1.section == l2.section:
                    problems.append(
                        SameSectionPortCollision(section=l1.section,
                                                 port=l1.port)
                    )
                else:
                    sections = [l1.section, l2.section]
                    problems.append(
                        PortCollision(sections=sections,
                                      interface=conflicting_interface,
                                      port=l1.port)
                    )

    return problems


def _get_ldap_listeners(full_configuration):
    """ Return a listener objects for all ldap sections
        Args:
            full_configuration (ConfigProvider)
        Returns
            [LDAPListener] listener for each LDAP port in the config
    """
    listeners = []
    for section_name, config in full_configuration.get_all_sections().items():
        if section_name.startswith('ldap_server'):
            interface = config.get_str('interface', '*')
            clear_port = config.get_int('port', 389)
            listeners.append(LDAPListener(interface, clear_port, section_name))
            if 'ssl_key_path' in config and 'ssl_cert_path' in config:
                ssl_port = config.get_int('ssl_port', 636)
                listeners.append(LDAPListener(interface, ssl_port, section_name))

    return listeners


def check_server_client_mapping(config):
    """
    Validates that all of the configured server sections map to a valid
    client configuration.

    Args:
        config (ConfigDict): The config object used for this check

    Returns:
        list of BaseResult
    """
    problems = []
    clients = [k for k in config.list_sections() if CLIENT_KEY in k]

    # It's possible that a client is configured in the main section
    for section, section_config in config.get_all_sections().items():
        # Only check server sections
        if config_provider.get_module_type(section) != 'server':
            continue

        if section.startswith('radius_server_duo_only') and 'client' in section_config:
            problems.append(IneffectiveConfig(key='client',
                                              section=section,
                                              condition='in this type of section'))

        client_name = config.get_section_client(section)

        if client_name:
            if client_name not in clients:
                problems.append(
                    InvalidClientServerMapping(client_name=client_name,
                                               section=section))

            if not client_name.startswith('ad_client') and section.startswith('ldap_server_auto'):
                problems.append(
                    InvalidClientServerMapping(client_name=client_name,
                                               section=section))

        elif not section.startswith('radius_server_duo_only'):
            problems.append(
                InvalidClientServerMapping(client_name=client_name,
                                           section=section))
    return problems


def check_pass_through_attrs(config):
    """
    Validates that all sections which have `pass_through_attr` names also have
    a radius client.

    Args:
        config (ConfigDict): The config object used for this check

    Returns:
        list of BaseResult
    """
    problems = []
    for section, section_config in config.get_all_sections().items():
        if 'pass_through_attr_names' in section_config:
            client_name = config.get_section_client(section)
            if client_name and not client_name.startswith('radius_client'):
                problems.append(KeyInvalidWithClient(key='pass_through_attr_names', client=client_name))

    return problems


def check_minimum_tls_version_with_fips_mode(config):
    """
    Checks if any ldap_server_auto or radius_server_eap sections have the
    minimum_tls_version config specified while fips_mode is enabled. If they
    do, a warning is returned indicating that the minimum_tls_version config
    will not have any effect.

    Args:
        config (ConfigDict): The config object to use for this check

    Returns:
        list of BaseResult
    """
    problems = []
    main_config = config.get_main_section_config()
    if main_config and main_config.get_bool('fips_mode', False):
        for section, section_config in config.get_all_sections().items():
            if section.startswith('ldap_server_auto') or section.startswith('radius_server_eap'):
                if 'minimum_tls_version' in section_config:
                    problems.append(IneffectiveConfig(key='minimum_tls_version',
                                                      section=section,
                                                      condition='fips_mode is enabled'))

    return problems
