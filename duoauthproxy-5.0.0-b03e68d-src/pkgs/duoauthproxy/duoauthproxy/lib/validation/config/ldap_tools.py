#
# Copyright (c) 2018 Duo Security
# All Rights Reserved
#

from ldaptor import ldapfilter
from ldaptor.protocols.ldap import distinguishedname as dn


def is_ldap_dn(section_config, key):
    """
    Test if a specified key for a given section config holds a value that is a valid LDAP DN

    Args:
        section_config (ConfigDict): the section config
        key (str): The key to test

    Returns:
        bool: True if the specified key holds a valid LDAP DN; False otherwise

    """
    dn_string = section_config.get(key)
    if dn_string is None:
        return False

    try:
        dn.DistinguishedName(dn_string)
        return True
    except dn.InvalidRelativeDistinguishedName:
        return False


def is_ldap_filter(section_config, key):
    """
    Test if a specified key for a given section config holds a value that is a valid LDAP filter

    Args:
        section_config (ConfigDict): the section config
        key (str): The key to test

    Returns:
        bool: True if the specified key holds a valid LDAP filter; False otherwise

    """
    filter_string = section_config.get(key)
    if filter_string is None:
        return False

    try:
        ldapfilter.parseFilter(filter_string)
        return True
    except ldapfilter.InvalidLDAPFilter:
        return False
