#
# Copyright (c) 2018 Duo Security
# All Rights Reserved
#

import re


def is_key_present(section_config, key):
    """
    Determine if a specified key exists in a given section config

    Args:
        section_config (ConfigDict): The section config to test
        key (str): the key to test

    Returns:
        bool: True if the specified key is present

    """
    return key in section_config


def is_key_usable(section_config, key):
    """
    Determine if a specified key exists, and has a non-blank value, in a given section config

    Args:
        section_config (ConfigDict): The section config to test
        key (str): the key to test

    Returns:
        bool: True if the specified key is present with a non-blank value

    """
    return is_key_present(section_config, key) and section_config.get(key) != ''


def get_unexpected_keys(section_config, fixed_keys, dynamic_keys):
    """
    Get a list of the unexpected keys present in a section config.

    The provided 'dynamic' list should include key prefixes the can appear with trailing numbers
      (i.e. to allow 'radius_ip_1', 'radius_ip_2', include 'radius_ip' in the dynamic list)
    The provided 'fixed' list of keys should include all other keys that can be present in the section

    Args:
        section_config (ConfigDict): the section config to check
        fixed_keys ([str]): the allowed 'fixed' keys
        dynamic_keys ([str]): the allowed 'dynamic' keys

    Returns:
        List(str): the keys present in the section that are not included in the provided fixed/dynamic lists
    """
    present_keys = set(section_config.keys())
    remaining_keys = list(present_keys.difference(set(fixed_keys)))

    to_remove = set()
    for dynamic_key in dynamic_keys:
        for key in remaining_keys:
            if re.match(r'{0}_\d+$'.format(dynamic_key), key):
                to_remove.add(key)

    remaining_keys = list(set(remaining_keys).difference(to_remove))
    return remaining_keys


def are_keys_unpaired(section_config, key_one, key_two):
    """
    Test a provided pair of keys in a given section config to ensure that both are not present in the config.

    Args:
        section_config (ConfigDict): the section config to test
        key_one (str): One key
        key_two (str): The other key

    Returns:
        bool: False if both keys are present, True otherwise

    """
    if not is_key_present(section_config, key_one) or not is_key_present(section_config, key_two):
        return True

    if is_key_usable(section_config, key_one):
        return not is_key_present(section_config, key_two)

    if is_key_usable(section_config, key_two):
        return not is_key_present(section_config, key_one)

    # Both keys present but with blank values
    return False
