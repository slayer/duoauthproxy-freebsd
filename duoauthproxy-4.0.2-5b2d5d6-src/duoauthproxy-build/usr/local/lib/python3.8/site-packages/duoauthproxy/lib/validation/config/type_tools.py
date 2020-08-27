#
# Copyright (c) 2018 Duo Security
# All Rights Reserved
#


def is_stringable(section_config, key, allow_empty=False):
    """
    Determine if the specified key in a given section config holds a value that can be a string

    Args:
        section_config (ConfigDict): the section config to test
        key (str): the key to test
        allow_empty (bool): True to treat an empty string as valid

    Returns:
        bool: True if the given key holds a string-able value; False otherwise

    """
    value = section_config.get(key)
    if value is None or value == '' and not allow_empty:
        return False

    return isinstance(value, str)


def is_intable(section_config, key):
    """
    Determine if the specified key in a given section config holds a value that can be an integer

    Args:
        section_config (ConfigDict): the section config to test
        key (str): the key to test

    Returns:
        bool: True if the given key holds a int-able value; False otherwise

    """
    value = section_config.get(key)
    if value is None:
        return False
    else:
        try:
            int(value)
            return True
        except ValueError:
            return False


def is_boolable(section_config, key):
    """
    Determine if the specified key in a given section config holds a value that can be a bool

    Args:
        section_config (ConfigDict): the section config to test
        key (str): the key to test

    Returns:
        bool: True if the given key holds a bool-able value; False otherwise

    """
    value = section_config.get(key)
    if value is None:
        return False

    if not isinstance(value, str):
        return False

    if value.lower() in ['true', 'false']:
        return True

    try:
        bool(int(value))
        return True
    except ValueError:
        return False
