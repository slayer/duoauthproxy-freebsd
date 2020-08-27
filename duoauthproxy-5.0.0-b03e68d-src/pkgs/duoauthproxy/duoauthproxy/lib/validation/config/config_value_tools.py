#
# Copyright (c) 2018 Duo Security
# All Rights Reserved
#
from codecs import getencoder

from twisted.internet.ssl import AcceptableCiphers

from duoauthproxy.modules.ssl_server import TLS_VERSIONS


def is_value_in_defined_set(value, options, transform=lambda x: x):
    """
    Test a given value to determine if it is in a given set of options

    Args:
        value (str): The value to test
        options (List(str)): The allowable values
        transform (function): A function that will take `value` as an arg.
                              Function will be applied before checking inclusion in `options`

    Returns:
        bool: True if the value in in the specified options, False otherwise or if the value is blank
    """
    try:
        value = transform(value)
    except Exception:
        return False

    if value == "":
        return False

    return value in options


def is_valid_permutation(value, enum, separator=",", repeats=False):
    """
    Check the validity of a string which should contain a list of seperated
    values which are all in a given enumerated list

    Args:
    config (ConfigDict): the section config to check
    key (str): key for the permutation string
    enum ([str]): enumerated list of values which can be in the permutation
    separator: (str): character separating items in permutation
    repeats: whether the permutation allows the same enum value to be present more than once

    Returns:
        Bool: whether or not he permutation is well formatted

    Example:
        factors=phone, push
        toolbox.test_valid_permutation(config, 'factors', ['push', 'phone', 'passcode'], ',', False)

        return true
    """

    seen = []
    for item in value.split(separator):
        if item.strip() not in enum:
            return False
        if repeats is False and item in seen:
            return False
        seen.append(item)

    return True


def is_codec(codec):
    try:
        getencoder(codec)
    except LookupError:
        return False

    return True


def is_tls_version(tls_version):
    return tls_version in TLS_VERSIONS


def is_cipher_list(cipher_list):
    try:
        return len(AcceptableCiphers.fromOpenSSLCipherString(cipher_list)._ciphers) > 0
    except Exception:
        return False
