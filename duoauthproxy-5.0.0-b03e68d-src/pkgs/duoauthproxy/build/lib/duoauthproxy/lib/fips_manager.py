#
# Copyright (c) 2011 Duo Security
# All Rights Reserved
#
# pylint: disable=no-member
"""
FipsManager controls the FIPS modes of operations.

It allows us to:

 * Enable FIPS mode if configured
 * Retrieve the current mode of operation
 * Wrap MD5 implementations with to guard against inappropriate uses

FIPS utilizes ONOFF values to set various FIPS modes and return values.
Currently, any non-zero value will enable fips but it is recommended to use 1
to ensure future compatability when other values can designate additional
restrictions to certain algorithms.

Go here details on the FIPS invocations:

 * https://wiki.openssl.org/index.php/FIPS_mode_set()
 * https://wiki.openssl.org/index.php/FIPS_mode()
"""

import platform

from cryptography.hazmat.bindings.openssl.binding import Binding

OPENSSL_LIB = Binding.lib
OPENSSL_FFI = Binding.ffi
FIPS_DISABLED = 0
FIPS_ENABLED = 1


def status():
    """
    Get the status of FIPS mode of operation

    Returns:
        result: (int) an integer that represents the FIPS mode of operation
    """
    return OPENSSL_LIB.FIPS_mode()


def enable():
    """
    Enable running in FIPS mode

    If FIPS mode is already enabled, we return the FIPS mode of operation.
    This is needed because if we enable more than once openssl will throw an error.

    Returns:
        result: (int) An integer that represents the FIPS mode of operation.
    """
    if status() != FIPS_DISABLED:
        # double-enabling FIPS is an error so we bail
        return status()

    # The import is scoped to the function because `backend` initializes
    # some packages that we need to wrap first.
    from cryptography.hazmat.backends.openssl import backend

    # Activate the random engine otherwise we can't generate random data.
    # Per `cryptography`'s documentation, the random engine only gets activated when
    # the backend is imported. Since we aren't using the backend directly, we
    # explicitly activate the random engine.
    if platform.system() != "Windows":
        backend.activate_builtin_random()
    else:
        backend.activate_osrandom_engine()

    result = OPENSSL_LIB.FIPS_mode_set(FIPS_ENABLED)

    if result == 0:
        error_code = OPENSSL_LIB.ERR_get_error()
        raise Exception("Failed to start in FIPS mode: ", error_code)

    return result


def get_openssl_version():
    """
    Returns the FIPS openssl version

    Return:
        string: the openssl version being used by the Auth Proxy
    """
    # The import is scoped to the function because `backend` initializes
    # some packages that we need to wrap first.
    from cryptography.hazmat.backends.openssl import backend

    return backend.openssl_version_text()


def reseed_openssl_rand(byte_count):
    """Reseed OpenSSL's pseudo random number generator with the given number
    of bytes.

    Args:
        byte_count (int): The number of bytes to use to reseed.

    Returns:
        int: The number of bytes OpenSSL was actually able to read.
    """
    return OPENSSL_LIB.RAND_load_file("/dev/urandom".encode("ascii"), byte_count)


# It is strongly discourged for any code outside of tests to explicitly
# disable FIPS mode
def _disable():
    """
    Disables running in FIPS mode

    Return:
        result: (int) an integer that represents the FIPS mode of operation.
    """
    result = OPENSSL_LIB.FIPS_mode_set(FIPS_DISABLED)

    # The import is scoped to the function because `backend` initializes
    # some packages that we need to wrap first.
    from cryptography.hazmat.backends.openssl import backend

    # The OS random engine has kernel-level access to hardware entropy and is preferable
    # over the userspace randomness generated by openssl but is not FIPS complaint
    # therefore we should use this stronger randomness whenver possible.
    backend.activate_osrandom_engine()

    if result == 0:
        error_code = OPENSSL_LIB.ERR_get_error()
        raise Exception("Failed to disable FIPS mode: ", error_code)

    return result
