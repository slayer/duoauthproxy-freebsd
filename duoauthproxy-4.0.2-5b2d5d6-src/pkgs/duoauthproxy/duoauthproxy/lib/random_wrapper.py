import sys
from duoauthproxy.lib.fips_manager import OPENSSL_FFI as ffi
from duoauthproxy.lib.fips_manager import OPENSSL_LIB as lib


# This method is also used in Trusted Path
def _duo_urandom_new_wrapper(n):
    """
    A function with the exact same API as os.urandom, but using a FIPS approved
    pseudo-random number generator.
    """
    # Create a C array that we can fill with random bytes. It is immediately
    # assigned to a variable to make sure the value isn't freed before we use it.
    char_array = ffi.new("unsigned char[]", [0] * n)

    # Fill the C array with n random bytes using a FIPS approved algorithm.
    return_code = lib.RAND_bytes(char_array, n)

    # Quoting the OpenSSL docs:
    #     RAND_bytes() and RAND_priv_bytes() return 1 on success, -1 if not
    #     supported by the current RAND method, or 0 on other failure.
    if return_code != 1:
        sys.stderr.write(
            ("\nOpenSSL's RAND_bytes() returned a non-one response ({}).\n" +
             "It was unable to generate a random byte sequence.\n" +
             "https://www.openssl.org/docs/manmaster/man3/RAND_bytes.html\n").format(return_code))
        sys.exit(1)

    # Get a buffer for the raw C array so we can work with it.
    result_buffer = ffi.buffer(char_array)

    # Copy the result as a Python byte string. Slice notation ( [:] ) is used
    # instead of str() to avoid inconsistencies between Python 2 and 3.
    result_byte_string = result_buffer[:]

    return result_byte_string
