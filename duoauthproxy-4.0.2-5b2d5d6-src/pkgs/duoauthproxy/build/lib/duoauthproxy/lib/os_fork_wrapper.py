from duoauthproxy.lib.fips_manager import reseed_openssl_rand


def _duo_os_fork_wrapper(func):
    def call(*args, **kwargs):
        result = func(*args, **kwargs)
        if result == 0:  # child
            # Add 32 bytes from urandom to the pool
            # Using 32 bytes as shown in https://wiki.openssl.org/index.php/Random_Numbers
            bytes_read = reseed_openssl_rand(32)
            if bytes_read != 32:
                raise IOError(
                    'Failed to reseed random on fork: read {} bytes from urandom'
                    .format(bytes_read))
        return result
    return call
