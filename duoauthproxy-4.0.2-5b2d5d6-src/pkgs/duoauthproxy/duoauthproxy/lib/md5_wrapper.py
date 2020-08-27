from cryptography.hazmat.bindings.openssl.binding import Binding
import _md5

Depends = object()


def _duo_md5_new_wrapper(func):
    def md5_with_safe_guard(*args, **kwargs):
        """
        Caller must explicitly pass used_for_security=False
        or used_for_security=Depends as a kwarg.
        """
        used_for_security = kwargs.get('used_for_security', True)

        try:
            if (used_for_security not in (Depends, False)) and Binding.lib.FIPS_mode():
                raise ValueError('Must pass used_for_security=False or used_for_security=Depends to use MD5 when in FIPS mode')
        except ImportError:
            pass

        if 'used_for_security' in kwargs:
            del kwargs['used_for_security']

        result = func(*args, **kwargs)

        return result
    return md5_with_safe_guard


def _duo_hashlib_new_wrapper(func):
    def hashlib_with_safe_guard(*args, **kwargs):
        # If `hashlib.new` is invoked with any other digest besides md5 then return.
        # This maintains expected functionality for digests like hashlib.new('sha1', 'hello')
        # without having to worry about the `used_for_security` keyword.
        if args[0] == "md5":
            # Remove first args (md5) and use python built-in md5 instead of openssl_md5
            args = args[1:]
            if _md5.md5.__name__ != 'md5_with_safe_guard':
                wrapped_md5 = _duo_md5_new_wrapper(_md5.md5)
            else:
                wrapped_md5 = _md5.md5
            return wrapped_md5(*args, **kwargs)
        else:
            return func(*args, **kwargs)

    return hashlib_with_safe_guard
