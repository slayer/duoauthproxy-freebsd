import _hashlib
import _md5
import hashlib
import platform

from duoauthproxy.lib.md5_wrapper import _duo_hashlib_new_wrapper, _duo_md5_new_wrapper
from duoauthproxy.lib.os_fork_wrapper import _duo_os_fork_wrapper
from duoauthproxy.lib.random_wrapper import _duo_urandom_new_wrapper

"""
_fipscustomize ensures that certain opertaions needed for FIPS compliance
such as protecting against uses of md5 for security purposes.

Wrapping md5:
During python initialization hashlib.md5 is initialized to openssl_md5
before any wrapping occurs. As a result, we have to make sure to wrap it.
hashlib.new tries to initialize a digest using _hashlib.new(name, string).
Since we've already wrapped _hashlib.new, just directly assign here.

Wrapping urandom:
We replace `os.urandom` with a function that obtains randomness from a
FIPS validated prng instead of `/dev/urandom` which is not fips approved.

We also replace `random._urandom` which is really just `os.urandom` imported
as `_urandom`.

We do not need to do this for Windows, because Windows uses the CryptGenRandom
generator which is FIPS validated.
"""

if _hashlib.new.__name__ != "hashlib_with_safe_guard":
    _hashlib.new = _duo_hashlib_new_wrapper(_hashlib.new)

if hashlib.new.__name__ != "hashlib_with_safe_guard":
    hashlib.new = _hashlib.new

if _md5.md5.__name__ != "md5_with_safe_guard":
    _md5.md5 = _duo_md5_new_wrapper(_md5.md5)

if _hashlib.openssl_md5.__name__ != "md5_with_safe_guard":
    # Set openssl's hashlib to always be the python built version of md5
    _hashlib.openssl_md5 = _md5.md5

if hashlib.md5.__name__ != "md5_with_safe_guard":
    # Set openssl's hashlib to always be the python built version of md5
    hashlib.md5 = _md5.md5


if platform.system() != "Windows":
    # Replace os.urandom with a FIPS approved implementation.
    import os

    os.urandom = _duo_urandom_new_wrapper

    # The random module imports hashlib and os.urandom, so we can't import it
    # until after our other patches are in place.
    import random

    random._urandom = _duo_urandom_new_wrapper

    # random.Random uses a non-FIPS-approved PRNG, while
    # random.SystemRandom references our FIPS-approved os.urandom.
    # NOTE: This is all written in the form of `x.y = x.y and z`, so it will
    #       raise if `x.y` doesn't exist, thus preventing us from adding new
    #       classes to the random module that weren't there before.
    random.Random = random.Random and random.SystemRandom

    # All of the following methods in the random module are pulled from an
    # instance of random.Random create when the module is first imported. We
    # have to overwrite them because our replacement of random.Random happens
    # after that instance is created.
    # We overwrite all of them one by one instead of dynamically, so we
    # statically can tell what is being overwritten.
    # NOTE: This is all written in the form of `x.y = x.y and z`, so it will
    #       raise if `x.y` doesn't exist, thus preventing us from adding new
    #       functions to the random module that weren't there before.
    _generator = random.SystemRandom()
    random.seed = random.seed and _generator.seed
    random.random = random.random and _generator.random
    random.uniform = random.uniform and _generator.uniform
    random.triangular = random.triangular and _generator.triangular
    random.randint = random.randint and _generator.randint
    random.choice = random.choice and _generator.choice
    random.choices = random.choices and _generator.choices
    random.randrange = random.randrange and _generator.randrange
    random.sample = random.sample and _generator.sample
    random.shuffle = random.shuffle and _generator.shuffle
    random.normalvariate = random.normalvariate and _generator.normalvariate
    random.lognormvariate = random.lognormvariate and _generator.lognormvariate
    random.expovariate = random.expovariate and _generator.expovariate
    random.vonmisesvariate = random.vonmisesvariate and _generator.vonmisesvariate
    random.gammavariate = random.gammavariate and _generator.gammavariate
    random.gauss = random.gauss and _generator.gauss
    random.betavariate = random.betavariate and _generator.betavariate
    random.paretovariate = random.paretovariate and _generator.paretovariate
    random.weibullvariate = random.weibullvariate and _generator.weibullvariate
    random.getstate = random.getstate and _generator.getstate
    random.setstate = random.setstate and _generator.setstate
    random.getrandbits = random.getrandbits and _generator.getrandbits

    # When in FIPS mode, we use OpenSSL's random number generation facilities
    # instead of those provided by the operating system. OpenSSL makes it clear
    # that its random number generator is not fork-safe, meaning that a forked
    # process may have predictable random number generation in relation to its parent.
    # https://wiki.openssl.org/index.php/Random_fork-safety
    #
    # This is unlikely to be an /actual/ problem with the FIPS-mode OpenSSL since
    # it mixes in both high-precision system time and the PID into random generation.
    # For more info see FIPS_get_timevec in fips_rand.c in the FIPS module source.
    # We still want to reseed on fork anyways to be extra safe.
    #
    # We do this mitigation by monkeypatching os.fork instead of
    # adding a post-fork handler using pthread_atfork
    # because Python upstream ran into deadlock issues that way:
    # https://phab.duosec.org/D28435#659554
    os.fork = _duo_os_fork_wrapper(os.fork)
