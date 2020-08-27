#
# Copyright (c) 2017 Duo Security
# All Rights Reserved
#

import copy
import itertools
import os
import random
import re
import socket
import string
import sys
from collections import OrderedDict

import colorama
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from ldaptor.ldapfilter import InvalidLDAPFilter, parseFilter
from OpenSSL.crypto import X509

from . import const, log
from .config_error import ConfigError
from .ssl_verify import load_ca_bundle

# SystemRandom instance for use by copy_and_shuffle's default shuffler
_system_random = random.SystemRandom()


def copy_and_shuffle(source_list, shuffler=_system_random.shuffle):
    """
    Makes a deep copy of the provided list, shuffles it, and returns it.
    Args:
        source_list (list): The list to copy and shuffle
        shuffler (callable): The method to use to shuffle the the list. Must
            shuffle the list in place!

    Returns:
        list: The shuffled copy of the source list
    """
    if not source_list:
        return []

    list_copy = copy.deepcopy(source_list)
    shuffler(list_copy)
    return list_copy


def is_length_delimiting_enabled(delimited_password_length):
    return delimited_password_length > 0


def do_password_split(password, delimiter, delimited_password_length):
    """ Take a full password with factor and delim and chunk it up
    Args:
        password (str)
        delimiter (str)
        delimited_password_length (int)
    Returns:
        tuple (str, str): password & factor
    """
    if is_length_delimiting_enabled(delimited_password_length):
        left = password[:delimited_password_length]
        right = password[delimited_password_length:]
        if right and right.startswith(delimiter):
            right = right[1:]

        return left, right
    elif delimiter in password:
        return tuple(password.rsplit(delimiter, 1))
    else:
        return password, None


def parse_ldap_filter(filter_string):
    """ Takes a raw ldap_filter as a string and returns an string object that plays nice with ldaptor
    Returns: The parsed filter if successful or None if it failed
    """
    try:
        return parseFilter(filter_string)
    except InvalidLDAPFilter as e:
        log.msg(
            "Invalid LDAP Filter: {0}. Exception: {1}".format(filter_string, str(e))
        )
        return None


def parse_delimited_set(xs, delimiter=","):
    xs = xs.split(delimiter)
    # Trailing comma, ''.split(',') => [''], etc.:
    xs = [x.strip() for x in xs if x.strip()]
    return list(OrderedDict.fromkeys(xs))


def parse_factor_list(factors):
    factors = parse_delimited_set(factors)
    if not factors:
        raise ConfigError("Factors list cannot be empty")

    for factor in factors:
        if factor not in const.FACTOR_CHOICES:
            raise ConfigError(
                'Factor "%s" is not one of ' % factor
                + (
                    ", ".join('"%s"' % c for c in const.FACTOR_CHOICES[:-1])
                    + ', or "'
                    + const.FACTOR_CHOICES[-1]
                    + '"'
                ),
            )
    return factors


def tokenize(factor):
    """Strips the given factor of leading or trailing whitespace, as well as any
    trailing digits.
    Args:
        factor: String representing a factor (eg. push, phone9)
    Returns:
        String representing the tokenized factor
    """
    factor = factor.strip()
    factor = factor.strip(string.digits)
    return factor


def is_factor(factor):
    """Checks to see if the given factor is in the global FACTOR_CHOICES list. Parses
    for trailing numbers (eg. phone9).
    Args:
        factor: String representing a factor
    Returns:
        Boolean value representing if the given factor is in the FACTOR_CHOICESs list.
    """
    if factor:
        factor = tokenize(factor)
        return factor in const.FACTOR_CHOICES
    return False


def factor_for_request(preferred_factors, preauth_res):
    """Combines factors returned by Duo service with the factors allowed by admin in the config
    to determine which factor to use for a request.
    Args:
        preferred_factors: List of strings that are factors ['auto', 'push']
    Returns:
        Either a valid argument for AuthDuoClient.auth or
        'passcode' indicating a passcode prompt challenge is needed.
        Or None if no usable factor is found
    """
    try:
        default_factor = preauth_res["factors"]["default"]
    except (KeyError, TypeError, ValueError):
        # No out-of-band factors.
        if "passcode" in preferred_factors:
            return "passcode"
        else:
            return None

    # Reconcile admin's factor preference with what preauth said
    # the user can do.
    user_factors = set(tokenize(factor) for factor in preauth_res["factors"].values())
    # Can't prompt conditionally based on whether user has
    # token(s) because preauth doesn't indicate that, but all
    # users are at least capable of having bypass codes.
    user_factors.add("passcode")
    for factor in preferred_factors:
        if factor == "auto":
            # No server-side 'auto' factor so fake one: break out
            # of factor reconciliation choosing whatever the
            # service thought best.
            return default_factor
        elif factor in user_factors:
            # Return the first factor that's in the intersection.
            # We return the factor type here instead of the exact factor name ie. phone not phone1
            # If a user has multiple factors of the same type Duo will use the first one
            return factor
    # Oops! No intersection between admin's list of usable auth
    # methods and those available for the user. Deny rather than
    # override the admin's restricted config.
    return None


# Keep the home directory so we can find config files, etc.
_home_dir = ""


def _set_home_dir():
    global _home_dir
    # get home directory
    if hasattr(sys, "frozen") and sys.frozen in ("windows_exe", "console_exe"):
        exe = os.path.abspath(sys.executable)
        _home_dir = os.path.dirname(os.path.dirname(exe))
    else:
        # This local file is <AUTHPROXY_INSTALL_DIR>/usr/local/lib/python2.7/site-packages/duoauthproxy/lib/util.py.
        # Find <AUTHPROXY_INSTALL_DIR>.
        _home_dir = os.path.abspath(
            os.path.join(os.path.dirname(__file__), *[".."] * 7)
        )


# do this when the module loads, i.e. before anybody calls chdir()
_set_home_dir()


def get_home_dir() -> str:
    return _home_dir


def resolve_file_path(path):
    """Takes relative or absolute paths and returns the appropriate absolute path for a file.
    By default, relative files are assumed to live in $AP_INSTALL_DIR/conf.
    Args:
        path (str): relative or absolute
    Returns:
        str: absolute path defined via os.path library
    """
    home_dir = get_home_dir()
    return os.path.join(home_dir, "conf", path)


def create_appdata_from_peercert(peercert: X509):
    """Pull the peercert from the connection and then massage it into the proper appdata

    Returns:
        appdata: Combination of the hashed cert and some metadata
    Raises:
        UnsupportedAlgorithm: If the cert's signature hash algorithm is not a single hash
    """
    # We convert to the cryptography library's object representation of a cert so that we have more functionality.
    # Specifically we want the signature_hash_algorithm
    crypto_peercert = peercert.to_cryptography()
    try:
        hash_algo = crypto_peercert.signature_hash_algorithm
    except UnsupportedAlgorithm as e:
        raise e
    if isinstance(hash_algo, (hashes.MD5, hashes.SHA1)):
        # https://tools.ietf.org/html/rfc5929#section-4.1
        hash_algo = hashes.SHA256()

    hashed_cert = crypto_peercert.fingerprint(hash_algo)
    return "tls-server-end-point:".encode("ASCII") + hashed_cert


def get_host_list(config):
    """Parse a config to create an ordered list of hosts and fallback hosts
    Args:
        config (ConfigDict): An ad_client config
    Returns:
        [str]: List of hosts
    Raises:
        ConfigError: If no host is given
    """
    base_key = "host"
    hosts = [
        config.get_str(host_key) for host_key in get_dynamic_keys(config, base_key)
    ]
    if not hosts:
        raise ConfigError("Missing required configuration item: '{0}'".format(base_key))
    return hosts


def get_dynamic_keys(config, base_key, protectable=False):
    """
    Parses the provided config to get all dynamic keys starting with the
    specified base key

    Args:
        config (ConfigDict): The config to check for the keys
        base_key (str): The base of the dynamic keys to check for (e.g. 'host'
        for host, host_1, host_2, etc.
    Returns:
        list of str; may be empty
    """
    keys = []

    if base_key in config:
        keys.append(base_key)

    keys += get_all_numbered_keys(config, base_key)

    if protectable:
        protected_version = base_key + "_protected"

        if protected_version in config:
            keys.append(protected_version)

        keys += get_all_numbered_keys(config, protected_version)

    return keys


def get_all_numbered_keys(config, base_key):
    """Returns ordered list of keys that start with base_key and end in a number
    Args:
        config (ConfigDict)
        base_key (str): A config key or a config_key with _protected appended
    Returns:
        List of str
    """
    prefix = base_key + "_"
    numbers = list(extract_numbers(list(config.keys()), prefix))
    numbers.sort(key=int)
    found_keys = [prefix + number for number in numbers]
    return found_keys


def get_addr_port_pairs(config):
    """Parse the host_1, host_2, etc. and port_1 port_2, etc. in a config
    Args:
        config (ConfigDict): A radius_client config
    Returns:
        [(str, int)]: List of (host, port) tuples
    Raises:
        ConfigError: If no host is given
    """
    addrs = []
    for suffix in ("", "_1"):
        host_key = "host" + suffix
        if host_key in config:
            addr = (
                config.get_str(host_key),
                config.get_int("port" + suffix, const.DEFAULT_RADIUS_PORT),
            )
            addrs.append(addr)
    if not addrs:
        # Raise error with 'host' as the missing item's name.
        config.get_str("host")
    for i in itertools.count(2):
        host_key = "host_%d" % i
        if host_key not in config:
            break
        addrs.append(
            (
                config.get_str(host_key),
                config.get_int(("port_%d" % i), const.DEFAULT_RADIUS_PORT),
            ),
        )
    return addrs


def get_ldap_port(config, transport_type):
    """ Get the port to be used to connect to LDAP Server
    Args:
        config (ConfigDict): AD Client config that may or may not specify port
    Returns:
        int: Port number
    """
    port = config.get_int("port", -1)
    if port == -1:
        if transport_type == const.AD_TRANSPORT_LDAPS:
            port = const.DEFAULT_LDAPS_PORT
        else:
            port = const.DEFAULT_LDAP_PORT

    return port


def get_ssl_ca_certs(config):
    """ Read ssl certs if filename has been provided
    Args:
        config (ConfigDict)
    Returns:
        List of PyOpenSSL X509 objects or None if no cert file given
    Raises:
        ConfigError: If we couldn't open the certs file
    """
    ssl_ca_certs_file = config.get_str("ssl_ca_certs_file", "")
    if ssl_ca_certs_file and not os.path.isfile(ssl_ca_certs_file):
        ssl_ca_certs_file = os.path.join("conf", ssl_ca_certs_file)

    # read ssl certs if a filename has been provided
    ssl_ca_certs = None
    if ssl_ca_certs_file:
        try:
            with open(ssl_ca_certs_file, "r") as fp:
                ssl_ca_certs = load_ca_bundle(fp)
        except Exception as e:
            log.msg("FATAL: Error loading certificates: %s" % str(e))
            raise ConfigError(
                "Could not load ssl ca certificates from '%s'" % ssl_ca_certs_file
            )

    return ssl_ca_certs


def warn_insecure_settings(auth_type, transport_type):
    """ Give message to warn admins if they have selected ad client settings
    that put them at a security risk
    Args:
        auth_type (str): One of const.AD_AUTH_TYPES_WIN or const.AD_AUTH_TYPES_NIX
        transport_type (str): One of const.AD_TRANSPORTS
    Returns:
        str: Warning message
    """
    msg = ""
    if (
        auth_type == const.AD_AUTH_TYPE_PLAIN
        and transport_type == const.AD_TRANSPORT_CLEAR
    ):
        msg = """WARNING: you have selected cleartext (plain) authentication for Active Directory
                    \twith no transport-level security. THIS IS A VERY BAD IDEA. Anyone able
                    \tto sniff packets on your network could capture all of your users passwords!"""

    if (
        auth_type == const.AD_AUTH_TYPE_NTLM_V1
        and transport_type == const.AD_TRANSPORT_CLEAR
    ):
        msg = """WARNING: you have selected NTLMv1 authentication for Active Directory
                     \twith no transport-level security. NTLMv1 has known weaknesses;
                     \tplease consider using NTLMv2 instead, or using SSL or STARTTLS"""

    return msg


def parse_ad_client(config):
    """Return arguments consumable by various ad_client factories
    Args:
        config (ConfigDict): An ad_client config
    Returns:
        Dict: Factory kwargs to be given to ADClientFactories
    Raises:
        ConfigError: For required settings that are missing or improperly configured settings
    """
    debug = config.get_bool("debug", False)
    is_logging_insecure = config.get_bool("is_logging_insecure", False)

    if is_windows_os():
        auth_type = config.get_enum(
            "auth_type", const.AD_AUTH_TYPES_WIN, const.AD_AUTH_TYPE_NTLM_V2, str.lower
        )
    else:
        auth_type = config.get_enum(
            "auth_type", const.AD_AUTH_TYPES_NIX, const.AD_AUTH_TYPE_NTLM_V2, str.lower
        )

    # service_account_username, service_account_password are optional
    # for auth_type = AD_AUTH_TYPE_SSPI; mandatory otherwise
    is_sspi = auth_type == const.AD_AUTH_TYPE_SSPI
    service_account_username = config.get_str(
        "service_account_username", "" if is_sspi else None
    )
    service_account_password = config.get_protected_str(
        "service_account_password_protected",
        "service_account_password",
        "" if is_sspi else None,
    )

    timeout = config.get_int("timeout", 10)
    search_dn = config.get_str("search_dn")
    security_group = config.get_str("security_group_dn", "")
    bind_dn = config.get_str("bind_dn", "")
    username_attribute = config.get_str("username_attribute", "sAMAccountName")
    at_attribute = config.get_str("at_attribute", "userPrincipalName")
    transport_type = config.get_enum(
        "transport", const.AD_TRANSPORTS, const.AD_TRANSPORT_CLEAR, str.lower
    )
    ntlm_domain = config.get_str("ntlm_domain", "")
    ntlm_workstation = config.get_str("ntlm_workstation", "")
    ssl_verify_depth = config.get_int(
        "ssl_verify_depth", const.DEFAULT_SSL_VERIFY_DEPTH
    )
    ssl_verify_hostname = config.get_bool("ssl_verify_hostname", True)

    ssl_ca_certs = get_ssl_ca_certs(config)

    ldap_filter_str = config.get_str("ldap_filter", "")

    if ldap_filter_str:
        ldap_filter = parse_ldap_filter(ldap_filter_str)
    else:
        ldap_filter = None

    # A blank bind_dn will be rejected with auth-type plain in validation
    # otherwise we supply a default
    if not bind_dn:
        bind_dn = "<ROOT>"

    warning_message = warn_insecure_settings(auth_type, transport_type)
    if warning_message:
        log.msg(warning_message)

    if (
        transport_type in (const.AD_TRANSPORT_LDAPS, const.AD_TRANSPORT_STARTTLS)
        and not ssl_verify_hostname
        and not ssl_ca_certs
    ):
        log.msg("WARNING: No CA certificates specified for SSL/TLS connection; server")
        log.msg("         certificate verification will be COMPLETELY disabled!")

    return {
        "debug": debug,
        "is_logging_insecure": is_logging_insecure,
        "bind_dn": bind_dn,
        "service_account_username": service_account_username,
        "service_account_password": service_account_password,
        "search_dn": search_dn,
        "security_group": security_group,
        "username_attribute": username_attribute,
        "at_attribute": at_attribute,
        "auth_type": auth_type,
        "ntlm_domain": ntlm_domain,
        "ntlm_workstation": ntlm_workstation,
        "timeout": timeout,
        "transport_type": transport_type,
        "ldap_filter": ldap_filter,
        "ssl_ca_certs": ssl_ca_certs,
        "ssl_verify_depth": ssl_verify_depth,
        "ssl_verify_hostname": ssl_verify_hostname,
    }


def get_authproxy_ip():
    """Return the IP address of the box the authproxy is running on"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect(("8.8.8.8", 53))
    ip = sock.getsockname()[0]
    sock.close()
    return ip


def extract_numbers(strings, prefix):
    """
    Given a set of strings of the form <prefix>+<number>, return the set of numbers present for the specified prefix

    Args:
        strings: The strings to check
        prefix: The prefix to check

    Returns:
        A set() of the numbers present that are paired with the specified prefix

    """
    return set(
        [
            re.sub(prefix, "", x)
            for x in strings
            if re.match(r"^\d+$", re.sub(prefix, "", x))
        ]
    )


def is_windows_os() -> bool:
    """
    Returns: True if the operating system is Windows, False otherwise
    """
    return os.name == "nt"


def set_stdout_color(color):
    """
    Wrapper around our usage of colorama. Sets the color printed to std_out
    to the specified color. Note that colorama must be initialized before
    calling this method for colorization to work on Windows.

    Args:
        color (str): The color to use. See color_map in the function body below
            for valid values.
    """

    # Use lighter colors on windows as the normal green and red are too dark
    windows = is_windows_os()
    color_map = {
        "green": colorama.Fore.LIGHTGREEN_EX if windows else colorama.Fore.GREEN,
        "red": colorama.Fore.LIGHTRED_EX if windows else colorama.Fore.RED,
        "reset": colorama.Style.RESET_ALL,
    }
    # Set 'end' to an empty string since the default is a newline and we don't
    # want to print a newline each time we change or reset the color.
    print(color_map[color], end="")


def should_try_splitting_password(
    password: str, allow_concat: bool, delimiter: str, delimited_password_length: int
) -> bool:
    if not allow_concat:
        return False

    if is_length_delimiting_enabled(delimited_password_length):
        # We are splitting based on password length
        return len(password) > delimited_password_length
    else:
        # We are splitting based on the delimiter
        return delimiter in password


def retrieve_error_string_from_openssl_error(error):
    """pyOpenSSL returns garbage exceptions that need to be peeled apart
    specifically to find errors. The most common location for an error is in
    the third slot of the actual error message tuple. This method just pulls
    out the error string for you to compare against.
    Args:
       OpenSSL.SSL.Error
    Returns:
        (str): Error message or '' if no error could be found
    """
    try:
        potential_ssl_err = error.args[0][0][2].lower()
    except (IndexError, AttributeError):
        # If the error doesn't fit the format we expect return ''
        potential_ssl_err = ""

    return potential_ssl_err


def safe_string_decode(maybe_bytes, codec="utf-8"):
    """ Safely decode a byte string if passed in. Otherwise just return the string back.
    Args:
        maybe_bytes: (bytes) or (str)
    Returns:
        str
    """
    if isinstance(maybe_bytes, str):
        return maybe_bytes
    else:
        return maybe_bytes.decode(codec)


def safe_byte_encode(maybe_string, codec="utf-8"):
    """ Safely encode a string if passed in. Otherwise just return the byte string back.
        Args:
            maybe_string: (str) or (bytes)
        Returns:
            byte
    """
    if isinstance(maybe_string, bytes):
        return maybe_string
    else:
        return maybe_string.encode(codec)
