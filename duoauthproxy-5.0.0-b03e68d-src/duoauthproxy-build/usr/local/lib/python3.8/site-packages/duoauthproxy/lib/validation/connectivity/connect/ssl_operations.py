#
# Copyright (c) 2018 Duo Security
# All Rights Reserved
#
"""Module for testing validity of user-specified SSL objects, such as in
ldap_server_auto, main, and ad_client."""

from OpenSSL import SSL, crypto

from duoauthproxy.lib.config_error import ConfigError
from duoauthproxy.lib.ssl_verify import load_ca_bundle
from duoauthproxy.lib.validation.connectivity.connectivity_results import (
    SslCertFileResult,
    SslContextResult,
    SslKeyFileResult,
    SslResult,
    UnmetPrerequisiteSkippedTestResult,
)
from duoauthproxy.modules import ssl_server


def _load_ssl_key(ssl_key_path):
    """Opens, validates, and returns a dict containing the SSL private key.
    Args:
        ssl_key_path (str): Possibly empty path to SSL private key
    Returns:
        (SslKeyFileResult, PKey): the result of trying to read the indicated SSL key file and the actual key data
    """
    if not ssl_key_path:
        return SslKeyFileResult(False, ssl_key_path), None
    try:
        with open(ssl_key_path) as fd:
            ssl_key = crypto.load_privatekey(crypto.FILETYPE_PEM, fd.read())
            ssl_key.check()
            return SslKeyFileResult(True, ssl_key_path), ssl_key
    except Exception as e:  # can be IOError, crypto.Error, and possibly others
        return SslKeyFileResult(False, ssl_key_path, exception=e), None


def _contains_truncated_certs(ssl_cert_input):
    """Checks to see that the number of BEGIN CERTIFICATE lines match the number of END CERTIFICATE lines.
    A mismatch would indicate a truncated certificate blob somewhere in the file.
    Args:
        ssl_cert_input (str): Contents of an SSL certificate containing zero or more PEM blobs
    Returns:
        bool: True if number of start lines equals end lines, False otherwise
    """
    begin_occurrences = ssl_cert_input.count("-----BEGIN CERTIFICATE-----")
    end_occurrences = ssl_cert_input.count("-----END CERTIFICATE-----")
    if begin_occurrences != end_occurrences:
        return True
    return False


def load_ssl_certs(ssl_cert_path):
    """Opens, validates, and returns a dict containing one or more SSL certificates.
    Self-signed certs will check out fine. Cert chain order will not be checked here.
    Args:
        ssl_cert_path (str): Possibly empty path to SSL certificate
    Returns:
        (SslCertFileResult, [certificates]): the result of the test and the actual certificate data
    """
    if not ssl_cert_path:
        return SslCertFileResult(False, ssl_cert_path), None
    try:
        with open(ssl_cert_path) as fd:
            cert_input = fd.read()
            if _contains_truncated_certs(cert_input):
                raise Exception(
                    "Certificate at {0} contains a mismatched number of BEGIN and END CERTIFICATE lines. "
                    "Please re-check your certificate to make sure all contained certificates begin with "
                    "'-----BEGIN CERTIFICATE-----' and end with '-----END CERTIFICATE-----'.".format(
                        ssl_cert_path
                    )
                )

            ssl_certs = load_ca_bundle(cert_input)

            cert_store = crypto.X509Store()
            for cert in ssl_certs:
                cert_store.add_cert(cert)

            cert_context = crypto.X509StoreContext(cert_store, ssl_certs[0])
            cert_context.verify_certificate()

            return SslCertFileResult(True, ssl_cert_path), ssl_certs
    except Exception as e:  # can be IOError, crypto.Error, and possibly others
        return SslCertFileResult(False, ssl_cert_path, exception=e), None


def _can_create_ssl_context(ssl_key, ssl_certs, cipher_list, minimum_tls_version=None):
    """Checks to see if user-specified SSL key, cert, and cipher list are capable
    of creating an SSL context.
    Args:
        ssl_key (crypto.PKey): Private key object
        ssl_certs (list of crypto.X509): Possibly empty list of X509 cert objects.
        Assumed to be in proper order (host, then intermediates, then root).
        cipher_list (str): Possibly empty comma-separated OpenSSL-formatted ciphers
        minimum_tls_version (str): The minimum TLS version for the server context
    Returns:
        SslContextResult or UnmetPrerequisiteSkippedTestResult: result of attempting
             to create the ssl context
    """
    if not ssl_key or not ssl_certs:
        return UnmetPrerequisiteSkippedTestResult(
            "SSL context creation", "SSL key and cert"
        )

    try:
        host_cert = ssl_certs[0]
        intermediate_and_root_certs = ssl_certs[1:]

        cert_options = ssl_server.ChainingOpenSSLContextFactory(
            cipher_list=cipher_list,
            minimum_tls_version=minimum_tls_version,
            privatekey_data=ssl_key,
            certificate_data=host_cert,
        )

        ctx = cert_options.getContext()

        for cert in intermediate_and_root_certs:
            ctx.add_extra_chain_cert(cert)

        ctx.check_privatekey()  # ensures key and host cert match each other
    except (ConfigError, SSL.Error) as e:
        return SslContextResult(False, cipher_list, minimum_tls_version, e)

    return SslContextResult(True, cipher_list, minimum_tls_version)


def can_validate_ssl_creds(
    ssl_key_path, ssl_cert_path, cipher_list=None, minimum_tls_version=None
):
    """Checks to see if SSL key and cert are valid and readable, and also checks user's
    specified SSL ciphers.
    Args:
        ssl_key_path, ssl_cert_path (str): Possibly empty paths to SSL private key and cert
        cipher_list (str): Possibly empty list of comma-separated ciphers
    Returns:
        SslResult: the result of testing the provided SSL components
    """
    key_result, key_data = _load_ssl_key(ssl_key_path)
    cert_result, cert_data = load_ssl_certs(ssl_cert_path)

    validate_result = _can_create_ssl_context(
        key_data, cert_data, cipher_list, minimum_tls_version,
    )

    return SslResult(key_result, cert_result, validate_result)
