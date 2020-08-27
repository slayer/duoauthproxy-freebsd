#
# Copyright (c) 2018 Duo Security
# All Rights Reserved
#

"""
This module provides functionality for servers like ldap_server_auto and
radius_server_eap to build a SSL context
"""
from twisted.internet import ssl
from twisted.internet.ssl import CertificateOptions, AcceptableCiphers
from twisted.internet._sslverify import TLSVersion
import OpenSSL

from duoauthproxy.lib.config_error import ConfigError
from duoauthproxy.lib import fips_manager, log

DEFAULT_MINIMUM_TLS_VERSION = TLSVersion.TLSv1_2

# The keys in this dict represent the user facing values that Gary would specify
# as their `minimum_tls_version` in the auth proxy config
TLS_VERSIONS = {
    "ssl3": TLSVersion.SSLv3,
    "tls1.0": TLSVersion.TLSv1_0,
    "tls1.1": TLSVersion.TLSv1_1,
    "tls1.2": TLSVersion.TLSv1_2,
}

DEFAULT_CIPHER_LIST = [
    'DEFAULT',
]


def _info_callback(conn, where, ret):
    """Use the info callback to gather information about attempted
    SSL connections and warn about incompatibilities. See the man
    page[1] for further information.

    [1] https://www.openssl.org/docs/manmaster/man3/SSL_CTX_set_info_callback.html
    """
    if where & OpenSSL.SSL.SSL_CB_WRITE_ALERT:
        if conn.get_cipher_name() is None:
            log.err(
                "Unable to establish SSL connection. "
                "Client may be attemping incompatible protocol version or cipher."
            )


class ChainingOpenSSLContextFactory(ssl.DefaultOpenSSLContextFactory, object):

    _handshake_done = object()

    def __init__(
            self,
            privatekey_filename=None,
            certificate_filename=None,
            privatekey_data=None,
            certificate_data=None,
            minimum_tls_version=None,
            cipher_list=None,
            context_factory=None):
        if not bool(privatekey_filename) ^ bool(privatekey_data):
            raise ValueError("Please specify one of 'privatekey_filename' or 'privatekey_data'")
        if not bool(certificate_filename) ^ bool(certificate_data):
            raise ValueError("Please specify one of 'certificate_filename' or 'certificate_data'")

        self.privatekey_filename = privatekey_filename
        self.certificate_filename = certificate_filename
        self.privatekey_data = privatekey_data
        self.certificate_data = certificate_data
        self.cipher_list = self._select_cipher_list(cipher_list)
        self.minimum_tls_version = self._select_minimum_tls_version(minimum_tls_version)
        self.context_factory = context_factory if context_factory is not None else CertificateOptions

        self.cacheContext()

    def cacheContext(self):
        """The default twisted ssl context factory doesn't support certificate
        chains, which we need for our PEMs with intermediate certs.
        """
        if self._context is not None:
            return

        # Twisted's CertificateOptions (context_factory) abstracts away some things like
        # setting a minimum tls, setting ciphers and performing a bitmask of
        # ssl options. For now we do need some more fine grained control,
        # so we make sure to get the SSL context right after.
        try:
            certOptions = self.context_factory(insecurelyLowerMinimumTo=self.minimum_tls_version,
                                               acceptableCiphers=self.cipher_list)
        except ValueError as e:
            if any("yielded no usable ciphers" in arg for arg in e.args):
                raise ConfigError("No usable ciphers specified in cipher_list")
            raise e

        context = certOptions.getContext()

        context = self._set_private_key(context)
        context = self._set_certificate(context)

        context.set_info_callback(_info_callback)

        self._context = context

    @staticmethod
    def _select_minimum_tls_version(minimum_tls_version=None):
        """
        Retreives a minimum TLS version to be used for a SSL Context
        """
        if fips_manager.status():
            return TLSVersion.TLSv1_2

        if minimum_tls_version and minimum_tls_version not in TLS_VERSIONS:
            raise ConfigError("incorrect minimum_tls_version")

        return TLS_VERSIONS.get(minimum_tls_version, DEFAULT_MINIMUM_TLS_VERSION)

    @staticmethod
    def _select_cipher_list(cipher_list=None):
        """
        Selects either a passed in cipher list or uses the default openssl cipher list
        """
        if cipher_list:
            return AcceptableCiphers.fromOpenSSLCipherString(cipher_list)

        if fips_manager.status():
            return AcceptableCiphers.fromOpenSSLCipherString('TLSv1.2:kRSA:!eNULL:!aNULL')

        return AcceptableCiphers.fromOpenSSLCipherString(':'.join(DEFAULT_CIPHER_LIST))

    def _set_private_key(self, context):
        if self.privatekey_filename:
            try:
                context.use_privatekey_file(self.privatekey_filename)
            except Exception as e:
                if e.args[0][0][1] == 'fopen' and e.args[0][2][1] == 'SSL_CTX_use_PrivateKey_file':
                    raise ConfigError(
                        "Could not open private key file at %s" % (self.privatekey_filename))
                raise e
        elif self.privatekey_data:
            context.use_privatekey(self.privatekey_data)

        return context

    def _set_certificate(self, context):
        if self.certificate_filename:
            try:
                context.use_certificate_file(self.certificate_filename)
                context.use_certificate_chain_file(self.certificate_filename)
            except Exception as e:
                if e.args[0][0][1] == 'fopen' and e.args[0][2][1] == 'SSL_CTX_use_certificate_file':
                    raise ConfigError(
                        "Could not open certificate file at %s" % (self.certificate_filename))
                raise e
        elif self.certificate_data:
            context.use_certificate(self.certificate_data)

        return context
