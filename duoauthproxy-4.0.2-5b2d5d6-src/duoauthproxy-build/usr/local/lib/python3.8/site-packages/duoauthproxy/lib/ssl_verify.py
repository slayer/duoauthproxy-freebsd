#
# Copyright (c) 2011 Duo Security
# All Rights Reserved
#

import re
from collections import OrderedDict
from typing import Union, IO

from twisted.internet import ssl
from OpenSSL import crypto
from cryptography import x509

from duoauthproxy.lib import fips_manager
from . import log


class _CertificateError(ValueError):
    pass


def _dnsname_to_pat(dn):
    # Copyright (c) 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010
    # Python Software Foundation; All Rights Reserved
    # function backported from Python 3.2 alpha3
    pats = []
    for frag in dn.split(r'.'):
        if frag == '*':
            # When '*' is a fragment by itself, it matches a non-empty dotless
            # fragment.
            pats.append('[^.]+')
        else:
            # Otherwise, '*' matches any dotless fragment.
            frag = re.escape(frag)
            pats.append(frag.replace(r'\*', '[^.]*'))
    return re.compile(r'\A' + r'\.'.join(pats) + r'\Z', re.IGNORECASE)


def _iter_hostnames(hostnames):
    if isinstance(hostnames, str):
        yield hostnames
    else:
        for hostname in hostnames:
            yield hostname


def _get_dns_subjectaltnames(cert):
    crypto_obj = cert.to_cryptography()

    try:
        san_data = crypto_obj.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    except x509.ExtensionNotFound:
        return []

    return san_data.value.get_values_for_type(x509.DNSName)


def _match_hostnames(cert, hostnames):
    # Copyright (c) 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010
    # Python Software Foundation; All Rights Reserved
    # function backported from Python 3.2 alpha3 and modded to work with
    # PyOpenSSL X509 objects.

    if not cert:
        raise ValueError("empty or no certificate")

    # first look at the subjectAltName extension, if it's present
    dnsnames = _get_dns_subjectaltnames(cert)
    for name in dnsnames:
        for hostname in _iter_hostnames(hostnames):
            if _dnsname_to_pat(name).match(hostname):
                return

    if not dnsnames:
        # The subject is only checked when there is no dNSName entry
        # in subjectAltName
        for (key, value) in cert.get_subject().get_components():
            if key == b'CN':
                for hostname in _iter_hostnames(hostnames):
                    if _dnsname_to_pat(value.decode()).match(hostname):
                        return
                dnsnames.append(value)

    if len(dnsnames):
        raise _CertificateError(
            "No match between hostname(s) %r and certificate name(s) %r"
            % (hostnames, dnsnames))
    else:
        raise _CertificateError(
            "no appropriate commonName or "
            "subjectAltName fields were found"
        )


class HostnameVerifySSLContextFactory(ssl.CertificateOptions):
    def __init__(self, hostnames, verbose=False, *args, **kwargs):
        """SSL Context Factory with Hostname Verification

        Performs similar checks to twisted.internet.ssl.CertificateOptions
        (i.e. to verify that a server-provided certificate has a trusted root
        in a provided collection of CA certs), but also checks that the
        CN of the server certificate matches the provided hostname.

        @param hostnames: a hostname (or list of hostnames) to match against
        @param verbose: More detailed log messages for invalid certificates

        All subsequent args/kwargs are passed through to the
        t.i.ssl.CertificateOptions constructor
        """
        ssl.CertificateOptions.__init__(self, *args, **kwargs)
        self.hostnames = hostnames
        self.verbose = verbose

    def _verify_callback(self, conn, cert, errno, depth, preverify_ok):
        if preverify_ok and depth == 0:
            try:
                _match_hostnames(cert, self.hostnames)
            except _CertificateError as e:
                log.err('Certificate verification failed: %s' % e)
                if self.verbose:
                    log.msg('Failing certificate: '
                            + crypto.dump_certificate(crypto.FILETYPE_PEM,
                                                      cert))
                return False
        elif not preverify_ok:
            log.err(
                'Certificate verification failed: errno %d depth=%s subject %s'
                % (errno, depth, cert.get_subject().get_components()))
            if self.verbose:
                log.msg('Failing certificate: '
                        + crypto.dump_certificate(crypto.FILETYPE_PEM,
                                                  cert))
        return preverify_ok

    def getContext(self):
        ctx = ssl.CertificateOptions.getContext(self)

        # override the verify callback
        ctx.set_verify(ctx.get_verify_mode(), self._verify_callback)

        return ctx


def load_ca_bundle(bundle_file: Union[str, IO[str]]):
    """Read multiple CA certificates from a PEM-encoded 'CA Bundle' file;
    return a list of PyOpenSSL X509 objects, suitable for use with an HTTPClient.
    Args:
        bundle_file (str or file descriptor): either the contents of the CA bundle file,
            or a file descriptor pointing to that file. That file should return strings when read()
    Returns:
        list: List of zero or more OpenSSL.crypto.X509 cert objects
    """

    if isinstance(bundle_file, str):
        content = bundle_file
    else:
        content = bundle_file.read()
    pattern = re.compile('-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', re.DOTALL)
    cert_strings = re.findall(pattern, content)

    # De-dupe. Otherwise Twisted's ssl.CertificateOptions will get an
    # OpenSSL.Error adding duplicate certs to a store.
    certs = OrderedDict()
    for cert in cert_strings:
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
        certs[cert.digest('sha1')] = cert
    return list(certs.values())


def create_context_factory(hostnames=None, privateKey=None, certificate=None,
                           caCerts=None, verifyDepth=9, verbose=False):
    """ Create an appropriate SSL context factory for the given CA certs
    and hostname.

    @param hostnames: the hostname (or list of hostnames) to match against.
        Pass 'None' to disable hostname validation
    @param privateKey: client private key, if the server requires it
    @param certificate: client certificate, if the server requires it
    @param caCerts: a list of CA root certs (of type
        OpenSSL.SSL.X509) against which servers should be
        validated. Pass 'None' to entirely disable certificate
        validation
    @param verifyDepth: maximum verify depth
    @param verbose: More detailed log messages for invalid certificates
        (Note: no effect if hostname validation is not enabled)
    """
    if fips_manager.status():
        minimum_ssl_version = ssl.TLSVersion.TLSv1_2
    else:
        minimum_ssl_version = None

    kwargs = {
        'certificate': certificate,
        'raiseMinimumTo': minimum_ssl_version,
        'privateKey': privateKey,
        'verify': False,
    }
    if not caCerts:
        return ssl.CertificateOptions(**kwargs)
    else:
        kwargs.update({
            'verify': True,
            'caCerts': caCerts,
            'verifyDepth': verifyDepth,
            'verifyOnce': False,
            'requireCertificate': True,
        })
        if hostnames:
            return HostnameVerifySSLContextFactory(
                hostnames, verbose=verbose, **kwargs)
        else:
            return ssl.CertificateOptions(**kwargs)
