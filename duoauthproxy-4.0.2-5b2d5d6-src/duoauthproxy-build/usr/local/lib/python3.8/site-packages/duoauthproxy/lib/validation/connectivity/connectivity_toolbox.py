#
# Copyright (c) 2018 Duo Security
# All Rights Reserved
#
from twisted.internet import defer

from duoauthproxy.lib.validation.connectivity.connect import listen
from duoauthproxy.lib.validation.connectivity.connect import duo
from duoauthproxy.lib.validation.connectivity.connect import ip
from duoauthproxy.lib.validation.connectivity.connect import ssl_operations
from duoauthproxy.lib.validation.connectivity.connect import ldap_operations


class ConnectivityTestToolbox(object):
    """
    Provides all the individual connectivity tests in one class
    """

    @defer.inlineCallbacks
    def test_listen_udp(self, port, interface=''):
        """
        Test whether it is possible to listen for UDP packets on the specified port and interface

        Args:
            port (int): The port to test
            interface (str): Optional argument for the interface to listen on.  Blank means 'all'

        Returns:
            ListenResult: the result of the test

        """
        result = yield listen.can_listen_udp(port, interface)
        defer.returnValue(result)

    @defer.inlineCallbacks
    def test_listen_tcp(self, port, interface=''):
        """
        Test whether it is possible to listen for TCP packets on the specified port and interface

        Args:
            port (int): The port to test
            interface (str): Optional argument for the interface to listen on.  Blank means 'all'

        Returns:
            ListenResult: the result of the test
        """
        result = yield listen.can_listen_tcp(port, interface)
        defer.returnValue(result)

    @defer.inlineCallbacks
    def test_connect_tcp(self, host, port):
        """
        Test whether it is possible to establish a TCP connection to the specified host and port

        Args:
            host (string): the host to test
            port (int): the port to test

        Returns:
            ConnectResult: the result of the test
        """
        result = yield ip.can_connect_tcp(host, port)
        defer.returnValue(result)

    def test_connect_radius(self, client, request):
        """
        Test whether a radius packet can reach the configured radius server

        Args:
            client (pyrad.Client): Client configured to reach server
            request (pyrad.Packet): Packet to send likely AccessRequest
        Returns:
            RadiusConnectResult: The result of testing the radius connection
        """
        return ip.can_connect_radius(client, request)

    @defer.inlineCallbacks
    def test_connect_with_http_proxy(self, http_proxy_host, http_proxy_port):
        """
        Test whether we can reach the http proxy

        Args:
            http_proxy_host (string): the proxy host to connect through
            http_proxy_port (int): the proxy port to connect through

        Returns:
            HttpProxyResult: the result of the test
        """
        result = yield ip.can_connect_tcp(http_proxy_host, http_proxy_port)
        defer.returnValue(result)

    @defer.inlineCallbacks
    def test_listen_ssl(self, port, ssl_ctx_factory, interface=''):
        """
        Test whether it is possible to listen on an SSL-enabled port and interface.
        Args:
            port (int): the port to listen on
            ssl_ctx_factory (twisted.internet.ssl.ContextFactory): Factory that can create
                an ssl context to be used by the connection
            interface (str): the interface to listen on
        Returns:
            ListenResult: the result of the test
        """
        result = yield listen.can_listen_ssl(port, ssl_ctx_factory, interface)
        defer.returnValue(result)

    def test_validate_api_credentials(self, duo_client):
        """
        Test whether a Duo /check API call succeeds for the given API credentials

        Args:
            duo_client (duo_client.Client): a Duo api client
        Returns:
            ValidateApiCredentialsResult: the result of the test
        """
        return duo.can_validate_duo_creds(duo_client)

    def test_ping_duo(self, duo_client):
        """
        Test whether a Duo /ping API call succeeds against the given host

        Args:
            duo_client (duo_client.Client): a Duo api client
        Returns:
            DuoPingResult: the result of the test

        """
        return duo.can_ping_duo(duo_client)

    def test_time_drift(self, duo_client):
        """
        Test the time drift between Duo Cloud and the server running the Auth Proxy

        Args:
            duo_client (duo_client.Client): a Duo api client
        Returns:
            TimeDriftResult: the result of the test

        """
        return duo.has_acceptable_time_drift(duo_client)

    def test_ssl_certs(self, cert_file_path):
        """
        Test whether a specified certificate file can be read properly

        Args:
            cert_file_path (string): the relative path to the certificate file

        Returns:
            SslCertFileResult: the result of the testing

        """
        ssl_file_result, _cert_data = ssl_operations.load_ssl_certs(cert_file_path)
        return ssl_file_result

    def test_ssl_credentials(self, key_file_path, cert_file_path, ciphers=None, minimum_tls_version=None):
        """Test if SSL credentials are capable of being used for listening to SSL connections.
        Args:
            key_file_path, cert_file_path (str): Possibly empty paths to SSL private key and cert
            ciphers (str): one or more cipher suite strings delimited by semicolons
            minimum_tls_version (str): minimum tls protocol for the server to use
        Returns:
            SslResult: the result of testing the provided SSL components
        """
        return ssl_operations.can_validate_ssl_creds(
            key_file_path,
            cert_file_path,
            ciphers,
            minimum_tls_version,
        )

    @defer.inlineCallbacks
    def test_bind_service_account(self, client, keep_bound=False):
        """Test if service account client can bind to the directory
        Args:
            client (_ADServiceClientProtocol): A connected client generated from an ad_client config
            keep_bound (bool): If True client will stay bound for use after this test
        Returns:
            LdapBindResult: the result of the test
        """
        result = yield ldap_operations.can_bind_service_account(client, keep_bound)
        defer.returnValue(result)

    @defer.inlineCallbacks
    def test_ldap_search_has_results(self, bound_client, search_dn, filter_object):
        """Determine if an ldap filter will return any results.
        Args:
            bound_client: An ldaptor client that's already connected and bound as a search user
            search_dn: the base DN to search from
            filter_object: the filter text for the search, in LDAP filter format
        Returns:
            LdapSearchResult: the result of the test
        """
        result = yield ldap_operations.ldap_search_has_results(bound_client, search_dn, filter_object)
        defer.returnValue(result)


STANDARD_TOOLBOX = ConnectivityTestToolbox()
