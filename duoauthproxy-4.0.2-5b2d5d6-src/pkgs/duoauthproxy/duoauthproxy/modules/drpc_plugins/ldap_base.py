#
# Copyright (c) 2019 Duo Security
# All Rights Reserved
#
"""
This is the base class for plugins that contain functionality for performing
LDAP-related operations.

The functions defined in this class, and any subclasses, are intended to be
invoked via Duo Remote Procedure Calls.
"""
import abc

from drpc.shared import exceptions as drpc_exceptions
from twisted.internet import defer, reactor
from twisted.internet.error import DNSLookupError

from duoauthproxy.lib import ldap, log, const
from duoauthproxy.lib.ssl_verify import load_ca_bundle

# ERR_LDAP* errors are returned by the proxy to our service over DDRPC.
ERR_LDAP_BIND_FAILED = 'LDAP bind failed'
ERR_LDAP_CONFIGURATION_FAILED = 'LDAP configuration failed'
ERR_LDAP_CONNECTION_FAILED = 'LDAP connection failed'
ERR_LDAP_HOSTNAME_RESOLUTION_FAILED = 'Failed to resolve domain controller hostname'
ERR_LDAP_PW_ENCRYPT_FAILED = 'password decryption failed'
ERR_LDAP_SEARCH_FAILED = 'LDAP search failed'
ERR_LDAP_TIMEOUT = 'LDAP timeout'
ERR_LDAP_BAD_AD_CONFIGURATION = 'Bad AD client configuration value'

CONFIG_BIND_USER = 'service_account_username'
CONFIG_BIND_PASSWORD = 'service_account_password'


class ServiceAccountCredential(object):
    def __init__(self, username=None, password=None):
        self._username = username
        self._password = password

    @property
    def username(self):
        return self._username

    @property
    def password(self):
        return self._password


class BaseLdapClientProtocol(ldap.client.ADClientProtocol):
    """ This class exists solely to improve the logging during calls. Twisted
    logs class names as a prefix. We can use this to determine this is a generic
    ldap plugin """
    pass


class BaseLdapClientFactory(ldap.client.ADClientFactory):
    """ This class exists solely to improve the logging during calls. Twisted
    logs class names as a prefix. We can use this to determine this is a generic
    ldap plugin """
    protocol = BaseLdapClientProtocol


class BaseLdapDrpcPlugin(abc.ABC):

    ldap_client_factory = BaseLdapClientFactory

    def __init__(self, config):
        self.debug = config.get_bool('debug', False)
        self.is_logging_insecure = config.get_bool('is_logging_insecure', False)

    @abc.abstractmethod
    def get_drpc_calls(self):
        """ Returns a list of available RPCs. The local function can return a deferred but
        it cannot use a inlineCallbacks decorator.

        Returns:
            A dict where the key is the DRPC call name and the value is the function to invoke
            in the Authentication Proxy.
        """
        pass

    def register_new_parameters(self, new_params):
        """
        Called to notify the plugin of any new parameters.  The plugin can decide which, if any, it cares about

        Args:
            new_params: dict with any new parameters the plugin may care about

        """
        pass

    @defer.inlineCallbacks
    def _get_client(self,
                    host,
                    port,
                    transport_type,
                    ssl_verify_depth,
                    ssl_verify_hostname,
                    ssl_ca_certs,
                    timeout,
                    debug,
                    is_logging_insecure):
        if ssl_ca_certs:
            ssl_ca_certs = load_ca_bundle(ssl_ca_certs)
            if not ssl_ca_certs:
                # Didn't parse out any PEM certificates.
                raise drpc_exceptions.CallBadArgError(['ssl_ca_certs'])
        else:
            # Ensure ssl_ca_certs is a list.
            ssl_ca_certs = []

        is_ssl = transport_type != const.AD_TRANSPORT_CLEAR
        if is_ssl:
            if ssl_verify_hostname and not ssl_ca_certs:
                log.msg('Missing required configuration item: '
                        "'SSL verify hostname' requires that "
                        "'SSL CA certs' also be specified "
                        '(and non-empty).')
                raise drpc_exceptions.CallError(ERR_LDAP_CONFIGURATION_FAILED)

        try:
            factory = self.ldap_client_factory(
                timeout=timeout,
                transport_type=transport_type,
                ssl_verify_depth=ssl_verify_depth,
                ssl_verify_hostname=ssl_verify_hostname,
                ssl_ca_certs=ssl_ca_certs,
                debug=debug,
                is_logging_insecure=is_logging_insecure,
            )
        except Exception as e:
            log.err(e, ERR_LDAP_CONFIGURATION_FAILED)
            raise drpc_exceptions.CallError(ERR_LDAP_CONFIGURATION_FAILED, {
                'error': str(e),
            })

        try:
            factory.connect_ldap(host, port)
            client = yield factory.deferred
        except ldap.client.ADClientError as e:
            if isinstance(e.underlying_exception, DNSLookupError):
                log.err(e, ERR_LDAP_HOSTNAME_RESOLUTION_FAILED)
                raise drpc_exceptions.CallError(ERR_LDAP_HOSTNAME_RESOLUTION_FAILED, {
                    'error': str(e),
                })
            else:
                log.err(e, ERR_LDAP_CONNECTION_FAILED)
                raise drpc_exceptions.CallError(ERR_LDAP_CONNECTION_FAILED, {
                    'error': str(e),
                })
        except Exception as e:
            log.err(e, ERR_LDAP_CONNECTION_FAILED)
            raise drpc_exceptions.CallError(ERR_LDAP_CONNECTION_FAILED, {
                'error': str(e),
            })

        def timeout_cb():
            log.msg('LDAP operation timed out')
            client.transport.abortConnection()
        timeout_dc = reactor.callLater(timeout, timeout_cb)

        defer.returnValue((client, timeout_dc))

    def _verify_ldap_config_args(self,
                                 bind_dn: str,
                                 bind_pw: str,
                                 auth_type: str,
                                 transport_type: str) -> None:
        if auth_type not in const.AD_AUTH_TYPES:
            raise drpc_exceptions.CallBadArgError(['auth_type'])
        if transport_type not in const.AD_TRANSPORTS:
            raise drpc_exceptions.CallBadArgError(['transport_type'])
        if auth_type != const.AD_AUTH_TYPE_SSPI \
                and (bind_dn == '' or bind_pw == ''):
            e = drpc_exceptions.CallError(ERR_LDAP_CONFIGURATION_FAILED, {
                'authproxy_configuration_error': 'Missing {0} or {1}'.format(
                    CONFIG_BIND_USER, CONFIG_BIND_PASSWORD)
            })
            log.err(e, ERR_LDAP_CONFIGURATION_FAILED)
            raise e
