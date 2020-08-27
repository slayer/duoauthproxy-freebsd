""" Module for providing the LDAP methods needed for SSO functionality
Register this module DrpcServerModule in order to have access to these functions. """
import base64
from typing import Callable, List, Optional, Set
import six

import OpenSSL
import drpc.v2 as drpc
from cryptography.fernet import Fernet, InvalidToken
from ldaptor import ldapfilter
from ldaptor.protocols.ldap import distinguishedname, ldaperrors
from ldaptor.protocols.ldap.ldapsyntax import LDAPEntry
from ldaptor.protocols import pureldap
from ldaptor._encoder import to_bytes
from twisted.internet import defer

from duoauthproxy.lib import ldap, log, const, secret_storage, util
from duoauthproxy.lib.const import AD_AUTH_TYPE_PLAIN
from duoauthproxy.modules.drpc_plugins import ldap_base
from duoauthproxy.types import LDAPAttribute, BytesLDAPEntry


ERR_LDAP_SSO_MISSING_RIKEY = 'Unable to find RIKEY in config'
ERR_LDAP_CANNOT_SERVICE_REQUEST = 'Unable to service request'
ERR_LDAP_PW_DECRYPT_FAILED = 'Unable to decrypt end user password'
ERR_LDAP_INVALID_BASE_DN = 'Unable to find base DN'
ERR_LDAP_BIND_INVALID_CREDS = 'Invalid bind credentials'
ERR_LDAP_NON_UNIQUE_USERNAME_ATTR = "Multiple users found for the provided username"
ERR_LDAP_MISSING_REQUIRED_ATTRIBUTE = "Required attribute is missing"
ERR_LDAP_INVALID_ATTRIBUTE_VALUE = "Invalid attribute value"
ERR_TLS_CERT = 'Problem with TLS cert'
ERR_TLS_INVALID_PROTOCOL = 'TLS protocol version mismatch'
ERR_TLS_GENERIC = 'Could not establish a TLS connection'
ERR_COUNTER_FAILURE = 'Unable to read proxy counter'

AUTH_INVALID_USER = 'Could not find user'
AUTH_TOO_MANY_USERS = 'Search for user returned more than 1 unique user'
AUTH_FAILED = 'Active Directory authentication failed'
AUTH_SUCCEEDED = 'Active Directory authentication succeeded'
FETCH_SUCCESSFUL = 'User attributes were fetched successfully'
FETCH_FAILED = 'User attributes failed to be fetched'
MSDS_PRINCIPAL_NAME_MISSING = 'Required attribute msDS-PrincipalName is missing for user {}'
INVALID_MSDS_PRINCIPAL_NAME = 'Invalid msDS-PrincipalName for user {}. msDS-PrincipalName must have a value of form domain\\sAMAccountName'

# An error string from openssl C library that tells us if a cert is bad
OPENSSL_ERROR_INVALID_CERT = 'certificate verify failed'
OPENSSL_ERROR_INVALID_PROTOCOL = 'unsupported protocol'


class LdapSsoClientProtocol(ldap.client.ADClientProtocol):
    """ This class exists soley to improve the logging during SSO calls. Twisted
    logs class names as a prefix """
    pass


class LdapSsoClientFactory(ldap.client.ADClientFactory):
    """ This class exists soley to improve the logging during SSO calls. Twisted
    logs class names as a prefix """
    protocol = LdapSsoClientProtocol


class LdapSsoDrpcPlugin(ldap_base.BaseLdapDrpcPlugin):
    ldap_client_factory = LdapSsoClientFactory

    def __init__(self, config, ri_credentials):
        """
        config: (config_provider.ConfigDict) a config dict
        ri_credentials: (dict) rikey as the key and ServiceAccountCredential as the value
        """
        super(LdapSsoDrpcPlugin, self).__init__(config)

        self.credential_mapping = ri_credentials
        self.proxy_key = config[const.DRPC_PROXY_KEY_IDENTIFIER]
        encryption_skey = config[const.DRPC_ENCRYPTION_SKEY_IDENTIFIER]
        if isinstance(encryption_skey, six.text_type):
            encryption_skey = encryption_skey.encode('utf-8')
        self.encryption_skey = encryption_skey

    def get_drpc_calls(self):
        return {
            'ldap_authentication': self.do_ldap_authentication,
            'fetch_ldap_attributes': self.do_fetch_ldap_attributes,
            'get_configured_idps': self.do_get_configured_idps,
            'ldap_health_check': self.do_ldap_health_check,
            'get_proxy_counter': self.do_get_proxy_counter,
        }

    def register_new_parameters(self, new_params):
        super(LdapSsoDrpcPlugin, self).register_new_parameters(new_params)

        if 'encryption_skey' in new_params:
            self.encryption_skey = new_params['encryption_skey']

    @drpc.inlineCallbacks
    def do_ldap_authentication(self,
                               servers,
                               username,
                               password,
                               rikey,
                               base_dns=None,
                               ntlm_domain=None,
                               ntlm_workstation=None,
                               auth_type=const.AD_AUTH_TYPE_NTLM_V2,
                               transport_type=const.AD_TRANSPORT_STARTTLS,
                               ssl_verify_depth=const.DEFAULT_SSL_VERIFY_DEPTH,
                               ssl_verify_hostname=True,
                               ssl_ca_certs=None,
                               timeout=60,
                               username_attributes=None,
                               call_id=None):
        creds = self.get_creds_for_ldap_idp(rikey, auth_type)
        service_account_username = creds.username
        service_account_password = creds.password

        self._verify_ldap_config_args(
            service_account_username,
            service_account_password,
            auth_type,
            transport_type
        )

        # Decrypt the end user password using our symmetric key
        try:
            password = self.decrypt_password(password)
        except InvalidToken as e:
            msg = "Unable to decrypt the password for user: {}. Please check that your CloudSSO enrollment code is correct. Failing the authentication".format(username)
            log.msg(msg)
            raise drpc.CallError(ERR_LDAP_PW_DECRYPT_FAILED, {
                'error': str(e),
            })

        res = yield self.perform_authentication(servers,
                                                username,
                                                password,
                                                service_account_username,
                                                service_account_password,
                                                base_dns=base_dns,
                                                ntlm_domain=ntlm_domain,
                                                ntlm_workstation=ntlm_workstation,
                                                auth_type=auth_type,
                                                transport_type=transport_type,
                                                ssl_verify_depth=ssl_verify_depth,
                                                ssl_verify_hostname=ssl_verify_hostname,
                                                ssl_ca_certs=ssl_ca_certs,
                                                timeout=timeout,
                                                username_attributes=username_attributes,
                                                call_id=call_id,
                                                )
        defer.returnValue(res)

    @defer.inlineCallbacks
    def perform_authentication(self,
                               servers,
                               username,
                               password,
                               service_account_username,
                               service_account_password,
                               base_dns=None,
                               ntlm_domain=None,
                               ntlm_workstation=None,
                               auth_type=const.AD_AUTH_TYPE_NTLM_V2,
                               transport_type=const.AD_TRANSPORT_STARTTLS,
                               ssl_verify_depth=const.DEFAULT_SSL_VERIFY_DEPTH,
                               ssl_verify_hostname=True,
                               ssl_ca_certs=None,
                               timeout=60,
                               username_attributes=None,
                               call_id=None):
        """
        Authenticates against the provided servers in random order until
        a successful authentication occurs or the list of servers has been
        exhausted.

        See do_ldap_search for further argument documentation.

        Args:
            servers (list): List of dicts, each containing a 'hostname' and 'port'

        Returns:
            A dict containing:
                success (bool): True if the auth  was successful
                msg (str): The message associated with the result of the auth
                exceptions (list): Dict of CallError keyed on hostname
                    containing any errors that occurred during the
                    authentication process. Note that the presence of errors
                    does not indicate auth failure! For example, the exceptions
                    list will be non-empty if the first server could not be
                    reached but the second server serviced the auth.

        """
        # Assume user authentication never legitimately uses anonymous bind.
        if not password:
            defer.returnValue({
                'success': False,
                'msg': AUTH_FAILED,
                'exceptions': {},
            })

        exceptions = {}
        auth_successful = False
        user_full_dn = None
        # Try each server in random order
        for server in servers:
            host = server['hostname']
            port = server['port']
            try:
                auth_successful, user_full_dn = yield self.authenticate_against_server(
                    host=host,
                    port=port,
                    username=username,
                    password=password,
                    service_account_username=service_account_username,
                    service_account_password=service_account_password,
                    base_dns=base_dns,
                    ntlm_domain=ntlm_domain,
                    ntlm_workstation=ntlm_workstation,
                    auth_type=auth_type,
                    transport_type=transport_type,
                    ssl_verify_depth=ssl_verify_depth,
                    ssl_verify_hostname=ssl_verify_hostname,
                    ssl_ca_certs=ssl_ca_certs,
                    timeout=timeout,
                    username_attributes=username_attributes,
                    call_id=call_id,
                )
                # If we reach this line without an exception, the auth was
                # serviced successfully and we don't need to check any more
                # servers.
                if auth_successful:
                    log.sso_ldap(msg="Successful authentication against server",
                                 query_type=log.SSO_LDAP_QUERY_TYPE_AUTH,
                                 status=log.SSO_LDAP_QUERY_SUCCEEDED,
                                 server=host,
                                 port=port,
                                 username=username,
                                 proxy_key=self.proxy_key)
                else:
                    log.sso_ldap(msg="Failed authentication against server",
                                 query_type=log.SSO_LDAP_QUERY_TYPE_AUTH,
                                 status=log.SSO_LDAP_QUERY_FAILED,
                                 server=host,
                                 port=port,
                                 username=username,
                                 proxy_key=self.proxy_key,
                                 reason='Invalid credentials')
                break
            except drpc.CallError as e:
                # serialize the errors in a similar format to what drpc does
                log.sso_ldap(msg="Failed authentication against server",
                             query_type=log.SSO_LDAP_QUERY_TYPE_AUTH,
                             status=log.SSO_LDAP_QUERY_FAILED,
                             server=host,
                             port=port,
                             username=username,
                             proxy_key=self.proxy_key,
                             reason=e.error)
                exceptions[host] = {
                    'error': e.error,
                    'error_args': e.error_args,
                }

        if self.connection_failures_for_all_servers(servers, exceptions):
            raise drpc.CallError(ERR_LDAP_CANNOT_SERVICE_REQUEST, {
                'error': str('Failed to communicate with any domain controllers')
            })

        if self.too_many_users_failure_on_all_servers(servers, exceptions):
            error = drpc.CallError(ERR_LDAP_NON_UNIQUE_USERNAME_ATTR, {
                'error': 'Each domain controller returned more than one user for the provided username attributes.'
            })
            log.err(error, '{msg} {username}'.format(msg=ERR_LDAP_NON_UNIQUE_USERNAME_ATTR, username=username))
            raise error

        defer.returnValue({
            'success': auth_successful,
            'user_full_dn': user_full_dn,
            'msg': AUTH_SUCCEEDED if auth_successful else AUTH_FAILED,
            'exceptions': exceptions,
        })

    def connection_failures_for_all_servers(self, servers, exceptions):
        if len(servers) != len(exceptions.keys()):
            return False

        for host in exceptions:
            if exceptions[host]['error'] not in [ldap_base.ERR_LDAP_TIMEOUT, ldap_base.ERR_LDAP_CONNECTION_FAILED, ldap_base.ERR_LDAP_HOSTNAME_RESOLUTION_FAILED]:
                return False

        return True

    @staticmethod
    def too_many_users_failure_on_all_servers(servers, exceptions):
        if len(servers) != len(exceptions.keys()):
            return False

        for host in exceptions:
            try:
                error = exceptions[host]['error_args']['error']
            except KeyError:
                return False
            else:
                if AUTH_TOO_MANY_USERS != error:
                    return False

        return True

    @staticmethod
    def to_unicode_ignore_errors(value):
        if isinstance(value, six.binary_type):
            return value.decode('utf-8', errors='ignore')
        return value

    @defer.inlineCallbacks
    def authenticate_against_server(self,
                                    host: str,
                                    port: str,
                                    username: str,
                                    password: str,
                                    service_account_username: str,
                                    service_account_password: str,
                                    base_dns: Optional[List[str]] = None,
                                    ntlm_domain: Optional[str] = None,
                                    ntlm_workstation: Optional[str] = None,
                                    auth_type: str = const.AD_AUTH_TYPE_NTLM_V2,
                                    transport_type: str = const.AD_TRANSPORT_STARTTLS,
                                    ssl_verify_depth: int = const.DEFAULT_SSL_VERIFY_DEPTH,
                                    ssl_verify_hostname: bool = True,
                                    ssl_ca_certs: Optional[str] = None,
                                    timeout: int = 60,
                                    username_attributes: Optional[List[str]] = None,
                                    call_id: Optional[int] = None):

        """
        * username_attribute: attribute within AD that we will compare the
          username against.

        See do_ldap_search for further argument documentation.

        Returns: tuple(bool, str).
            - True if the auth was successful,
            - The full dn of the user who authed
        """

        bind_dn = service_account_username
        bind_pw = service_account_password
        # At this point we *should* have a username attribute passed to us. But if we don't have one
        # we will default to the most popular attribute, samaccountname. This will only work for AD.
        username_attributes = username_attributes if username_attributes else ['samaccountname']
        base_dns = base_dns if base_dns else ['']

        log.msg(("Performing LDAP authentication: "
                 "call_id={call_id} host={host} port={port} base_dns={base_dns} "
                 "auth_type={auth_type} transport_type={transport_type} "
                 "ssl_verify_depth={ssl_verify_depth} ssl_verify_hostname={ssl_verify_hostname} "
                 "ssl_ca_certs={ssl_ca_certs} username={username} username_attributes={username_attributes}"
                 ).format(call_id=call_id, host=host, port=port, base_dns=base_dns, auth_type=auth_type,
                          transport_type=transport_type, ssl_verify_depth=ssl_verify_depth,
                          ssl_verify_hostname=ssl_verify_hostname, username=username,
                          username_attributes=username_attributes, ssl_ca_certs=ssl_ca_certs is not None))

        # The factory has a username attribute field on it but we will not be using it
        cl, timeout_dc = yield self._get_client(
            host,
            port,
            transport_type,
            ssl_verify_depth,
            ssl_verify_hostname,
            ssl_ca_certs,
            timeout,
            self.debug,
            self.is_logging_insecure,
        )

        try:
            # Primary bind. This authenticates us to AD and allows us to
            # make search queries.
            try:
                yield cl.perform_bind(
                    auth_type=auth_type,
                    dn=bind_dn,
                    username=bind_dn,
                    password=bind_pw,
                    domain=ntlm_domain,
                    workstation=ntlm_workstation,
                    permit_implicit=True
                )
            except Exception as e:
                if timeout_dc.active():
                    log.err(e, ldap_base.ERR_LDAP_BIND_FAILED)
                    raise drpc.CallError(ldap_base.ERR_LDAP_BIND_FAILED, {
                        'error': str(e),
                    })
                else:
                    log.err(e, ldap_base.ERR_LDAP_TIMEOUT)
                    raise drpc.CallError(ldap_base.ERR_LDAP_TIMEOUT, {
                        'during': 'bind',
                        'error': str(e),
                    })

            username_match = dict.fromkeys(username_attributes, username)
            filterObject = yield cl.user_filter_object(username_matches=username_match)

            # Search for the user. With AD, the user's cn is their full
            # name, not username. So, we need to search for the user by comparing
            # the username to a selection of specific attributes. For example:
            # sAMAccountName or userprincipalname

            search_hits: List[BytesLDAPEntry] = []
            try:
                # Always fetch msDS-PrincipalName since we need the user's
                # sAMAccountName and domain. The username entered by the user
                # may not be in a valid format for SSPI or NTLM depending on
                # the username attributes configured, but the sAMAccountName
                # that's part of msDS-PrincipalName will always work.
                attributes_to_fetch = {str(attr).lower() for attr in username_attributes}
                attributes_to_fetch.add('msds-principalname')
                # Also fetch some helpful attributes for debugging if something goes wrong
                attributes_to_fetch.add('objectclass')
                attributes_to_fetch.add('objectcategory')

                # To check multiple base dns we need to perform a search for each one. If the
                # combination of all of these searches returns more than 1 unique user we will
                # fail the auth
                for base_dn in base_dns:
                    result = yield cl.perform_search(base_dn, filterObject, attributes=tuple(attributes_to_fetch))
                    search_hits.extend(result)
            except distinguishedname.InvalidRelativeDistinguishedName as e:
                log.err(e, ldap_base.ERR_LDAP_BAD_AD_CONFIGURATION)
                raise drpc.CallError(ldap_base.ERR_LDAP_BAD_AD_CONFIGURATION, {
                    'error': str(e),
                })
            except Exception as e:
                log.err(e, '{msg} for {username}'.format(msg=ldap_base.ERR_LDAP_SEARCH_FAILED, username=username))
                raise drpc.CallError(ldap_base.ERR_LDAP_SEARCH_FAILED, {
                    'error': str(e),
                })

            if len(search_hits) == 0:
                err_msg = AUTH_INVALID_USER
                err = drpc.CallError(ldap_base.ERR_LDAP_SEARCH_FAILED, {
                    'error': err_msg,
                })
                log.err(err, '{msg} {username}'.format(msg=err_msg, username=username))
                raise err

            if len(search_hits) > 1:
                err_msg = AUTH_TOO_MANY_USERS
                err = drpc.CallError(ldap_base.ERR_LDAP_SEARCH_FAILED, {
                    'error': err_msg,
                })
                log.err(err, '{msg} while searching for {username}: {users}'.format(
                    msg=err_msg,
                    username=username,
                    users=[str(user.dn) for user in search_hits]))
                raise err

            user_result = search_hits[0]
            user_full_dn = str(user_result.dn)
            # Log out the search result
            matched_attributes = determine_matched_attributes(username, username_attributes, user_result)
            log.msg('Found {username} with attributes {atts}'.format(username=username, atts=matched_attributes))

            # Initialize these as None since Plain binds don't these values
            bind_username = None
            user_domain = None
            # If the auth type is not plain, determine the user's domain and
            # sAMAccountName by pulling them from msDS-PrincipalName. We need
            # both in order to do NTLM and SSPI authentications.
            if auth_type != AD_AUTH_TYPE_PLAIN:
                msds_principalname_attribute_set = user_result.get('msDS-PrincipalName')
                if not msds_principalname_attribute_set:
                    # msDS-PrincipalName must be provided so we can determine
                    # the domain of the user authenticating. Abort the
                    # authentication if the attribute doesn't exist for the user.
                    err = drpc.CallError(ERR_LDAP_MISSING_REQUIRED_ATTRIBUTE, {
                        'error': MSDS_PRINCIPAL_NAME_MISSING.format(username)
                    })
                    log.err(err, user_result)
                    raise err

                msds_principalname = list(user_result.get('msDS-PrincipalName'))[0].decode('utf8')
                if not msds_principalname or '\\' not in msds_principalname:
                    # This means that msDS-PrincipalName was empty, a form
                    # we can't work with (e.g. SID), or didn't have any
                    # domain information on it. We can't guarantee we'll
                    # log in the correct user without knowing their domain,
                    # so abort the authentication.
                    err = drpc.CallError(ERR_LDAP_INVALID_ATTRIBUTE_VALUE, {
                        'error': INVALID_MSDS_PRINCIPAL_NAME.format(username)
                    })
                    log.err(err, user_result)
                    raise err

                user_domain, bind_username = msds_principalname.split('\\', 1)

            # Secondary bind. Assuming the user we queried exists, attempt
            # to bind as them (this is essentially performing an authentication).
            try:
                yield cl.perform_bind(
                    auth_type=auth_type,
                    dn=user_full_dn,
                    username=bind_username,
                    password=password,
                    domain=user_domain,
                    workstation=ntlm_workstation,
                    permit_implicit=False
                )
            except Exception as e:
                log.msg('Authentication failed for user {username} ({dn})'.format(username=username, dn=user_full_dn))
                log.msg(e)
                defer.returnValue((False, None))
        finally:
            if timeout_dc.active():
                timeout_dc.cancel()
            try:
                cl.transport.abortConnection()
            except Exception:
                pass

        log.msg('Authentication succeeded for user {username} ({dn})'.format(username=username, dn=user_full_dn))
        defer.returnValue((True, user_full_dn))

    @drpc.inlineCallbacks
    def do_fetch_ldap_attributes(self,
                                 servers,
                                 rikey,
                                 desired_attributes,
                                 user_dn,
                                 ntlm_domain=None,
                                 ntlm_workstation=None,
                                 auth_type=const.AD_AUTH_TYPE_NTLM_V2,
                                 transport_type=const.AD_TRANSPORT_STARTTLS,
                                 ssl_verify_depth=const.DEFAULT_SSL_VERIFY_DEPTH,
                                 ssl_verify_hostname=True,
                                 ssl_ca_certs=None,
                                 timeout=60,
                                 call_id=None,
                                 ):
        exceptions = {}
        search_successful = False
        search_result = {}
        for server in servers:
            host = server['hostname']
            port = server['port']
            try:
                search_result = yield self.fetch_ldap_attributes_from_server(host=host,
                                                                             port=port,
                                                                             rikey=rikey,
                                                                             desired_attributes=desired_attributes,
                                                                             user_dn=user_dn,
                                                                             ntlm_domain=ntlm_domain,
                                                                             ntlm_workstation=ntlm_workstation,
                                                                             auth_type=auth_type,
                                                                             transport_type=transport_type,
                                                                             ssl_verify_depth=ssl_verify_depth,
                                                                             ssl_verify_hostname=ssl_verify_hostname,
                                                                             ssl_ca_certs=ssl_ca_certs,
                                                                             timeout=timeout,
                                                                             call_id=call_id)
                search_successful = True
                log.sso_ldap(msg="Fetched LDAP attributes from server",
                             query_type=log.SSO_LDAP_QUERY_TYPE_ATTRIBUTE_FETCH,
                             status=log.SSO_LDAP_QUERY_SUCCEEDED,
                             server=host,
                             port=port,
                             username=user_dn,
                             proxy_key=self.proxy_key)
                break
            except drpc.CallError as e:
                log.sso_ldap(msg="Failed to failed to fetch LDAP attributes from server",
                             query_type=log.SSO_LDAP_QUERY_TYPE_ATTRIBUTE_FETCH,
                             status=log.SSO_LDAP_QUERY_FAILED,
                             server=host,
                             port=port,
                             username=user_dn,
                             proxy_key=self.proxy_key,
                             reason=e.error)
                exceptions[host] = {
                    'error': e.error,
                    'error_args': e.error_args
                }

        if self.connection_failures_for_all_servers(servers, exceptions):
            raise drpc.CallError(ERR_LDAP_CANNOT_SERVICE_REQUEST, {
                'error': str('Failed to communicate with any domain controllers')
            })

        defer.returnValue({
            'success': search_successful,
            'attributes': search_result,
            'msg': FETCH_SUCCESSFUL if search_successful else FETCH_FAILED,
            'exceptions': exceptions
        })

    @defer.inlineCallbacks
    def fetch_ldap_attributes_from_server(self,
                                          host,
                                          port,
                                          rikey,
                                          desired_attributes,
                                          user_dn,
                                          ntlm_domain=None,
                                          ntlm_workstation=None,
                                          auth_type=const.AD_AUTH_TYPE_NTLM_V2,
                                          transport_type=const.AD_TRANSPORT_STARTTLS,
                                          ssl_verify_depth=const.DEFAULT_SSL_VERIFY_DEPTH,
                                          ssl_verify_hostname=True,
                                          ssl_ca_certs=None,
                                          timeout=60,
                                          call_id=None,
                                          ):
        creds = self.get_creds_for_ldap_idp(rikey, auth_type)
        bind_dn = creds.username
        bind_pw = creds.password

        log.msg(("Performing user attributes fetch: "
                 "call_id={call_id} host={host} port={port} rikey={rikey} "
                 "desired_attributes={desired_attributes} user_dn={user_dn} ntlm_domain={ntlm_domain} "
                 "ntlm_workstation={ntlm_workstation} auth_type={auth_type} transport_type={transport_type} "
                 "ssl_verify_depth={ssl_verify_depth} ssl_verify_hostname={ssl_verify_hostname} "
                 "ssl_ca_certs={ssl_ca_certs}"
                 ).format(call_id=call_id, host=host, port=port, rikey=rikey,
                          desired_attributes=desired_attributes, user_dn=user_dn, ntlm_domain=ntlm_domain,
                          ntlm_workstation=ntlm_workstation, auth_type=auth_type, transport_type=transport_type,
                          ssl_verify_depth=ssl_verify_depth, ssl_verify_hostname=ssl_verify_hostname,
                          ssl_ca_certs=ssl_ca_certs is not None))

        self._verify_ldap_config_args(bind_dn, bind_pw, auth_type, transport_type)

        client, timeout_dc = yield self._get_client(
            host,
            port,
            transport_type,
            ssl_verify_depth,
            ssl_verify_hostname,
            ssl_ca_certs,
            timeout,
            self.debug,
            self.is_logging_insecure
        )

        # Try to do everything network-related
        try:
            # Bind as service user, for searching
            try:
                yield client.perform_bind(
                    auth_type=auth_type,
                    dn=bind_dn,
                    username=bind_dn,
                    password=bind_pw,
                    domain=ntlm_domain,
                    workstation=ntlm_workstation,
                    permit_implicit=True
                )
            except Exception as e:
                if timeout_dc.active():
                    log.err(e, ldap_base.ERR_LDAP_BIND_FAILED)
                    raise drpc.CallError(ldap_base.ERR_LDAP_BIND_FAILED,
                                         {
                                             'error': six.text_type(e)
                                         })
                else:
                    log.err(e, ldap_base.ERR_LDAP_TIMEOUT)
                    raise drpc.CallError(ldap_base.ERR_LDAP_TIMEOUT,
                                         {
                                             'during': 'bind',
                                             'error': six.text_type(e)
                                         })

            # Search for the user
            try:
                result = yield client.perform_search(user_dn, None, attributes=desired_attributes, scope=pureldap.LDAP_SCOPE_baseObject)

                if len(result) != 1:
                    log.err(AUTH_INVALID_USER)
                    raise Exception(AUTH_INVALID_USER)

                result = result[0]
            except distinguishedname.InvalidRelativeDistinguishedName as irdn:
                log.err(irdn, ldap_base.ERR_LDAP_BAD_AD_CONFIGURATION)
                raise drpc.CallError(ldap_base.ERR_LDAP_BAD_AD_CONFIGURATION,
                                     {
                                         'error': six.text_type(irdn)
                                     })
            except Exception as e:
                log.err(e, ldap_base.ERR_LDAP_SEARCH_FAILED)
                raise drpc.CallError(ldap_base.ERR_LDAP_SEARCH_FAILED,
                                     {
                                         'error': six.text_type(e)
                                     })
        finally:
            # Clean up networking
            if timeout_dc.active():
                timeout_dc.cancel()

            try:
                client.transport.abortConnection()
            except Exception:
                pass

        # At this point, result is a single LDAPEntry, or something has gone wrong and we ideally raised somewhere above
        encoded_dict = transform_result(result, desired_attributes)

        logged_atts = transform_result(result, desired_attributes, value_transform=self.to_unicode_ignore_errors)
        log.msg('For user dn {dn}, found attributes {atts}'.format(dn=user_dn, atts=logged_atts))

        defer.returnValue(encoded_dict)

    @drpc.inlineCallbacks
    def do_ldap_health_check(self,
                             rikey,
                             host,
                             port,
                             base_dns,
                             filter_text=None,
                             attributes=None,
                             ntlm_domain=None,
                             ntlm_workstation=None,
                             auth_type=const.AD_AUTH_TYPE_NTLM_V2,
                             transport_type=const.AD_TRANSPORT_STARTTLS,
                             ssl_verify_depth=const.DEFAULT_SSL_VERIFY_DEPTH,
                             ssl_verify_hostname=True,
                             ssl_ca_certs=None,
                             timeout=60,
                             call_id=None):
        """
        Performs a health check against the specified host by binding as the
        service user and executing a dummy search against each provided base DN
        to ensure the searches are executed without error.
        """

        # Do this outside of the try/except. If something goes wrong with these
        # operations, then we should raise that error and not treat it as an
        # unhealthy result.
        service_account_credentials = self.get_creds_for_ldap_idp(rikey, auth_type)

        self._verify_ldap_config_args(service_account_credentials.username, service_account_credentials.password, auth_type, transport_type)

        log.msg(("Performing health check: "
                 "call_id={call_id} host={host} port={port} rikey={rikey} "
                 "attributes={attributes} base_dns={base_dns} ntlm_domain={ntlm_domain} "
                 "ntlm_workstation={ntlm_workstation} auth_type={auth_type} transport_type={transport_type} "
                 "ssl_verify_depth={ssl_verify_depth} ssl_verify_hostname={ssl_verify_hostname} "
                 "ssl_ca_certs={ssl_ca_certs}"
                 ).format(call_id=call_id, host=host, port=port, rikey=rikey,
                          attributes=attributes, base_dns=base_dns,
                          ntlm_domain=ntlm_domain, ntlm_workstation=ntlm_workstation,
                          auth_type=auth_type, transport_type=transport_type,
                          ssl_verify_depth=ssl_verify_depth,
                          ssl_verify_hostname=ssl_verify_hostname,
                          ssl_ca_certs=ssl_ca_certs is not None))

        client, timeout_dc = yield self._get_client(
            host,
            port,
            transport_type,
            ssl_verify_depth,
            ssl_verify_hostname,
            ssl_ca_certs,
            timeout,
            self.debug,
            self.is_logging_insecure
        )

        try:
            try:
                # First make sure we can bind as the service user
                yield client.perform_bind(
                    auth_type=auth_type,
                    dn=service_account_credentials.username,
                    username=service_account_credentials.username,
                    password=service_account_credentials.password,
                    domain=ntlm_domain,
                    workstation=ntlm_workstation,
                    permit_implicit=True
                )
            except OpenSSL.SSL.Error as e:
                error_message = util.retrieve_error_string_from_openssl_error(e)
                if OPENSSL_ERROR_INVALID_CERT in error_message:
                    drpc_error = ERR_TLS_CERT
                elif OPENSSL_ERROR_INVALID_PROTOCOL in error_message:
                    drpc_error = ERR_TLS_INVALID_PROTOCOL
                else:
                    drpc_error = ERR_TLS_GENERIC
                log.err(e, drpc_error)
                raise drpc.CallError(drpc_error, {
                    'error': str(e),
                })
            except ldaperrors.LDAPInvalidCredentials as e:
                raise drpc.CallError(ERR_LDAP_BIND_INVALID_CREDS, {
                    'error': str(e),
                })
            except Exception as e:
                # T76043: add better/more specific error handling so we can tell
                # Gary why the search failed
                if timeout_dc.active():
                    log.err(e, ldap_base.ERR_LDAP_BIND_FAILED)
                    raise drpc.CallError(ldap_base.ERR_LDAP_BIND_FAILED, {
                        'error': str(e),
                    })
                else:
                    log.err(e, ldap_base.ERR_LDAP_TIMEOUT)
                    raise drpc.CallError(ldap_base.ERR_LDAP_TIMEOUT, {
                        'during': 'bind',
                        'error': str(e),
                    })

            # Then execute a search over each provided base DN to make sure that:
            #   1) The service user has search permissions
            #   2) Each of the provided base DN's exists
            filter_obj = ldapfilter.parseFilter(filter_text.encode('utf-8')) if filter_text else None
            try:
                for base_dn in base_dns:
                    yield client.perform_search(
                        dn=base_dn,
                        filter_object=filter_obj,
                        attributes=attributes,
                        scope=pureldap.LDAP_SCOPE_baseObject,
                        sizeLimit=1
                    )
            except (ldaperrors.LDAPNoSuchObject, ldaperrors.LDAPReferral) as e:
                # https://ldap.com/ldap-result-code-reference-core-ldapv3-result-codes/#rc-noSuchObject
                # Object at the requested BaseDN doesn't exist. Since we are searching for just anything at all
                # this likely means the Base DN is invalid.
                # https://ldap.com/ldap-result-code-reference-core-ldapv3-result-codes/#rc-referral
                # We dont support referrals so it's basically an unknown/bad DN
                log.err(e, ERR_LDAP_INVALID_BASE_DN)
                raise drpc.CallError(ERR_LDAP_INVALID_BASE_DN, {
                    'error': str(e),
                    'base_dn': str(base_dn)
                })
            except Exception as e:
                # T76043: add better/more specific error handling so we can tell
                # Gary why the search failed
                if timeout_dc.active():
                    log.err(e, ldap_base.ERR_LDAP_SEARCH_FAILED)
                    raise drpc.CallError(ldap_base.ERR_LDAP_SEARCH_FAILED, {
                        'error': str(e),
                    })
                else:
                    log.err(e, ldap_base.ERR_LDAP_TIMEOUT)
                    raise drpc.CallError(ldap_base.ERR_LDAP_TIMEOUT, {
                        'during': 'search',
                        'error': str(e),
                    })
        finally:
            if timeout_dc.active():
                timeout_dc.cancel()
            try:
                client.transport.abortConnection()
            except Exception as e:
                log.err(e, "Error cleaning up connection to host {}".format(host))

        # If nothing went wrong by this point, then everything's healthy as
        # far as we can tell.
        result = {
            'healthy': True,
        }

        log.msg(result)
        defer.returnValue(result)

    def do_get_configured_idps(self):
        rikeys = list(self.credential_mapping.keys())
        log.msg("Returning list of configured IdPs. {}".format(rikeys))
        return {
            'rikeys': rikeys
        }

    def do_get_proxy_counter(self):
        log.msg('Reporting proxy counter')
        try:
            counter = secret_storage.access_proxy_counter()
            if self.debug:
                log.msg('Found counter value {counter}'.format(counter=counter))
        except Exception as e:
            log.err(e, ERR_COUNTER_FAILURE)
            raise drpc.CallError(ERR_COUNTER_FAILURE, {
                'during': 'get_proxy_counter',
                'error': str(e)
            })

        return {
            'counter': counter,
        }

    def decrypt_password(self, encrypted_password):
        """ Pull out the symmetric key from the secret storage and use it to
        decrypt the provided password.
        Args:
            encrypted_password (str): six.text_type or six.binary_type
        Returns:
            str: six.text_type
        """
        fernet = Fernet(self.encryption_skey)

        if isinstance(encrypted_password, six.text_type):
            encrypted_password = encrypted_password.encode('utf-8')

        return fernet.decrypt(encrypted_password).decode()

    def get_creds_for_ldap_idp(self, rikey, auth_type):
        try:
            creds = self.credential_mapping[rikey]
            if auth_type == const.AD_AUTH_TYPE_SSPI:
                creds = ldap_base.ServiceAccountCredential(username=None, password=None)

            return creds
        except KeyError as e:
            log.err(e, ERR_LDAP_SSO_MISSING_RIKEY)
            raise drpc.CallError(ERR_LDAP_SSO_MISSING_RIKEY, {
                'error': str(e),
            })


def encoding_transform(value: LDAPAttribute) -> str:
    return base64.standard_b64encode(to_bytes(value)).decode()


def transform_result(result: LDAPEntry,
                     desired_attributes: List[str],
                     value_transform: Callable[[LDAPAttribute], str] = encoding_transform):
    """
    Turn an LDAPEntry result into a dictionary of attribute values.

    Args:
        result (LDAPEntry): an LDAPEntry
        desired_attributes (list): The desired attributes
        value_transform (func): a per-value transform function to apply

    Returns:
        A dict of {attribute name: [list of attribute values]} for the requested attributes
    """
    result_dict = {}
    for att in desired_attributes:
        attset = result.get(att, [])
        transformed_values = set()
        for val in list(attset):
            transformed_values.add(value_transform(val))
        result_dict[att] = list(transformed_values)

    result_dict.pop('userpassword', None)

    return result_dict


def determine_matched_attributes(target_username: str, candidate_attributes: List[str], user_result) -> List[str]:
    """
    Args:
        target_username (str):
        candidate_attributes (list[str]):
        user_result (LDAPEntry):

    Returns:
        list[str]: the subset of the candidate_attributes present on the user result which matched the target username
    """
    matches = []

    for attribute in candidate_attributes:
        result_attributes_as_bytes: Set[bytes] = set(user_result.get(attribute, {}))
        result_attributes_as_strings: List[str] = [attr.decode('utf8') for attr in result_attributes_as_bytes]
        if target_username in result_attributes_as_strings:
            matches.append(attribute)

    return matches
