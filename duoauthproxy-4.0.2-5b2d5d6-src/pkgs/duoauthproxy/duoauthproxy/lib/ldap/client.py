import struct
from typing import Tuple, Optional, Dict

from twisted.internet import defer
from twisted.internet import protocol
from twisted.internet import reactor

from ldaptor import ldapfilter
from ldaptor.protocols import pureldap
from ldaptor.protocols.ldap import ldapclient
from ldaptor.protocols.ldap import ldaperrors
from ldaptor.protocols.ldap.distinguishedname import DistinguishedName
from ldaptor.protocols.ldap.ldapsyntax import LDAPEntry

from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import UnsupportedAlgorithm

from ..ssl_verify import create_context_factory
from . import utilities
from .. import log, ntlm, const

try:
    import sspi
    import sspicon
    import win32security
except ImportError:
    sspi = None
    sspicon = None
    win32security = None

# Not defined in sspicon, for some reason...
ISC_REQ_NO_INTEGRITY = 0x00800000

# active directory error code given when we search using an attribute range
# that exceeds the total number of elements in the multi-value attribute.
ERR_AD_CANT_RETRIEVE_ATTS = b'00002121'


class ADClientError(Exception):
    def __init__(self, message, underlying_exception=None):
        super(ADClientError, self).__init__(message)
        self.underlying_exception = underlying_exception


class SSPIError(ADClientError):
    pass


class InvalidSecurityGroupDn(Exception):
    pass


class MissingObjectSid(Exception):
    pass


class DnLookupFailed(Exception):
    pass


class NoUserFound(Exception):
    pass


class ADClientProtocol(ldapclient.LDAPClient, object):
    """
    LDAPClient with utility methods needed for proxying.
    """

    def __init__(self):
        super(ADClientProtocol, self).__init__()
        self._tls_ensured = None
        self.unsolicited_notification_handler = None
        self.upstream_server_disconnect_handler = None
        self.factory: protocol.Factory

    def connectionMade(self):
        super(ADClientProtocol, self).connectionMade()

        if self.factory.transport_type == const.AD_TRANSPORT_STARTTLS:
            self._tls_ensured = self.startTLS(self.factory.ssl_context_factory)
        else:
            self._tls_ensured = defer.succeed(True)
        self.factory.deferred.callback(self)

    def connectionLost(self, reason=protocol.connectionDone):
        super(ADClientProtocol, self).connectionLost(reason)
        if callable(self.upstream_server_disconnect_handler):
            try:
                host = self.transport.connector.host
                port = self.transport.connector.port
            except AttributeError:
                host = 'unknown'
                port = 'unknown'
            self.upstream_server_disconnect_handler(reason, host, port)  # pylint: disable=E1102

    @defer.inlineCallbacks
    def user_filter_object(self, username_matches=None):
        """
        Return a filterObject for searching for a dict of username attributes.

        If username_match is not None, add a filter requiring that at least one
        of the username attributes match the specified value.

        ex. {'uid': 'jack', 'mail': 'jack@example.com'} would require one of these
        fields to be set to the specified value
        """
        filter_objs = []

        if username_matches:
            filter_objs.append(self._create_username_attribute_filter(username_matches))

        # Requires that the user is in the security group if one is provided.
        # Group must be either one of the user's memberof attributes or the primarygroupid attribute.
        security_group_filter_obj = yield self._create_security_group_filter()
        if security_group_filter_obj:
            filter_objs.append(security_group_filter_obj)

        # Add filter to match only objects that are users.
        filter_objs.append(self.factory.user_filter)

        # Config can supply an optional extra filter expression to
        # be AND'd with the above.
        if self.factory.ldap_filter is not None:
            filter_objs.append(self.factory.ldap_filter)

        defer.returnValue(pureldap.LDAPFilter_and(filter_objs))

    def create_service_account_user_filter_object(self, username_matches):
        """
        Return a filterObject for searching for a potential service account user with the provided
        username_matches.
        While this method could find objects that aren't service accounts, use with caution
        because this filter does not check extra configuration options like security_group_dn or ldap_filter.
        The returned filter will only make sure that the object is a user type object and that they have
        an attribute that matches the provided username. That last bit is determined by username_matches.

        Args:
            username_matches: {'uid': 'jack', 'mail': 'jack@example.com'}
        """
        filter_objs = [
            self._create_username_attribute_filter(username_matches),
            self.factory.user_filter,
        ]

        return pureldap.LDAPFilter_and(filter_objs)

    def _create_username_attribute_filter(self, username_matches):
        """
        Creates filter requiring that at least one
        of the username attributes match the specified value.

        ex. {'uid': 'jack', 'mail': 'jack@example.com'} would require one of these
        fields to be set to the specified value
        """
        username_filters = self.dict_to_equality_filters(username_matches)
        return pureldap.LDAPFilter_or(username_filters)

    @defer.inlineCallbacks
    def _create_security_group_filter(self):
        """ Create a filter that requires that the user is in the security group if one is provided.
        Group must be either one of the user's memberof attributes or be the users primarygroup.
        Returns:
            None if we don't have a security gruop
            LDAPFilter object if one is created
        """
        if not self.factory.security_group:
            defer.returnValue(None)

        # Look for security_group_dn in the memberof attribute.
        # This is the most common way a security_group_dn is tied to a user
        group_match_mapping = {
            'memberof': self.factory.security_group,
        }

        # If we want customers to be able to specify a primary group as their security_group_dn we need an extra search here
        # to look up objectsid for the group. Then we can take the RID off the objectsid and use that for the
        # primarygroupid comparison
        try:
            object_sid = yield self.get_object_sid_for_group(self.factory.security_group)
        except (InvalidSecurityGroupDn, MissingObjectSid, utilities.InvalidSid) as e:
            # We want to fail safely here because not all LDAP Servers may have an objectSID
            if self.debug:
                log.msg("Tried to search security group DN for object sid but it could not be found. Falling back to just checking memberOf. Error: {}".format(e))
        else:
            security_group_rid = object_sid.split('-')[-1]
            group_match_mapping['primarygroupid'] = security_group_rid

        group_match_filters = self.dict_to_equality_filters(group_match_mapping)
        group_filter = pureldap.LDAPFilter_or(group_match_filters)
        defer.returnValue(group_filter)

    def dict_to_equality_filters(self, d):
        """ Takes a dict of key value pairs and turns them into a list of LDAP equality matches
        Args:
            d: (dict) attribute: value
        Returns:
            List of LDAPFilter_equalityMatch objects
        """
        filters = []
        for attribute, value in d.items():
            attr_obj = pureldap.LDAPAttributeDescription(attribute)
            value_obj = pureldap.LDAPAssertionValue(value)
            filters.append(pureldap.LDAPFilter_equalityMatch(attr_obj, value_obj))

        return filters

    @defer.inlineCallbacks
    def get_object_sid_for_group(self, group_dn):
        """ Search for the group's object sid. Convert the binary SID to string format
        Args:
            group_dn (str): Full DN
        Returns:
            sid (str): S-1-1234-1234-1234
        Raises:
            If security group could not be found or group has no objectsid
        """
        try:
            search_res = yield self.perform_search(
                dn=group_dn,
                filter_object=None,
                attributes=tuple(['objectsid']),
                sizeLimit=1,
                scope=pureldap.LDAP_SCOPE_baseObject,
            )
        except (ldaperrors.LDAPNoSuchObject, ldaperrors.LDAPReferral):
            raise InvalidSecurityGroupDn('{} could not be found'.format(group_dn))

        if len(search_res) != 1:
            raise InvalidSecurityGroupDn('Search for {} did not return exactly 1 group'.format(group_dn))

        security_group = search_res[0]
        security_group_objectsid = security_group.get('objectsid', None)
        if not security_group_objectsid:
            raise MissingObjectSid('Object sid not found for {}'.format(group_dn))

        object_sid_str = utilities.convert_binary_sid_to_string(list(security_group_objectsid)[0])
        defer.returnValue(object_sid_str)

    @defer.inlineCallbacks
    def validate_ldap_username_for_auth(self, possible_username: str, search_dn: str, domain_discovery: bool):
        """
        Takes in a potential username and looks it up against attributes in the AD
        to validate to make sure the user does exist.
        This also serves the purpose of checking security groups and ldapfilters to make sure
        the user is allowed in.
        We will then return the user object if the username was able to be validated and is safe to use with Duo or for NTLM auth.
        If not we will raise an exception.
        Returns:
            LDAPEntryWithClient: The full user object for the given username
        Raises:
            NoUserFound: If the user could not be found because of the name was bad or didn't match the filters
        """
        username_filter = self._create_username_filter(possible_username)
        if username_filter is None:
            raise Exception("Username: {} was not provided in a supported format. Failing the authentication.".format(possible_username))
        user_filter_obj = yield self.user_filter_object(username_filter)

        attributes_to_fetch = tuple(['msds-PrincipalName'])
        result = yield self.perform_search(search_dn, user_filter_obj, attributes=attributes_to_fetch)

        if len(result) == 1:
            # The "DN" matched against one of the username attributes so we can just return
            # that "DN" as the actual username to use with Duo.
            defer.returnValue(result[0])

        # At this point we have apparently found a duplicate match for this user or possibly no users.
        # We will do an additional check to also validate the domain and see if we
        # can narrow it down. Note: This only works with Active Directory.
        if 'sAMAccountName' in username_filter and domain_discovery:
            for match in result:
                user_principal_name = list(match.get('msDS-PrincipalName', [b'']))[0]
                if user_principal_name.decode().lower() == possible_username.lower():
                    # The "DN" matched the msDS-PrincipalName attribute (eg. DOMAIN\username)
                    # Because msDS-PrincipalNames are guaranteed unique we can just return that
                    # value up to Duo to be used
                    defer.returnValue(match)

        # At this point we had either no users or multiple users and we couldn't figure out how narrow it down.
        # We need to fail
        if len(result) > 1:
            err_msg = "Found too many users with username: {}".format(possible_username)
        else:
            err_msg = "Could not find user with username: {}. It's possible this user does not exist or did not match your configured security filters.".format(possible_username)

        raise NoUserFound(err_msg)

    @defer.inlineCallbacks
    def dn_to_username(self, dn_str: str, client_factory):
        """
        Return a username usable for Duo auth.

        The return value may include a domain. If necessary, that must
        be handled with a domain username normalization policy on the
        Duo integration.
        Args:
            dn_str: (str)
            client_factory (ADClientFactory)
        Returns:
            str: The username we want to send to Duo
            None: If we could not determine the username to send
        """
        try:
            dn = DistinguishedName(dn_str)
        except Exception:
            # At this point we think the DN is actually in a username format
            # but we'll need some extra searches to verify for sure.
            # This is technically not legal LDAP to do this, but Active Directory
            # supports it so we must as well.
            try:
                _ = yield self.validate_ldap_username_for_auth(dn_str, client_factory.search_dn, client_factory.domain_discovery)
            except NoUserFound as e:
                log.msg(str(e))
                defer.returnValue(None)
            else:
                # If our validate call didn't throw an exception that means our "DN" was a valid username
                # and we can just return that for usage with our call to Duo
                defer.returnValue(dn_str)

        entry = LDAPEntry(self, dn)
        user_filter = yield self.user_filter_object()
        result = yield entry.search(
            filterObject=user_filter,
            attributes=(
                self.factory.username_attribute,
            ),
        )

        if len(result) != 1:
            defer.returnValue(None)

        attr_set = result[0].get(self.factory.username_attribute)

        if not attr_set:
            defer.returnValue(None)

        defer.returnValue(list(attr_set)[0].decode())

    @defer.inlineCallbacks
    def username_to_dn(self, username):
        """
        Given a username return the full DN for that object

        Typically used when an appliance only sends you a username attribute and you
        need to the full DN for say exempt_ou checking.

        The way we retrieve the full DN is by performing an extra search where we try to match
        the provided username with the at_attribute or the username_attribute specified in the config.
        If we find a match we pull the DN off that object and use it.
        """
        username_filter = self._create_username_filter(username)
        if username_filter is None:
            raise DnLookupFailed("Username doesn't look like the format for {} or DOMAIN\\{}.".format(self.factory.at_attribute, self.factory.username_attribute))
        username_filter_object = self.create_service_account_user_filter_object(username_filter)

        res = yield self.perform_search(
            self.factory.search_dn,
            username_filter_object,
            attributes=None,
        )

        if len(res) != 1:
            raise DnLookupFailed("Search on username returned {} users. Expected just 1".format(len(res)))
        else:
            service_account_user = res[0]
            defer.returnValue(service_account_user.dn)

    def _create_username_filter(self, possible_username: str) -> Optional[Dict[str, str]]:
        """
        Given a possible username return a dictionary that maps a username attribute to the username.
        We do this dynamically by inspecting the format of the username to look for characters that hint
        at what attribute it maps to.
        """
        username_filter: Optional[Dict[str, str]]

        if ',' not in possible_username and possible_username.count('@') == 1:
            # @ sign means it's probaby an at_attribute formatted username
            username_filter = {self.factory.at_attribute: possible_username}
        elif ',' not in possible_username and possible_username.count('\\') == 1:
            # The \ probably means it's domain\username formatted
            _domain, username = possible_username.split('\\', 1)
            username_filter = {self.factory.username_attribute: username}
        else:
            username_filter = None

        return username_filter

    @defer.inlineCallbacks
    def perform_unbind(self):
        op = pureldap.LDAPUnbindRequest()
        yield self.send_noResponse(op)

    @defer.inlineCallbacks
    def perform_bind_plain(self, dn, password):
        op = pureldap.LDAPBindRequest(dn=dn, auth=password, sasl=False)
        response = yield self.send(op)
        if response.resultCode != ldaperrors.Success.resultCode:
            raise ldaperrors.get(response.resultCode, response.errorMessage)

    @defer.inlineCallbacks
    def perform_bind_ntlm(self, dn, username, password, domain,
                          workstation,
                          ntlm_version):
        ntlm_negotiate_msg = ntlm.create_negotiate_msg()
        op = pureldap.LDAPBindRequest(
            dn=dn, auth=('GSS-SPNEGO', ntlm_negotiate_msg), sasl=True)
        response = yield self.send(op)
        if response.resultCode != ldaperrors.LDAPSaslBindInProgress.resultCode:
            raise ldaperrors.get(response.resultCode, response.errorMessage)

        ntlm_challenge_msg = response.serverSaslCreds.value
        ntlm_authenticate_msg = ntlm.create_authenticate_msg(
            ntlm_negotiate_msg, ntlm_challenge_msg, username, password,
            domain, workstation,
            ntlm_version)
        op = pureldap.LDAPBindRequest(
            dn=dn, auth=('GSS-SPNEGO', ntlm_authenticate_msg), sasl=True)
        response = yield self.send(op)
        if response.resultCode != ldaperrors.Success.resultCode:
            raise ldaperrors.get(response.resultCode, response.errorMessage)

    @defer.inlineCallbacks
    def perform_bind_sspi(self, dn: str, username: str, password: str, domain: str,
                          permit_implicit: bool, targetspn=None):
        """Perform bind using native windows SSPI mechanism. If no
        username, password, or domain is provided, then we'll attempt
        to use the authproxy's existing process credentials to perform
        the bind.

        If targetspn is provided (and valid), then theoretically we
        might use kerberos instead of NTLM

        Returns:
            No return value from this function. Finishing without raising an exception means the
            bind succeeded
        Raises:
            LDAPUnwillingToPerform: If SSPI auth is not supported
            SSPIError: If the SSPI negotiation fails
        """

        if sspi is None:
            msg = 'The SSPI bind type is only supported on Windows.'
            log.err(msg)
            raise ldaperrors.LDAPUnwillingToPerform(msg)

        auth_info: Optional[Tuple[str, str, str]] = (username, domain, password)
        # omitting 'domain' from this if statement; that way we can
        # specify ntlm_domain in config and have it apply to user
        # auth, but not automatically trip us into using configured,
        # rather than implicit, service account creds
        if not (username or password):
            if permit_implicit:
                auth_info = None
            else:
                # even passing a tuple of empty values still appears
                # to trigger the implicit-auth mechanism, so we need
                # to be explicit
                msg = 'Implicit authentication forbidden for this request.'
                log.err(msg)
                raise ldaperrors.LDAPUnwillingToPerform(msg)

        # SSPI negotiation can request some application-level
        # encryption/authentication, but AD apparently throws a fit if
        # you leave this on when using SSL/TLS (and expects you to
        # actually somehow sign all your LDAP requests otherwise)
        scflags = ISC_REQ_NO_INTEGRITY

        # these return codes mean we need to continue the handshake
        sspi_continue = set([
            sspicon.SEC_I_CONTINUE_NEEDED,
            sspicon.SEC_I_COMPLETE_AND_CONTINUE])
        # any return code not in this set should be considered an error
        sspi_ok = sspi_continue.union([
            sspicon.SEC_E_OK,
            sspicon.SEC_I_COMPLETE_NEEDED])

        ca = self._create_sspi_authenticator(auth_info, targetspn, scflags)
        data = None
        # This negotiation is made up of challenge and response messages.
        # We will continue responding to challenges until a success or
        # failure case is hit
        while True:
            # get the next step in the handshake
            err, out_buf = ca.authorize(data)
            if err not in sspi_ok:
                raise SSPIError('SSPI negotiation failed', err)

            response = yield self._send_sspi_bind(dn, out_buf)

            if response.resultCode == ldaperrors.LDAPSaslBindInProgress.resultCode:
                data = self._recalculate_buffer_data(ca, response)
            elif response.resultCode == ldaperrors.Success.resultCode:
                break
            else:
                raise ldaperrors.get(response.resultCode, response.errorMessage)

            # if SSPI said we're done, but ldap response doesn't
            # agree, that's weird
            if err not in sspi_continue:
                raise SSPIError('SSPI negotiation should\'ve finished by now', err)

    @defer.inlineCallbacks
    def _send_sspi_bind(self, dn, current_buffer):
        # format request and send it
        op = pureldap.LDAPBindRequest(
            dn=dn,
            auth=('GSS-SPNEGO', current_buffer[0].Buffer),
            sasl='True',
        )
        response = yield self.send(op)
        return response

    def _recalculate_buffer_data(self, ca, response):
        peercert = self._get_peercert()
        new_data = self._create_buffer_array(ca.pkg_info['MaxToken'], response.serverSaslCreds.value, peercert)
        return new_data

    def perform_bind(self,
                     auth_type: str,
                     dn: str,
                     username: str,
                     password: str,
                     domain: str,
                     workstation: str,
                     permit_implicit=False):
        if auth_type == const.AD_AUTH_TYPE_PLAIN:
            password_bytes = password.encode()
            return self.perform_bind_plain(dn, password_bytes)
        elif auth_type == const.AD_AUTH_TYPE_NTLM_V1:
            return self.perform_bind_ntlm(dn, username, password, domain,
                                          workstation,
                                          ntlm_version=1)
        elif auth_type == const.AD_AUTH_TYPE_NTLM_V2:
            return self.perform_bind_ntlm(dn, username, password, domain,
                                          workstation,
                                          ntlm_version=2)
        elif auth_type == const.AD_AUTH_TYPE_SSPI:
            return self.perform_bind_sspi(dn, username, password, domain,
                                          permit_implicit)

    @defer.inlineCallbacks
    def perform_search(self, dn, filter_object, attributes=(), sizeLimit=0, scope=None):
        """
        Args:
            dn (str): The base DN for the search to start at
            filter_object (LDAPFilterSet): Filter to qualify the search against
            attributes (tuple): Attriutes to get back. Default of empty set means all. `None` gives no attrs
            sizeLimit (int): Number of results to return. 0 means no limit
            scope (int): One of
                LDAP_SCOPE_baseObject = 0
                LDAP_SCOPE_singleLevel = 1
                LDAP_SCOPE_wholeSubtree = 2
        """
        entry = LDAPEntry(self, dn)
        result = yield entry.search(
            filterObject=filter_object,
            attributes=attributes,
            sizeLimit=sizeLimit,
            scope=scope,
        )
        defer.returnValue(result)

    @defer.inlineCallbacks
    def send(self, op, controls=None, handler=None, handle_msg=False):
        yield self._tls_ensured
        send_result = yield (
            super(ADClientProtocol, self).send(op, controls=controls, handler=handler, handle_msg=handle_msg)
        )
        defer.returnValue(send_result)

    @defer.inlineCallbacks
    def send_multiResponse(self, op, handler, *args, **kwargs):
        yield self._tls_ensured
        send_result = yield (
            super(ADClientProtocol, self).send_multiResponse(op, handler, *args, **kwargs)
        )
        defer.returnValue(send_result)

    @defer.inlineCallbacks
    def send_noResponse(self, op):
        yield self._tls_ensured
        super(ADClientProtocol, self).send_noResponse(op)

    def unsolicitedNotification(self, msg):
        """Passes the message back the authproxy server section to determine
        what action should be taken to inform the downstream client
        """
        super(ADClientProtocol, self).unsolicitedNotification(msg)
        if callable(self.unsolicited_notification_handler):
            self.unsolicited_notification_handler(msg)  # pylint: disable=E1102

    def _startTLS(self, ctx):
        if not self.connected:
            raise ldapclient.LDAPClientConnectionLostException
        elif self.onwire:
            raise ldapclient.LDAPStartTLSBusyError(self.onwire)
        else:
            op = pureldap.LDAPStartTLSRequest()
            # call super's send to avoid a circular dependency on yield self._tls_ensured
            d = super(ADClientProtocol, self).send(op)
            d.addCallback(self._cbStartTLS, ctx)
            return d

    def _create_sspi_authenticator(self, auth_info, targetspn, scflags):
        # explicitly specifying 'Kerberos' or 'NTLM' will also work
        # here, but technically if we say the SASL type is GSS-SPNEGO,
        # we're supposed to use 'Negotiate'
        ca = sspi.ClientAuth('Negotiate', auth_info=auth_info, targetspn=targetspn, scflags=scflags)
        return ca

    def _create_buffer_array(self, max_token_size, challenge_response, peercert):
        """ Given the challenge response from our BindRequest build up an array of the buffers to be used as a
        response to that challenge. This will most often just be the challenge itself as well as the channel binding
        token if using a transport with SSL
        Args:
            max_token_size (int): As defined by ClientAuth this value is the maximum size of a token for the handshake
            challenge_response (str) This arg contains the raw bytes of the challenge from the server
            peercert: Peer SSL certificate taken off of a transport
        Returns:
            PySecBufferDescType: The array of PySecBufferTypes
        """
        buffer_array = win32security.PySecBufferDescType()

        challenge_buffer = win32security.PySecBufferType(max_token_size, sspicon.SECBUFFER_TOKEN)
        challenge_buffer.Buffer = challenge_response
        buffer_array.append(challenge_buffer)

        # To support servers that have turned on LdapEnforceChannelBinding we add this token
        if peercert:
            try:
                appdata = self._create_appdata_from_peercert(peercert)
            except UnsupportedAlgorithm:
                log.msg("Skipping the creation of the CBT due to unsupported hash algorithm")
            else:
                cbt_buffer = self._create_channel_binding_token(max_token_size, appdata)
                buffer_array.append(cbt_buffer)

        return buffer_array

    def _get_peercert(self):
        if self.factory.transport_type in const.AD_TRANSPORTS_WITH_SSL:
            peercert = self.transport.getPeerCertificate()
            if not peercert and self.debug:
                log.msg("SSL transport was specified but we are unable to get peercertificate. CBT will not be created.")
        else:
            peercert = None
        return peercert

    @staticmethod
    def _create_appdata_from_peercert(peercert):
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
            log.err(str(e))
            raise e
        if isinstance(hash_algo, (hashes.MD5, hashes.SHA1)):
            # https://tools.ietf.org/html/rfc5929#section-4.1
            hash_algo = hashes.SHA256()

        hashed_cert = crypto_peercert.fingerprint(hash_algo)
        return 'tls-server-end-point:'.encode('ASCII') + hashed_cert

    @staticmethod
    def _create_channel_binding_token(max_token_size, appdata):
        """ Create a channel binding token to bind the LDAP layer to the underlying TLS layer.
        We do this by hashing the peercert and packing it into a buffer to be sent with an LDAPBindRequest.
        See T34588 for more detail. """

        # This struct.pack creates the SEC_CHANNEL_BINDINGS structure followed by the actual appdata
        # https://docs.microsoft.com/en-us/windows/desktop/api/sspi/ns-sspi-_sec_channel_bindings
        application_data_length = len(appdata)
        application_data_offset = 32
        struct_plus_data = struct.pack('<LLLLLLLL{}s'.format(len(appdata)), 0, 0, 0, 0, 0, 0, application_data_length, application_data_offset, appdata)

        cbtbuf = win32security.PySecBufferType(max_token_size, sspicon.SECBUFFER_CHANNEL_BINDINGS)
        cbtbuf.Buffer = struct_plus_data
        return cbtbuf


class ADClientFactory(protocol.ClientFactory, object):
    protocol = ADClientProtocol

    user_filter = ldapfilter.parseFilter(
        '(|'
        # AD: match only users.
        # <http://social.technet.microsoft.com/wiki/contents/articles/5392.active-directory-ldap-syntax-filters.aspx>
        '(&(objectClass=user)(objectCategory=person))'
        # RFC 2798 schemas:
        '(objectClass=inetOrgPerson)'
        # OpenLDAP Core schema
        '(objectClass=organizationalPerson)'
        ')')

    def __init__(self,
                 timeout,
                 transport_type,
                 ssl_ca_certs,
                 ssl_verify_depth,
                 ssl_verify_hostname,
                 domain_discovery=False,
                 username_attribute='sAMAccountName',
                 at_attribute='userPrincipalName',
                 security_group=None,
                 ldap_filter=None,
                 debug=False,
                 is_logging_insecure=False):
        self.timeout = timeout
        self.domain_discovery = domain_discovery
        self.username_attribute = username_attribute
        self.at_attribute = at_attribute
        self.transport_type = transport_type
        self.ssl_ca_certs = ssl_ca_certs
        self.ssl_context_factory = None
        self.ssl_verify_depth = ssl_verify_depth
        self.ssl_verify_hostname = ssl_verify_hostname
        self.security_group = security_group
        self.ldap_filter = ldap_filter
        self.debug = debug
        self.is_logging_insecure = is_logging_insecure
        self.deferred = defer.Deferred()

    def buildProtocol(self, addr):
        p = super(ADClientFactory, self).buildProtocol(addr)
        p.debug = self.debug
        p.is_logging_insecure = self.is_logging_insecure
        return p

    def clientConnectionFailed(self, connector, reason):
        log.msg('AD Connection failed: %r' % reason)
        try:
            if reason:
                reason.raiseException()
        except Exception as e:
            underlying_exception = e
        else:
            underlying_exception = None

        self.deferred.errback(
            ADClientError('AD Connection failed: %s' % reason, underlying_exception=underlying_exception)
        )

    def stopFactory(self):
        super(ADClientFactory, self).stopFactory()
        try:
            self.deferred.errback(
                ADClientError('AD Connection closed prematurely'))
        except defer.AlreadyCalledError:
            pass

    def connect_ldap(self, host, port):
        if self.transport_type in (const.AD_TRANSPORT_STARTTLS, const.AD_TRANSPORT_LDAPS):
            ssl_hostname = (host if self.ssl_verify_hostname else None)
            self.ssl_context_factory = create_context_factory(
                hostnames=ssl_hostname, caCerts=self.ssl_ca_certs,
                verifyDepth=self.ssl_verify_depth)

        if self.transport_type == const.AD_TRANSPORT_LDAPS:
            return reactor.connectSSL(
                host, port, self, self.ssl_context_factory,
                timeout=self.timeout)
        else:
            return reactor.connectTCP(
                host, port, self, timeout=self.timeout)
