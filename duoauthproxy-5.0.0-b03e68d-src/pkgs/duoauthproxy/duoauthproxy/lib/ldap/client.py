import struct
from typing import Dict, Optional, Tuple, Union

from cryptography.exceptions import UnsupportedAlgorithm
from ldaptor import ldapfilter
from ldaptor.protocols import pureldap
from ldaptor.protocols.ldap import ldapclient, ldaperrors
from ldaptor.protocols.ldap.distinguishedname import DistinguishedName
from ldaptor.protocols.ldap.ldapsyntax import LDAPEntry
from ldaptor.protocols.pureldap import LDAPBindResponse
from OpenSSL.crypto import X509
from twisted.internet import defer, protocol, reactor, tcp
from twisted.internet.defer import Deferred
from twisted.internet.interfaces import IHandshakeListener
from twisted.protocols.tls import TLSMemoryBIOProtocol
from zope.interface import implementer

from duoauthproxy.lib import fips_manager, util

from .. import const, log, ntlm
from ..ssl_verify import create_context_factory
from . import utilities
from .bind_context import BaseContext, NTLMContext, SignAndSealNotSupported, SSPIContext
from .sign_seal_transport import SignSealDecoder, SignSealEncoder, wrap_protocol
from .utilities import LdapUsername, LdapUsernameOrigin

try:
    import pywintypes
    import sspi
    import sspicon
    import win32security

    # these return codes mean subsequent calls to authorize() on the
    # client authenticator will be needed to complete the authentication.
    SSPI_CONTINUE = {
        sspicon.SEC_I_CONTINUE_NEEDED,
        sspicon.SEC_I_COMPLETE_NEEDED,
        sspicon.SEC_I_COMPLETE_AND_CONTINUE,
    }
except ImportError:
    pywintypes = None
    sspi = None
    sspicon = None
    win32security = None
    SSPI_CONTINUE = set()

# Not defined in sspicon, for some reason...
ISC_REQ_NO_INTEGRITY = 0x00800000

# active directory error code given when we search using an attribute range
# that exceeds the total number of elements in the multi-value attribute.
ERR_AD_CANT_RETRIEVE_ATTS = b"00002121"


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


class ConnectionNotProperlyBoundError(Exception):
    pass


@implementer(IHandshakeListener)
class ADClientProtocol(ldapclient.LDAPClient):
    """
    LDAPClient with utility methods needed for proxying.
    """

    def __init__(self):
        super(ADClientProtocol, self).__init__()
        self.unsolicited_notification_handler = None
        self.upstream_server_disconnect_handler = None
        self.factory: protocol.Factory
        self.transport: Union[TLSMemoryBIOProtocol, tcp.Client]
        self.debug: bool

        # Deferred that's completed when the TLS handshake is done. "Optional"
        # in that it's None until connectionMade is called, but that method
        # will always set it.
        self._tls_ensured: Optional[Deferred] = None
        self.bound = False

    def handshakeCompleted(self):
        """
        Implements the IHandshakeListener interface. Called when the TLS
        handshake is completed. Not called for transport_type clear.
        """
        self._tls_ensured.callback(True)

    def _cbStartTLS(self, msg, ctx):
        try:
            super(ADClientProtocol, self)._cbStartTLS(msg, ctx)
        except ldaperrors.LDAPProtocolError as e:
            # Something went wrong while requesting startTLS. Per the LDAP
            # spec, it's on us to close the connection when startTLS did not
            # succeed so abort the connection and re-raise the error.
            #
            # "The client's current session is unaffected if the server does
            # not support TLS. The client MAY proceed with any LDAP operation,
            # or it MAY close the connection."
            # https://tools.ietf.org/html/rfc2830
            self.transport.abortConnection()
            raise e

    def connectionMade(self):
        super(ADClientProtocol, self).connectionMade()

        if self.factory.transport_type == const.AD_TRANSPORT_STARTTLS:
            # The docs for startTLS say that the returned deferred will be
            # completed when the TLS handshake is complete, but that's false.
            # The deferred is completed once the LDAPExtendedResponse indicating
            # the server has agreed to upgrade to TLS, not once the TLS
            # handshake is complete. Therefore we're using our own deferred
            # to track the handshake being done via handshakeCompleted
            self._tls_ensured = Deferred()
            # Even though we don't really care about the deferred returned
            # from startTLS for the reasons mentioned above, we should at least
            # handle any raised errors since test cases don't like unhandled
            # deferreds and it's better practice to handle them even though
            # it's not strictly necessary.
            # See https://twisted.readthedocs.io/en/latest/core/howto/defer.html#unhandled-errors
            start_tls_requested = self.startTLS(self.factory.ssl_context_factory)
            start_tls_requested.addErrback(log.msg)
        elif self.factory.transport_type == const.AD_TRANSPORT_LDAPS:
            # Use our own deferred in the case of LDAPS. We'll call the
            # deferred's callback in handshakeCompleted
            self._tls_ensured = Deferred()
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
                host = "unknown"
                port = "unknown"
            self.upstream_server_disconnect_handler(
                reason, host, port
            )  # pylint: disable=E1102

        # If the _tls_ensured deferred hasn't been called yet, then we lost
        # the connection during the handshake. Errback with the reason so things
        # yielding on _tls_ensured don't wait forever.
        if not self._tls_ensured.called and reason != protocol.connectionDone:
            self._tls_ensured.errback(reason)

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
            "memberof": self.factory.security_group,
        }

        # If we want customers to be able to specify a primary group as their security_group_dn we need an extra search here
        # to look up objectsid for the group. Then we can take the RID off the objectsid and use that for the
        # primarygroupid comparison
        try:
            object_sid = yield self.get_object_sid_for_group(
                self.factory.security_group
            )
        except (InvalidSecurityGroupDn, MissingObjectSid, utilities.InvalidSid) as e:
            # We want to fail safely here because not all LDAP Servers may have an objectSID
            if self.debug:
                log.msg(
                    "Tried to search security group DN for object sid but it could not be found. Falling back to just checking memberOf. Error: {}".format(
                        e
                    )
                )
        else:
            security_group_rid = object_sid.split("-")[-1]
            group_match_mapping["primarygroupid"] = security_group_rid

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
                attributes=tuple(["objectsid"]),
                sizeLimit=1,
                scope=pureldap.LDAP_SCOPE_baseObject,
            )
        except (ldaperrors.LDAPNoSuchObject, ldaperrors.LDAPReferral):
            raise InvalidSecurityGroupDn("{} could not be found".format(group_dn))

        if len(search_res) != 1:
            raise InvalidSecurityGroupDn(
                "Search for {} did not return exactly 1 group".format(group_dn)
            )

        security_group = search_res[0]
        security_group_objectsid = security_group.get("objectsid", None)
        if not security_group_objectsid:
            raise MissingObjectSid("Object sid not found for {}".format(group_dn))

        object_sid_str = utilities.convert_binary_sid_to_string(
            list(security_group_objectsid)[0]
        )
        defer.returnValue(object_sid_str)

    @defer.inlineCallbacks
    def validate_ldap_username_for_auth(
        self, possible_username: LdapUsername, search_dn: str
    ):
        """
        Takes in a potential username and looks it up against attributes in the AD
        to validate to make sure the user does exist.
        This also serves the purpose of checking security groups and ldapfilters to make sure
        the user is allowed in.
        We will then return the user object if the username was able to be validated and is safe to use with Duo or for NTLM auth.
        If not we will raise an exception.
        Args:
            possible_username: LdapUsername to validate
            search_dn: DN to scope the search with
        Returns:
            LDAPEntryWithClient: The full user object for the given username
        Raises:
            NoUserFound: If the user could not be found because of the name was bad or didn't match the filters
        """
        username_filter = self._create_username_filter(possible_username)
        if username_filter is None:
            raise Exception(
                "Username: {} was not provided in a supported format. Failing the authentication.".format(
                    possible_username.username
                )
            )
        user_filter_obj = yield self.user_filter_object(username_filter)

        attributes_to_fetch = tuple(["msds-PrincipalName"])
        result = yield self.perform_search(
            search_dn, user_filter_obj, attributes=attributes_to_fetch
        )

        if len(result) == 1:
            # The "DN" matched against one of the username attributes so we can just return
            # that "DN" as the actual username to use with Duo.
            defer.returnValue(result[0])

        # At this point we have apparently found a duplicate match for this user or possibly no users.
        # We will do an additional check to also validate the domain and see if we
        # can narrow it down. Note: This only works with Active Directory and if the user provided a NetBIOS style
        # username name.
        if "sAMAccountName" in username_filter:
            for match in result:
                user_principal_name = list(match.get("msDS-PrincipalName", [b""]))[0]
                if (
                    user_principal_name.decode().lower()
                    == possible_username.username.lower()
                ):
                    # The "DN" matched the msDS-PrincipalName attribute (eg. DOMAIN\username)
                    # Because msDS-PrincipalNames are guaranteed unique we can just return that
                    # value up to Duo to be used
                    defer.returnValue(match)

        # At this point we had either no users or multiple users and we couldn't figure out how narrow it down.
        # We need to fail
        if len(result) > 1:
            err_msg = "Found too many users with username: {}".format(
                possible_username.username
            )
        else:
            err_msg = "Could not find user with username: {}. It's possible this user does not exist or did not match your configured security filters.".format(
                possible_username.username
            )

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
            possible_username = utilities.LdapUsername(
                dn_str, LdapUsernameOrigin.BIND_DN
            )
            try:
                _ = yield self.validate_ldap_username_for_auth(
                    possible_username, client_factory.search_dn
                )
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
            filterObject=user_filter, attributes=(self.factory.username_attribute,),
        )

        if len(result) != 1:
            defer.returnValue(None)

        attr_set = result[0].get(self.factory.username_attribute)

        if not attr_set:
            defer.returnValue(None)

        defer.returnValue(list(attr_set)[0].decode())

    @defer.inlineCallbacks
    def username_to_dn(self, username: LdapUsername):
        """
        Given a username return the full DN for that object

        Typically used when an appliance only sends you a username attribute and you
        need the full DN for say exempt_ou checking.

        The way we retrieve the full DN is by performing an extra search where we try to match
        the provided username with the at_attribute or the username_attribute specified in the config.
        If we find a match we pull the DN off that object and use it.

        Args:
            username: username to translate to DN
            from_ldap_bind: Set to true if the username was taken off of the DN field of a bind
        """
        username_filter = self._create_username_filter(username)
        if username_filter is None:
            if username.original_location == utilities.LdapUsernameOrigin.BIND_DN:
                plain_attr = "CN"
            else:
                plain_attr = self.factory.username_attribute
            raise DnLookupFailed(
                "Username doesn't look like the format for {at_attr}, DOMAIN\\{user_attr}, or {plain_attr}.".format(
                    at_attr=self.factory.at_attribute,
                    user_attr=self.factory.username_attribute,
                    plain_attr=plain_attr,
                )
            )
        username_filter_object = self.create_service_account_user_filter_object(
            username_filter
        )

        res = yield self.perform_search(
            self.factory.search_dn, username_filter_object, attributes=None,
        )

        if len(res) != 1:
            raise DnLookupFailed(
                "Search on username returned {} users. Expected just 1".format(len(res))
            )
        else:
            service_account_user = res[0]
            defer.returnValue(service_account_user.dn)

    def _create_username_filter(
        self, possible_username: LdapUsername
    ) -> Optional[Dict[str, str]]:
        """
        Given a possible username return a dictionary that maps a username attribute to the username.
        We do this dynamically by inspecting the format of the username to look for characters that hint
        at what attribute it maps to.

        Args:
            possible_username: User to put in filter
            from_ldap_bind_dn: A bool to tell us if the username came off of an ldap bind request's DN. If it
                               did the filter to use is different than if it came from an NTLM packet or from
                               a radius packet.
        """
        username_filter: Optional[Dict[str, str]]
        possible_username_str = possible_username.username

        if "," not in possible_username_str and possible_username_str.count("@") == 1:
            # @ sign means it's probaby an at_attribute formatted username
            username_filter = {self.factory.at_attribute: possible_username_str}
        elif (
            "," not in possible_username_str and possible_username_str.count("\\") == 1
        ):
            # The \ probably means it's domain\username formatted
            # Since NetBIOS format is AD specific we actually know that the second chunk of the username
            # is equal to the sAMAccountName attribute. Instead of looking at the configured username attribute
            # we just hardcode samaccountname into the filter.
            _domain, username = possible_username_str.split("\\", 1)
            username_filter = {"sAMAccountName": username}
        elif "," not in possible_username_str:
            # If it's not UPN or NetBIOS our best guess is that this username is either
            # the configured username_attribute or the user's CN.
            if possible_username.original_location in [
                utilities.LdapUsernameOrigin.BIND_DN
            ]:
                username_filter = {"cn": possible_username_str}
            elif possible_username.original_location in [
                utilities.LdapUsernameOrigin.NTLM,
                utilities.LdapUsernameOrigin.RADIUS,
            ]:
                username_filter = {
                    self.factory.username_attribute: possible_username_str
                }
            else:
                username_filter = None
        else:
            # We don't know what this username format is so we just fail
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

    @staticmethod
    @defer.inlineCallbacks
    def perform_bind_ntlm(
        client,
        username,
        password,
        domain,
        workstation,
        ntlm_version,
        peercert: X509 = None,
    ):
        """
        Perform bind using custom NTLM mechanism. Will return different value
        based on ntlm_version.

        NTLMv2 using session key for future sign and seal.
        We do not support NTLMv1 with sign and seal on purpose.

        :returns
            NTLMv1 : None
            NTLMv2 : session key for sign and seal
        """
        sign_seal_enable = client._ntlm_sign_seal_enable(ntlm_version)
        ntlm_negotiate_msg = ntlm.create_negotiate_msg(sign_seal=sign_seal_enable)
        op = pureldap.LDAPBindRequest(
            auth=("GSS-SPNEGO", ntlm_negotiate_msg), sasl=True
        )
        response = yield client.send(op)
        if response.resultCode != ldaperrors.LDAPSaslBindInProgress.resultCode:
            raise ldaperrors.get(response.resultCode, response.errorMessage)

        ntlm_challenge_msg = response.serverSaslCreds.value
        ntlm_authenticate = ntlm.create_ntlm_auth(
            ntlm_negotiate_msg,
            ntlm_challenge_msg,
            username,
            password,
            domain,
            workstation,
            ntlm_version,
            sign_seal=sign_seal_enable,
            peercert=peercert,
        )
        op = pureldap.LDAPBindRequest(
            auth=("GSS-SPNEGO", ntlm_authenticate.get_encoded_msg()), sasl=True
        )
        response = yield client.send(op)
        if response.resultCode != ldaperrors.Success.resultCode:
            raise ldaperrors.get(response.resultCode, response.errorMessage)
        if ntlm_version == 2 and isinstance(ntlm_authenticate, ntlm.NTLMv2Auth):
            defer.returnValue(ntlm_authenticate.session_key)

    def _ntlm_sign_seal_enable(self, ntlm_version):
        """Not all ntlm bind need sign and seal. Sign and seal the message only for
        bind request using NTLMv2 and NOT using ldaps or starttls
        """

        if ntlm_version == 1:
            return False
        if self.factory.transport_type in const.AD_TRANSPORTS_WITH_SSL:
            return False

        return True

    @defer.inlineCallbacks
    def perform_bind_sspi(
        self,
        username: str,
        password: str,
        domain: str,
        permit_implicit: bool,
        targetspn: str = None,
    ):
        """Perform bind using native windows SSPI mechanism. If no
        username, password, or domain is provided, then we'll attempt
        to use the authproxy's existing process credentials to perform
        the bind.

        This method uses the Negotiate authentication mechanism (GSS-SPNEGO).
        If a valid targetspn is provided, then SSPI will use Kerberos. Otherwise,
        NTLM will be used.

        Returns:
            No return value from this function. Finishing without raising an exception means the
            bind succeeded
        Raises:
            LDAPUnwillingToPerform: If SSPI auth is not supported
            SSPIError: If the SSPI negotiation fails
        """

        if sspi is None:
            msg = "The SSPI bind type is only supported on Windows."
            log.error(msg)
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
                msg = "Implicit authentication forbidden for this request."
                log.error(msg)
                raise ldaperrors.LDAPUnwillingToPerform(msg)

        # TLS and Sign and Seal are mutually eclusive security measures
        # so we only request integrity checking if we don't already have
        # it from the transport layer
        if self.factory.transport_type in const.AD_TRANSPORTS_WITH_SSL:
            scflags = ISC_REQ_NO_INTEGRITY
        else:
            scflags = sspicon.ISC_REQ_INTEGRITY | sspicon.ISC_REQ_CONFIDENTIALITY

        # When doing an SSPI bind, we interact with two services:
        #
        #   1) SSPI
        #   2) LDAP
        #
        # SSPI creates a security context and provides the credentials to do
        # a SASL bind. The authentication is complete when both SSPI and LDAP
        # don't require any more steps.
        #
        # There is no guarantee that there will be the same number of interactions
        # with SSPI and LDAP for a single authentication. For example, when
        # doing a Kerberos authentication the entire flow is
        # authorize->bind->authorize due to there being no LDAP challenge. If
        # NTLM is used, though, the flow is authorize->bind(neg)->authorize->bind(auth).
        # Because of this, we must check whether we need to do another authorize
        # and/or bind on each iteration of the loop.
        #
        # More details on how to interact with SSPI and authorize(), particularly
        # the 'Remarks' section:
        # https://docs.microsoft.com/en-us/previous-versions/windows/desktop/legacy/aa375509(v=vs.85)
        response = None
        result_code = None
        out_buf = None
        err = None
        ca = self._create_sspi_authenticator(auth_info, targetspn, scflags)

        while err != sspicon.SEC_E_OK or result_code != ldaperrors.Success.resultCode:
            # If it's either our first iteration or SSPI says more steps are
            # necessary, authorize to get the data buffer for the next step.
            # Intentionally checking for err being None instead of falsey since
            # sspicon.SEC_E_OK is 0, which is also falsey!
            if err is None or err in SSPI_CONTINUE:
                err, out_buf = yield self._authorize(ca, response)

            # Send a bind request if this is our first iteration or if the
            # LDAP response from the previous iteration was a challenge.
            if (
                not response
                or response.resultCode == ldaperrors.LDAPSaslBindInProgress.resultCode
            ):
                response = yield self._send_sspi_bind(out_buf)
                result_code = response.resultCode

            # if SSPI said we're done, but ldap response doesn't agree, we've
            # reached an unexpected state. Raise an error.
            if err == sspicon.SEC_E_OK and result_code != ldaperrors.Success.resultCode:
                raise SSPIError("SSPI negotiation should've finished by now", err)

        defer.returnValue(ca)

    @defer.inlineCallbacks
    def _authorize(self, ca, response: Optional[LDAPBindResponse] = None):
        """Recalculates the buffer data and authorizes to get the next err and
        buffer in the authentication process"""
        if response and response.serverSaslCreds:
            server_sasl_creds = response.serverSaslCreds.value
        else:
            server_sasl_creds = None

        data = yield self._recalculate_buffer_data(ca, server_sasl_creds)
        try:
            err, out_buf = ca.authorize(data)
        except pywintypes.error as e:
            # For at least one error type (maybe all?), authorize is *raising* an error object instead of
            # returning the error code.
            err = e.winerror

        # If the result of the authorize call isn't an OK response or one of
        # the continue responses, something went wrong.
        if err not in SSPI_CONTINUE.union([sspicon.SEC_E_OK]):
            raise SSPIError("SSPI negotiation failed", err)

        defer.returnValue((err, out_buf))

    @defer.inlineCallbacks
    def _send_sspi_bind(self, current_buffer):
        # format request and send it
        op = pureldap.LDAPBindRequest(
            auth=("GSS-SPNEGO", current_buffer[0].Buffer), sasl="True",
        )
        response = yield self.send(op)

        # If we got something other than a success or challenge back from
        # the bind, an LDAP error occurred. Halt immediately.
        if response.resultCode not in [
            ldaperrors.Success.resultCode,
            ldaperrors.LDAPSaslBindInProgress.resultCode,
        ]:
            raise ldaperrors.get(response.resultCode, response.errorMessage)

        return response

    @defer.inlineCallbacks
    def _recalculate_buffer_data(self, ca, server_sasl_creds: Optional[bytes]):
        peercert = yield self._get_peercert()
        new_data = self._create_buffer_array(
            ca.pkg_info["MaxToken"], server_sasl_creds, peercert
        )
        return defer.returnValue(new_data)

    @defer.inlineCallbacks
    def perform_bind(
        self,
        auth_type: str,
        dn: str,
        username: str,
        password: str,
        domain: str,
        workstation: str,
        permit_implicit=False,
    ):
        bind_context: Optional[BaseContext] = None
        tls_enabled = self.factory.transport_type in const.AD_TRANSPORTS_WITH_SSL
        if auth_type == const.AD_AUTH_TYPE_PLAIN:
            password_bytes = password.encode()
            yield self.perform_bind_plain(dn, password_bytes)
            # Bind context for plain will always be None
        elif auth_type == const.AD_AUTH_TYPE_NTLM_V1:
            yield ADClientProtocol.perform_bind_ntlm(
                self,
                username,
                password,
                domain,
                workstation,
                ntlm_version=1,
                peercert=None,
            )
            # Bind context for NTLMv1 will always be None
        elif auth_type == const.AD_AUTH_TYPE_NTLM_V2:
            peercert = yield self._get_peercert()
            session_key = yield ADClientProtocol.perform_bind_ntlm(
                self,
                username,
                password,
                domain,
                workstation,
                ntlm_version=2,
                peercert=peercert,
            )
            # NTLMv2 returns session key
            if not tls_enabled:
                if not fips_manager.status():
                    bind_context = NTLMContext(session_key)
                else:
                    raise SignAndSealNotSupported(
                        "Sign and seal using md5 for security is not FIPS compliant, "
                        "Must use secure transport (LDAPS/STARTTLS)"
                        "Read more about FIPS configuration: https://duo.com/docs/authproxy-reference#fips-mode"
                    )
        elif auth_type == const.AD_AUTH_TYPE_SSPI:
            # Use the host to build the targetspn. If it's a hostname
            # and the targetspn maps to a valid service provider, then
            # Kerberos will be used. Otherwise SSPI will use NTLM.
            targetspn = "ldap/{}".format(self.transport.connector.host)
            ca = yield self.perform_bind_sspi(
                username, password, domain, permit_implicit, targetspn
            )
            if self.debug:
                ca_package_info = ca.ctxt.QueryContextAttributes(
                    sspicon.SECPKG_ATTR_PACKAGE_INFO
                )

                log.msg("SSPI security package {data}", data=ca_package_info)
            if not tls_enabled:
                if not fips_manager.status():
                    bind_context = SSPIContext(ca)
                else:
                    raise SignAndSealNotSupported(
                        "Sign and seal using md5 for security is not FIPS compliant, "
                        "Must use secure transport (LDAPS/STARTTLS)"
                        "Read more about FIPS configuration: https://duo.com/docs/authproxy-reference#fips-mode"
                    )
        if not self.bound:
            self.bound = True
            if bind_context:
                if self.debug:
                    log.msg("Sign and Seal has been negotiated on this connection")
                wrap_protocol(
                    self, SignSealEncoder, SignSealDecoder, context=bind_context
                )

        defer.returnValue(bind_context)

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
        try:
            result = yield entry.search(
                filterObject=filter_object,
                attributes=attributes,
                sizeLimit=sizeLimit,
                scope=scope,
            )
        except ldaperrors.LDAPOperationsError as e:
            if e.message.decode().startswith(const.LDAP_SUCCESSFUL_BIND_NEEDED_ERROR):
                log.failure("LDAP search failed")
                raise ConnectionNotProperlyBoundError(
                    "Search failed because either there was no bind on this connection or there were insufficient privileges with the bound user. If you are attempting to use integrated authentication with SSPI please make sure the server running the Authentication Proxy is domain joined."
                )
            else:
                raise e
        defer.returnValue(result)

    @defer.inlineCallbacks
    def send(self, op, controls=None, handler=None, return_controls=False):
        yield self._tls_ensured
        send_result = yield (
            super(ADClientProtocol, self).send(
                op, controls=controls, handler=handler, return_controls=return_controls
            )
        )
        defer.returnValue(send_result)

    @defer.inlineCallbacks
    def send_multiResponse(self, op, handler, *args, **kwargs):
        yield self._tls_ensured
        send_result = yield (
            super(ADClientProtocol, self).send_multiResponse(
                op, handler, *args, **kwargs
            )
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
        # Use the Negotiate package which means we'll use Kerberos if it's
        # supported/available and fall back to NTLM otherwise.
        ca = sspi.ClientAuth(
            "Negotiate", auth_info=auth_info, targetspn=targetspn, scflags=scflags
        )
        return ca

    def _create_buffer_array(
        self,
        max_token_size: int,
        server_sasl_creds: Optional[bytes],
        peercert: Optional[X509],
    ):
        """
        Creates a buffer array to be passed to an SSPI client authenticator.

        If serverSaslCreds are provided, they will be appended to the created
        buffer. If a peercert is provided, a channel binding token will be
        appended to the buffer

        Args:
            max_token_size: As defined by ClientAuth this value is the maximum size of a token for the handshake
            server_sasl_creds: The serverSaslCreds received from the server
                that need to be included on the next call to authorize()
            peercert: Peer SSL certificate taken off of a transport
        Returns:
            PySecBufferDescType: The array of PySecBufferTypes
        """
        buffer_array = win32security.PySecBufferDescType()

        if server_sasl_creds:
            server_sasl_creds_buffer = win32security.PySecBufferType(
                max_token_size, sspicon.SECBUFFER_TOKEN
            )
            server_sasl_creds_buffer.Buffer = server_sasl_creds
            buffer_array.append(server_sasl_creds_buffer)

        # To support servers that have turned on LdapEnforceChannelBinding we add this token
        if peercert:
            try:
                appdata = util.create_appdata_from_peercert(peercert)
            except UnsupportedAlgorithm:
                log.msg(
                    "Skipping the creation of the CBT due to unsupported hash algorithm"
                )
            else:
                cbt_buffer = self._create_sspi_channel_binding_token(
                    max_token_size, appdata
                )
                buffer_array.append(cbt_buffer)

        return buffer_array

    @defer.inlineCallbacks
    def _get_peercert(self) -> X509:
        # Make sure the handshake is complete first since the peer certificate
        # (if there is one) isn't available until the handshake is done.
        yield self._tls_ensured

        if self.factory.transport_type in const.AD_TRANSPORTS_WITH_SSL:
            peercert = self.transport.getPeerCertificate()
            if not peercert and self.debug:
                log.msg(
                    "SSL transport was specified but we are unable to get peercertificate. CBT will not be created."
                )
        else:
            peercert = None
        defer.returnValue(peercert)

    @staticmethod
    def _create_sspi_channel_binding_token(max_token_size, appdata):
        """ Create a channel binding token to bind the LDAP layer to the underlying TLS layer.
        We do this by hashing the peercert and packing it into a buffer to be sent with an LDAPBindRequest.
        See T34588 for more detail. """

        # This struct.pack creates the SEC_CHANNEL_BINDINGS structure followed by the actual appdata
        # https://docs.microsoft.com/en-us/windows/desktop/api/sspi/ns-sspi-_sec_channel_bindings
        application_data_length = len(appdata)
        application_data_offset = 32
        struct_plus_data = struct.pack(
            "<LLLLLLLL{}s".format(len(appdata)),
            0,
            0,
            0,
            0,
            0,
            0,
            application_data_length,
            application_data_offset,
            appdata,
        )

        cbtbuf = win32security.PySecBufferType(
            max_token_size, sspicon.SECBUFFER_CHANNEL_BINDINGS
        )
        cbtbuf.Buffer = struct_plus_data
        return cbtbuf


class ADClientFactory(protocol.ClientFactory, object):
    protocol = ADClientProtocol

    user_filter = ldapfilter.parseFilter(
        "(|"
        # AD: match only users.
        # <http://social.technet.microsoft.com/wiki/contents/articles/5392.active-directory-ldap-syntax-filters.aspx>
        "(&(objectClass=user)(objectCategory=person))"
        # RFC 2798 schemas:
        "(objectClass=inetOrgPerson)"
        # OpenLDAP Core schema
        "(objectClass=organizationalPerson)"
        ")"
    )

    def __init__(
        self,
        timeout,
        transport_type,
        ssl_ca_certs,
        ssl_verify_depth,
        ssl_verify_hostname,
        username_attribute="sAMAccountName",
        at_attribute="userPrincipalName",
        security_group=None,
        ldap_filter=None,
        debug=False,
        is_logging_insecure=False,
    ):
        self.timeout = timeout
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
        log.msg("AD Connection failed: %r" % reason)
        try:
            if reason:
                reason.raiseException()
        except Exception as e:
            underlying_exception = e
        else:
            underlying_exception = None

        self.deferred.errback(
            ADClientError(
                "AD Connection failed: %s" % reason,
                underlying_exception=underlying_exception,
            )
        )

    def stopFactory(self):
        super(ADClientFactory, self).stopFactory()
        try:
            self.deferred.errback(ADClientError("AD Connection closed prematurely"))
        except defer.AlreadyCalledError:
            pass

    def connect_ldap(self, host, port):
        if self.transport_type in (
            const.AD_TRANSPORT_STARTTLS,
            const.AD_TRANSPORT_LDAPS,
        ):
            ssl_hostname = host if self.ssl_verify_hostname else None
            self.ssl_context_factory = create_context_factory(
                hostnames=ssl_hostname,
                caCerts=self.ssl_ca_certs,
                verifyDepth=self.ssl_verify_depth,
            )

        if self.transport_type == const.AD_TRANSPORT_LDAPS:
            return reactor.connectSSL(
                host, port, self, self.ssl_context_factory, timeout=self.timeout
            )
        else:
            return reactor.connectTCP(host, port, self, timeout=self.timeout)
