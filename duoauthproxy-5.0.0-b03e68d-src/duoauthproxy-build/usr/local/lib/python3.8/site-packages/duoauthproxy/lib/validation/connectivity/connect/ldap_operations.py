#
# Copyright (c) 2018 Duo Security
# All Rights Reserved
#
from ldaptor.protocols.ldap import ldaperrors
from ldaptor.protocols.ldap.distinguishedname import DistinguishedName
from OpenSSL import SSL
from twisted.internet import defer

from ..connectivity_results import LdapBindResult, LdapSearchResult


@defer.inlineCallbacks
def ldap_search_has_results(bound_client, search_dn_str, filter_object):
    """
    Determine if an ldap filter will return any results.  The exact count will not be determined, just whether
    the search will return zero or 1+ results.

    Args:
        bound_client: An ldaptor client that's already connected and bound as a search user
        search_dn_str (str): the base DN to search from
        filter_object: the filter text for the search, in LDAP filter format

    Returns:
        LdapSearchResult: the result of the test
    """
    search_dn = DistinguishedName(search_dn_str)

    try:
        search_results = yield bound_client.perform_search(
            search_dn, filter_object, sizeLimit=1
        )
    except Exception as e:
        result = LdapSearchResult(False, search_dn_str, filter_object, exception=e)
    else:
        if len(search_results) > 0:
            result = LdapSearchResult(True, search_dn_str, filter_object)
        else:
            result = LdapSearchResult(False, search_dn_str, filter_object)

    defer.returnValue(result)


@defer.inlineCallbacks
def can_bind_service_account(client, keep_bound=False):
    """Function for determining if service account client generated from the config can bind to the directory
    Args:
        client (_ADServiceClientProtocol): A connected client generated from an ad_client config
        keep_bound (bool): If True client will stay bound for use after this test
    Returns:
        LdapBindResult: the result of the test
    """
    try:
        yield _attempt_bind(client, keep_bound)
        result = LdapBindResult(True, client.factory.service_account_username)
    except Exception as e:
        result = LdapBindResult(
            False, client.factory.service_account_username, exception=e
        )

    defer.returnValue(result)


@defer.inlineCallbacks
def _attempt_bind(client, keep_bound=False):
    """Helper function that binds as user
    Args:
        client (_ADServiceClientProtocol)
        keep_bound (bool): If True client will not unbind after successful bind
    Returns:
        bool: True if we could bind successfully
    Raises:
        ldaperrors.LDAPException: If we couldn't bind correctly due to bad creds/bind_dn
        SSL.Error: If we couldn't bind correctly due to bad CA certs
    """
    try:
        yield client.primary_bind()
        if not keep_bound:
            yield client.perform_unbind()
        defer.returnValue(True)
    except (ldaperrors.LDAPException, SSL.Error) as e:
        if client.connected:
            yield client.perform_unbind()
        raise e
