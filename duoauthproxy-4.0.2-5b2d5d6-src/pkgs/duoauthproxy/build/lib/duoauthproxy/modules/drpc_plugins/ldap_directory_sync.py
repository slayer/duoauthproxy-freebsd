""" Module for providing the LDAP methods needed for directory sync functionality
Register this module DrpcServerModule in order to have access to these functions. """
import functools
from typing import Optional, Any, Set

import drpc.v1 as drpc
import six
from ldaptor import ldapfilter
from ldaptor.protocols import pureldap, pureber
from ldaptor.protocols.ldap import ldaperrors, distinguishedname
from ldaptor.protocols.ldap.ldaperrors import LDAPOperationsError
from twisted.internet import defer

from duoauthproxy.modules.drpc_plugins import ldap_base
from duoauthproxy.lib import ldap, log, const

RFC_2696_CONTROL_TYPE = b'1.2.840.113556.1.4.319'

PAGINATION_TYPE_CRITICAL = 'force'
PAGINATION_TYPE_ENABLE = 'True'
PAGINATION_TYPE_DISABLE = 'False'

DEFAULT_PAGE_SIZE = 5000
# ldap multi-value attributes can only be returned in segments of 1500 values
# per request. actually, it's controlled by a server-side setting but 1500 is
# the default. it's incredibly unlikely that anyone would make this SMALLER
# than 1500. if they make it larger then it shouldn't make too much difference.
LDAP_ATTR_DEFAULT_RANGE_LEN = 1500

PRINTABLE = set('0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[]^_`{|}~ ')


class LdapSyncClientProtocol(ldap.client.ADClientProtocol):
    """ This class exists solely to improve the logging during directory sync calls. Twisted
    logs class names as a prefix """
    pass


class LdapSyncClientFactory(ldap.client.ADClientFactory):
    """ This class exists solely to improve the logging during directory sync calls. Twisted
    logs class names as a prefix """
    protocol = LdapSyncClientProtocol


class LdapSyncDrpcPlugin(ldap_base.BaseLdapDrpcPlugin):
    ldap_client_factory = LdapSyncClientFactory

    def __init__(self, config):
        super(LdapSyncDrpcPlugin, self).__init__(config)

        self.service_account_username = config.get_str(ldap_base.CONFIG_BIND_USER, '')
        self.service_account_password = config.get_protected_str(
            '{0}_protected'.format(ldap_base.CONFIG_BIND_PASSWORD), ldap_base.CONFIG_BIND_PASSWORD, '')

    def get_drpc_calls(self):
        return {
            'ldap_search': self.do_ldap_search,
        }

    @drpc.inlineCallbacks
    def do_ldap_search(self,
                       host: str,
                       port: int,
                       base_dn: str,
                       filter_text: Optional[str] = None,
                       attributes: Optional[Set[str]] = None,
                       ntlm_domain: Optional[str] = None,
                       ntlm_workstation: Optional[str] = None,
                       auth_type: str = const.AD_AUTH_TYPE_NTLM_V2,
                       transport_type: str = const.AD_TRANSPORT_STARTTLS,
                       ssl_verify_depth: int = const.DEFAULT_SSL_VERIFY_DEPTH,
                       ssl_verify_hostname: bool = True,
                       ssl_ca_certs: Optional[str] = None,
                       pagination: Optional[str] = PAGINATION_TYPE_CRITICAL,
                       page_size: int = DEFAULT_PAGE_SIZE,
                       max_result_size: Optional[int] = None,
                       timeout: int = 60,
                       call_id: Optional[int] = None):
        """
        * host: LDAP IP address we will perform actions against.
        * port: LDAP server port.
        * filter_text: Filter user search.
        * attributes: Retrieve only the listed attributes. If None,
          retrieve all attributes.
        * ntlm_{domain, workstation}: Windows authentication mechanism.
          Allows for bypassing primary bind if already within the domain.
        * auth_type: Bind method to use, e.g. NTLM, Plain, SSPI, etc.
        * transport_type: Method of transportation to use, e.g. Clear, TLS,
          LDAPS, etc.
        * timeout: If either establishing the connection or binding
          and searching take longer than this number of seconds
          the response will be an error.
        * page_size: As in RFC 2696.
        * max_result_size: If paging, stop requesting results after
          when at least this number of results have been received.
        """

        if attributes is None:
            attributes = set()

        try:
            attributes = set(k.lower() for k in attributes)
            if 'userpassword' in attributes:
                attributes.remove('userpassword')
        except Exception as e:
            log.err(e)
            raise drpc.CallBadArgError(['attributes'])

        page_size = parse_positive_int(page_size, 'page_size')
        if max_result_size is not None:
            max_result_size = parse_positive_int(
                max_result_size, 'max_result_size')

        if not (filter_text is None
                or isinstance(filter_text, six.string_types)):
            raise drpc.CallBadArgError(['filter_text'])

        bind_dn = self.service_account_username
        bind_pw = self.service_account_password

        log.msg(("Performing LDAP search: "
                 "call_id={call_id} host={host} port={port} base_dn={base_dn} "
                 "auth_type={auth_type} transport_type={transport_type} "
                 "ssl_verify_depth={ssl_verify_depth} ssl_verify_hostname={ssl_verify_hostname} "
                 "ssl_ca_certs={ssl_ca_certs} attributes={attributes}"
                 ).format(call_id=call_id, host=host, port=port,
                          base_dn=base_dn, auth_type=auth_type,
                          transport_type=transport_type,
                          ssl_verify_depth=ssl_verify_depth,
                          ssl_verify_hostname=ssl_verify_hostname,
                          attributes=attributes,
                          ssl_ca_certs=ssl_ca_certs is not None)
                )

        self._verify_ldap_config_args(
            bind_dn,
            bind_pw,
            auth_type,
            transport_type
        )

        cl, timeout_dc = yield self._get_client(
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
                yield cl.perform_bind(
                    auth_type=auth_type,
                    dn=bind_dn,
                    username=bind_dn,
                    password=bind_pw,
                    domain=ntlm_domain,
                    workstation=ntlm_workstation,
                    permit_implicit=True
                )
            except Exception:
                if timeout_dc.active():
                    log.err(None, ldap_base.ERR_LDAP_BIND_FAILED)
                    raise drpc.CallError(ldap_base.ERR_LDAP_BIND_FAILED)
                else:
                    log.err(None, ldap_base.ERR_LDAP_TIMEOUT)
                    raise drpc.CallError(ldap_base.ERR_LDAP_TIMEOUT, {
                        'during': 'bind',
                    })

            try:
                filter_bytes = None
                if filter_text is not None:
                    filter_bytes = filter_text.encode('utf-8')

                result = yield self._paged_search(
                    client=cl,
                    base_dn=base_dn,
                    filter_text=filter_bytes,
                    attributes=[a.encode('utf-8') for a in attributes],
                    pagination=pagination,
                    page_size=page_size,
                    max_result_size=max_result_size,
                )

                # any object that has a 'member' attribute is a potential
                # group object. if that attribute is an empty list then the
                # group is either empty or contains more values than the
                # server's configured maximum attribute length (usually 1500)
                # results.
                # try to check for members using range before giving up.
                try_ranged = [obj for obj in result if obj.get('member') == []]
                if try_ranged:
                    yield self.try_ranged_search(cl, base_dn, try_ranged)

            except Exception:
                if timeout_dc.active():
                    log.err(None, ldap_base.ERR_LDAP_SEARCH_FAILED)
                    raise drpc.CallError(ldap_base.ERR_LDAP_SEARCH_FAILED)
                else:
                    log.err(None, ldap_base.ERR_LDAP_TIMEOUT)
                    raise drpc.CallError(ldap_base.ERR_LDAP_TIMEOUT, {
                        'during': 'search',
                    })
        finally:
            if timeout_dc.active():
                timeout_dc.cancel()
            try:
                cl.transport.abortConnection()
            except Exception:
                pass

        defer.returnValue({
            'results': result,
        })

    @defer.inlineCallbacks
    def _paged_search(self, client, base_dn, filter_text, attributes,
                      pagination=PAGINATION_TYPE_CRITICAL,
                      max_result_size=None,
                      page_size=DEFAULT_PAGE_SIZE):
        """
        Given a bound client, search exhaustively using RFC 2696.
        Return a list of dictionaries containing the attributes
        of the resulting entries.

        * attributes: Set of lower-case byte-strings.
        """
        res = []

        def handle_msg(value, controls, d):
            try:
                if isinstance(value, pureldap.LDAPSearchResultDone):
                    e = ldaperrors.get(
                        value.resultCode, value.errorMessage)
                    if isinstance(e, (ldaperrors.Success, ldaperrors.LDAPSizeLimitExceeded)):
                        cookie = get_cookie(controls)
                        d.callback((None, cookie))
                    else:
                        d.callback((e, None))
                elif isinstance(value, pureldap.LDAPSearchResultEntry):
                    # Always send DN. Overwrite DN from attribute set, if any.
                    obj = {
                        'distinguishedname': [escape_bytes(value.objectName)]
                    }

                    for k, vs in value.attributes:
                        # Smash attribute name case.
                        k = k.decode().lower()

                        # Server may not honor attributes (e.g.
                        # SearchByTreeWalkingMixin).
                        if attributes and k.encode() not in attributes:
                            continue

                        # Covert value to list and encode for JSON.
                        vs = [escape_bytes(v) for v in vs]

                        obj[k] = vs

                    # Refuse to return certain attributes even if all
                    # attributes were requested.
                    obj.pop('userpassword', None)

                    res.append(obj)
            except Exception:
                log.err()
            finally:
                return isinstance(value, (
                    pureldap.LDAPBindResponse,
                    pureldap.LDAPSearchResultDone,
                ))

        if filter_text:
            filter_obj = ldapfilter.parseFilter(filter_text)
        else:
            filter_obj = None
        op = pureldap.LDAPSearchRequest(
            baseObject=base_dn,
            scope=pureldap.LDAP_SCOPE_wholeSubtree,
            derefAliases=0,
            sizeLimit=0,
            timeLimit=0,
            typesOnly=0,
            filter=filter_obj,
            attributes=attributes,
        )

        if pagination == PAGINATION_TYPE_CRITICAL:
            # AD may ignore the RFC 2696 control if it is not
            # critical. The caller can override this default if the
            # control should be present but not critical or absent.
            criticality = True
        else:
            criticality = False

        cookie = pureber.BEROctetString('')
        while True:
            if pagination == PAGINATION_TYPE_DISABLE:
                controls = None
            else:
                controls = [
                    (
                        RFC_2696_CONTROL_TYPE,
                        criticality,
                        pureber.BERSequence([
                            pureber.BERInteger(page_size),
                            cookie,
                        ]),
                    ),
                ]

            d = defer.Deferred()
            yield client.send(
                op=op,
                controls=controls,
                handler=functools.partial(handle_msg, d=d),
                handle_msg=True,
            )

            # handle_msg() is synchronous so d should be called by the
            # time it returns to LDAPClient.handle().
            if d.called:
                e, cookie = yield d
            else:
                log.err('Paging cookie not found!')
                break
            if e is not None:
                # So the RPC caller can distinguish between problems
                # with the search (e.g. bad configuration) and
                # searches that return no results.
                raise e
            if not cookie.value:
                break
            if max_result_size is not None and len(res) > max_result_size:
                break
        defer.returnValue(res)

    @defer.inlineCallbacks
    def try_ranged_search(self, client, base_dn, objs):
        """ So, you are an empty group object or a group with too many members
            to return in one shot.
            Let's try to grab those members a few at a time until we determine
            that the group is empty or we've built up the full list of members.
        """
        for obj in objs:
            member_range = None
            previous_result_empty = False
            # loop until we've exhausted all range segments
            while True:
                # can't help you without a dn. sorry.
                if not obj.get('distinguishedname'):
                    break
                previous_range = member_range
                member_range = next_range(previous_range, previous_result_empty)

                # create an ldap filter object to search with.
                # pureldap will escape the distinguishedname, making it safe.
                # Since we're reading the distinguishedname from search results,
                # we'll need to unescape it before it gets re-escaped.
                attr_obj = pureldap.LDAPAttributeDescription(
                    'distinguishedname')
                value_obj = pureldap.LDAPAssertionValue(
                    distinguishedname.unescape(obj['distinguishedname'][0]))
                filter_object = pureldap.LDAPFilter_equalityMatch(
                    attr_obj, value_obj)

                attributes = [
                    'member;range={0}-{1}'.format(
                        member_range[0], member_range[1])]
                try:
                    ranged_res = yield client.perform_search(base_dn, filter_object, attributes=attributes)
                except LDAPOperationsError as e:
                    # searched for a range that exceeds the total number of
                    # elements in the attribute.
                    # if this is the first instance of this error, we may
                    # just need to try again with a '*' as the upper bound
                    # to get the last few members.
                    # if this is the second time (we are using the '*'), then
                    # we already have all of the members and can break.
                    if ldap.client.ERR_AD_CANT_RETRIEVE_ATTS in e.message:
                        if previous_result_empty:
                            break
                        previous_result_empty = True
                        continue
                    # something bad happened... give up
                    else:
                        log.err(e)
                        break
                # no results; we're done here
                if len(ranged_res) == 0:
                    break
                else:
                    # update the result object with the newly discovered
                    # members
                    for k, vs in ranged_res[0].items():
                        k = k.decode().lower()
                        vs = [escape_bytes(v) for v in vs]
                        if k.startswith('member;'):
                            obj['member'].extend(vs)


def parse_positive_int(v: Any, arg_name: str) -> int:
    try:
        parsed = int(v)
        assert parsed > 0
    except Exception:
        raise drpc.CallBadArgError([arg_name])

    return parsed


def get_cookie(controls):
    for control in controls:
        # control was parsed by pureldap.LDAPControl.fromBER but is
        # now [type, criticality, value], not an LDAPControl object.
        if control[0] == RFC_2696_CONTROL_TYPE:
            value = pureber.BERSequence.fromBER(
                tag=None,
                content=control[2],  # The control's value.
                berdecoder=pureber.BERDecoderContext())
            _size, cookie = value[0]
            return cookie
    return None


def next_range(previous_range, previous_result_empty, range_len=LDAP_ATTR_DEFAULT_RANGE_LEN):
    """ Calculate the next range to use for requesting attribute values
        that exceed the servers maximum attr length setting.
        If the previous search caused an error because the range segment
        did not include values, try again with a '*' as the upper range
        to get any remaining members.
    """
    if previous_result_empty:
        return 0 if previous_range is None else previous_range[0], '*'
    if previous_range is None:
        return 0, range_len - 1
    else:
        return previous_range[1] + 1, previous_range[1] + range_len


def escape_bytes(s):
    if isinstance(s, str):
        s = s.encode()

    return ''.join([
        chr(c) if chr(c) in PRINTABLE else '\\{0:02x}'.format(c)
        for c in s
    ])
