# pylint: disable=unused-argument, multiple-statements, no-self-use, super-init-not-called

from __future__ import annotations

from typing import Dict, List, Union

from ldaptor.protocols.ldap.ldapsyntax import LDAPEntryWithClient

LDAPAttribute = Union[bytes]
LDAPAttributeMap = Dict[bytes, List[LDAPAttribute]]


class BytesLDAPEntry(LDAPEntryWithClient):
    """ This exists to allow us to ask the type checker to enforce byte-values for this partcular
        LDAPEntry (such as those that come from search results).
        This is a type-checking hack, not a concrete type. """

    attributes: Dict[bytes, List[bytes]]
