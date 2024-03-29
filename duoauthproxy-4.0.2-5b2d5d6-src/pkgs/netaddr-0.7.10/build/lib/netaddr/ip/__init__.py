#-----------------------------------------------------------------------------
#   Copyright (c) 2008-2012, David P. D. Moss. All rights reserved.
#
#   Released under the BSD license. See the LICENSE file for details.
#-----------------------------------------------------------------------------
"""Routines for IPv4 and IPv6 addresses, subnets and ranges."""

import sys as _sys
import re as _re

from netaddr.core import AddrFormatError, AddrConversionError, num_bits, \
    DictDotLookup, NOHOST, N, INET_PTON, P, ZEROFILL, Z

from netaddr.strategy import ipv4 as _ipv4, ipv6 as _ipv6

from netaddr.compat import _sys_maxint, _iter_range, _is_str, _int_type, \
    _str_type

#-----------------------------------------------------------------------------
#   Pre-compiled regexen used by cidr_merge() function.
RE_CIDR_ADJACENT = _re.compile(r'^([01]+)0 \1[1]$')
RE_CIDR_WITHIN = _re.compile(r'^([01]+) \1[10]+$')
RE_VALID_CIDR_BITS = _re.compile('^[01]+$')

#-----------------------------------------------------------------------------
class BaseIP(object):
    """
    An abstract base class for common operations shared between various IP
    related subclasses.

    """
    __slots__ = ('_value', '_module')

    def __init__(self):
        """Constructor."""
        self._value = None
        self._module = None

    def _set_value(self, value):
        if not isinstance(value, _int_type):
            raise TypeError('int argument expected, not %s' % type(value))
        if not 0 <= value <= self._module.max_int:
            raise AddrFormatError('value out of bounds for an %s address!' \
                % self._module.family_name)
        self._value = value

    value = property(lambda self: self._value, _set_value,
        doc='a positive integer representing the value of IP address/subnet.')

    def key(self):
        """
        :return: a key tuple that uniquely identifies this IP address.
        """
        return NotImplemented

    def sort_key(self):
        """
        :return: A key tuple used to compare and sort this `IPAddress`
            correctly.
        """
        return NotImplemented

    def __hash__(self):
        """
        :return: A hash value uniquely indentifying this IP object.
        """
        return hash(self.key())

    def __eq__(self, other):
        """
        :param other: an `IPAddress` or `IPNetwork` object.

        :return: ``True`` if this `IPAddress` or `IPNetwork` object is
            equivalent to ``other``, ``False`` otherwise.
        """
        try:
            return self.key() == other.key()
        except (AttributeError, TypeError):
            return NotImplemented

    def __ne__(self, other):
        """
        :param other: an `IPAddress` or `IPNetwork` object.

        :return: ``True`` if this `IPAddress` or `IPNetwork` object is
            not equivalent to ``other``, ``False`` otherwise.
        """
        try:
            return self.key() != other.key()
        except (AttributeError, TypeError):
            return NotImplemented

    def __lt__(self, other):
        """
        :param other: an `IPAddress` or `IPNetwork` object.

        :return: ``True`` if this `IPAddress` or `IPNetwork` object is
            less than ``other``, ``False`` otherwise.
        """
        try:
            return self.sort_key() < other.sort_key()
        except (AttributeError, TypeError):
            return NotImplemented

    def __le__(self, other):
        """
        :param other: an `IPAddress` or `IPNetwork` object.

        :return: ``True`` if this `IPAddress` or `IPNetwork` object is
            less than or equal to ``other``, ``False`` otherwise.
        """
        try:
            return self.sort_key() <= other.sort_key()
        except (AttributeError, TypeError):
            return NotImplemented

    def __gt__(self, other):
        """
        :param other: an `IPAddress` or `IPNetwork` object.

        :return: ``True`` if this `IPAddress` or `IPNetwork` object is
            greater than ``other``, ``False`` otherwise.
        """
        try:
            return self.sort_key() > other.sort_key()
        except (AttributeError, TypeError):
            return NotImplemented

    def __ge__(self, other):
        """
        :param other: an `IPAddress` or `IPNetwork` object.

        :return: ``True`` if this `IPAddress` or `IPNetwork` object is
            greater than or equal to ``other``, ``False`` otherwise.
        """
        try:
            return self.sort_key() >= other.sort_key()
        except (AttributeError, TypeError):
            return NotImplemented

    def is_unicast(self):
        """:return: ``True`` if this IP is unicast, ``False`` otherwise"""
        return not self.is_multicast()

    def is_multicast(self):
        """:return: ``True`` if this IP is multicast, ``False`` otherwise"""
        if self._module == _ipv4:
            return self in IPV4_MULTICAST
        elif self._module == _ipv6:
            return self in IPV6_MULTICAST

    def is_loopback(self):
        """
        :return: ``True`` if this IP is loopback address (not for network
            transmission), ``False`` otherwise.
            References: RFC 3330 and 4291.
        """
        if self.version == 4:
            return self in IPV4_LOOPBACK
        elif self.version == 6:
            return self == IPV6_LOOPBACK

    def is_private(self):
        """
        :return: ``True`` if this IP is for internal/private use only
            (i.e. non-public), ``False`` otherwise. Reference: RFCs 1918,
            3330, 4193, 3879 and 2365.
        """
        if self.version == 4:
            for cidr in IPV4_PRIVATE:
                if self in cidr:
                    return True
        elif self.version == 6:
            for cidr in IPV6_PRIVATE:
                if self in cidr:
                    return True

        if self.is_link_local():
            return True

        return False

    def is_link_local(self):
        """
        :return: ``True`` if this IP is link-local address ``False`` otherwise.
            Reference: RFCs 3927 and 4291.
        """
        if self.version == 4:
            return self in IPV4_LINK_LOCAL
        elif self.version == 6:
            return self in IPV6_LINK_LOCAL

    def is_reserved(self):
        """
        :return: ``True`` if this IP is in IANA reserved range, ``False``
            otherwise. Reference: RFCs 3330 and 3171.
        """
        if self.version == 4:
            for cidr in IPV4_RESERVED:
                if self in cidr:
                    return True
        elif self.version == 6:
            for cidr in IPV6_RESERVED:
                if self in cidr:
                    return True
        return False

    def is_ipv4_mapped(self):
        """
        :return: ``True`` if this IP is IPv4-compatible IPv6 address, ``False``
            otherwise.
        """
        return self.version == 6 and (self._value >> 32) == 0xffff

    def is_ipv4_compat(self):
        """
        :return: ``True`` if this IP is IPv4-mapped IPv6 address, ``False``
            otherwise.
        """
        return self.version == 6 and (self._value >> 32) == 0

    @property
    def info(self):
        """
        A record dict containing IANA registration details for this IP address
        if available, None otherwise.
        """
        #   Lazy loading of IANA data structures.
        from netaddr.ip.iana import query
        return DictDotLookup(query(self))

    @property
    def version(self):
        """the IP protocol version represented by this IP object."""
        return self._module.version


#-----------------------------------------------------------------------------
class IPAddress(BaseIP):
    """
    An individual IPv4 or IPv6 address without a net mask or subnet prefix.

    To support these and other network based operations, see `IPNetwork`.

    """
    __slots__ = ()

    def __init__(self, addr, version=None, flags=0):
        """
        Constructor.

        :param addr: an IPv4 or IPv6 address which may be represented in an
            accepted string format, as an unsigned integer or as another
            IPAddress object (copy construction).

        :param version: (optional) optimizes version detection if specified
            and distinguishes between IPv4 and IPv6 for addresses with an
            equivalent integer value.

        :param flags: (optional) decides which rules are applied to the
            interpretation of the addr value. Supported constants are
            INET_PTON and ZEROFILL. See the netaddr.core docs for further
            details.

        """
        super(IPAddress, self).__init__()

        if isinstance(addr, BaseIP):
            #   Copy constructor.
            if version is not None and version != addr._module.version:
                raise ValueError('cannot switch IP versions using '
                    'copy constructor!')
            self._value = addr._value
            self._module = addr._module
        else:
            #   Explicit IP address version.
            if version is not None:
                if version == 4:
                    self._module = _ipv4
                elif version == 6:
                    self._module = _ipv6
                else:
                    raise ValueError('%r is an invalid IP version!' % version)

            has_upper = hasattr(addr, 'upper')
            if has_upper and '/' in addr:
                raise ValueError('%s() does not support netmasks or subnet' \
                    ' prefixes! See documentation for details.'
                    % self.__class__.__name__)

            if self._module is None:
                #   IP version is implicit, detect it from addr.
                if isinstance(addr, _int_type):
                    try:
                        if 0 <= int(addr) <= _ipv4.max_int:
                            self._value = int(addr)
                            self._module = _ipv4
                        elif _ipv4.max_int < int(addr) <= _ipv6.max_int:
                            self._value = int(addr)
                            self._module = _ipv6
                    except ValueError:
                        pass
                else:
                    for module in _ipv4, _ipv6:
                        try:
                            self._value = module.str_to_int(addr, flags)
                        except:
                            continue
                        else:
                            self._module = module
                            break

                if self._module is None:
                    raise AddrFormatError('failed to detect a valid IP ' \
                        'address from %r' % addr)
            else:
                #   IP version is explicit.
                if has_upper:
                    try:
                        self._value = self._module.str_to_int(addr, flags)
                    except AddrFormatError:
                        raise AddrFormatError('base address %r is not IPv%d'
                            % (addr, self._module.version))
                else:
                    if 0 <= int(addr) <= self._module.max_int:
                        self._value = int(addr)
                    else:
                        raise AddrFormatError('bad address format: %r' % addr)

    def __getstate__(self):
        """:returns: Pickled state of an `IPAddress` object."""
        return self._value, self._module.version

    def __setstate__(self, state):
        """
        :param state: data used to unpickle a pickled `IPAddress` object.

        """
        value, version = state

        self._value = value

        if version == 4:
            self._module = _ipv4
        elif version == 6:
            self._module = _ipv6
        else:
            raise ValueError('unpickling failed for object state: %s' \
                % str(state))

    def is_hostmask(self):
        """
        :return: ``True`` if this IP address host mask, ``False`` otherwise.
        """
        int_val = self._value + 1
        return (int_val & (int_val - 1) == 0)

    def is_netmask(self):
        """
        :return: ``True`` if this IP address network mask, ``False`` otherwise.
        """
        int_val = (self._value ^ self._module.max_int) + 1
        return (int_val & (int_val - 1) == 0)

    def __iadd__(self, num):
        """
        Increases the numerical value of this IPAddress by num.

        An IndexError is raised if result exceeds maximum IP address value or
        is less than zero.

        :param num: size of IP address increment.
        """
        new_value = self._value + num
        if 0 <= new_value <= self._module.max_int:
            self._value = new_value
            return self
        raise IndexError('result outside valid IP address boundary!')

    def __isub__(self, num):
        """
        Decreases the numerical value of this IPAddress by num.

        An IndexError is raised if result is less than zero or exceeds maximum
        IP address value.

        :param num: size of IP address decrement.
        """
        new_value = self._value - num
        if 0 <= new_value <= self._module.max_int:
            self._value = new_value
            return self
        raise IndexError('result outside valid IP address boundary!')

    def __add__(self, num):
        """
        Add the numerical value of this IP address to num and provide the
        result as a new IPAddress object.

        :param num: size of IP address increase.

        :return: a new IPAddress object with its numerical value increased by num.
        """
        new_value = self._value + num
        if 0 <= new_value <= self._module.max_int:
            return self.__class__(new_value, self.version)
        raise IndexError('result outside valid IP address boundary!')

    __radd__ = __add__

    def __sub__(self, num):
        """
        Subtract the numerical value of this IP address from num providing
        the result as a new IPAddress object.

        :param num: size of IP address decrease.

        :return: a new IPAddress object with its numerical value decreased by num.
        """
        new_value = self._value - num
        if 0 <= new_value <= self._module.max_int:
            return self.__class__(new_value, self.version)
        raise IndexError('result outside valid IP address boundary!')

    def __rsub__(self, num):
        """
        Subtract num (lvalue) from the numerical value of this IP address
        (rvalue) providing the result as a new IPAddress object.

        :param num: size of IP address decrease.

        :return: a new IPAddress object with its numerical value decreased by num.
        """
        new_value = num - self._value
        if 0 <= new_value <= self._module.max_int:
            return self.__class__(new_value, self.version)
        raise IndexError('result outside valid IP address boundary!')

    def key(self):
        """
        :return: a key tuple that uniquely identifies this IP address.
        """
        #   NB - we return the value here twice because this IP Address may
        #   be sorted with a list of networks and it should still end up
        #   in the expected order.
        return self.version, self._value

    def sort_key(self):
        """:return: A key tuple used to compare and sort this `IPAddress` correctly."""
        return self.version, self._value, self._module.width

    def __int__(self):
        """:return: the value of this IP address as an unsigned integer"""
        return self._value

    def __long__(self):
        """:return: the value of this IP address as an unsigned integer"""
        return self._value

    def __oct__(self):
        """:return: an octal string representation of this IP address."""
        #   Python 2.x
        if self._value == 0:
            return '0'
        return '0%o' % self._value

    def __hex__(self):
        """:return: a hexadecimal string representation of this IP address."""
        #   Python 2.x
        return '0x%x' % self._value

    def __index__(self):
        """
        :return: return the integer value of this IP address when called by \
            hex(), oct() or bin().
        """
        #   Python 3.x
        return self._value

    def bits(self, word_sep=None):
        """
        :param word_sep: (optional) the separator to insert between words.
            Default: None - use default separator for address type.

        :return: the value of this IP address as a binary digit string."""
        return self._module.int_to_bits(self._value, word_sep)

    @property
    def packed(self):
        """The value of this IP address as a packed binary string."""
        return self._module.int_to_packed(self._value)

    @property
    def words(self):
        """
        A list of unsigned integer words (octets for IPv4, hextets for IPv6)
        found in this IP address.
        """
        return self._module.int_to_words(self._value)

    @property
    def bin(self):
        """
        The value of this IP adddress in standard Python binary
        representational form (0bxxx). A back port of the format provided by
        the builtin bin() function found in Python 2.6.x and higher.
        """
        return self._module.int_to_bin(self._value)

    @property
    def reverse_dns(self):
        """The reverse DNS lookup record for this IP address"""
        return self._module.int_to_arpa(self._value)

    def ipv4(self):
        """
        Raises an `AddrConversionError` if IPv6 address cannot be converted
        to IPv4.

        :return: A numerically equivalent version 4 `IPAddress` object.
        """
        ip = None
        klass = self.__class__

        if self.version == 4:
            ip = klass(self._value, 4)
        elif self.version == 6:
            if 0 <= self._value <= _ipv4.max_int:
                ip = klass(self._value, 4)
            elif _ipv4.max_int <= self._value <= 0xffffffffffff:
                ip = klass(self._value - 0xffff00000000, 4)
            else:
                raise AddrConversionError('IPv6 address %s unsuitable for ' \
                    'conversion to IPv4!' % self)
        return ip

    def ipv6(self, ipv4_compatible=False):
        """
        .. note:: The IPv4-mapped IPv6 address format is now considered \
            deprecated. See RFC 4291 or later for details.

        :param ipv4_compatible: If ``True`` returns an IPv4-mapped address
            (::ffff:x.x.x.x), an IPv4-compatible (::x.x.x.x) address
            otherwise. Default: False (IPv4-mapped).

        :return: A numerically equivalent version 6 `IPAddress` object.
        """
        ip = None
        klass = self.__class__

        if self.version == 6:
            if ipv4_compatible and \
                (0xffff00000000 <= self._value <= 0xffffffffffff):
                ip = klass(self._value - 0xffff00000000, 6)
            else:
                ip = klass(self._value, 6)
        elif self.version == 4:
            #   IPv4-Compatible IPv6 address
            ip = klass(self._value, 6)
            if not ipv4_compatible:
                #   IPv4-Mapped IPv6 address
                ip = klass(0xffff00000000 + self._value, 6)

        return ip

    def format(self, dialect=None):
        """
        Only relevant for IPv6 addresses. Has no effect for IPv4.

        :param dialect: An ipv6_* dialect class.

        :return: an alternate string representation for this IP address.
        """
        if dialect is not None:
            if not hasattr(dialect, 'word_fmt'):
                raise TypeError(
                    'custom dialects should subclass ipv6_verbose!')
        return self._module.int_to_str(self._value, dialect=dialect)

    def __or__(self, other):
        """
        :param other: An `IPAddress` object (or other int-like object).

        :return: bitwise OR (x | y) between the integer value of this IP
            address and ``other``.
        """
        return self.__class__(self._value | int(other), self.version)

    def __and__(self, other):
        """
        :param other: An `IPAddress` object (or other int-like object).

        :return: bitwise AND (x & y) between the integer value of this IP
            address and ``other``.
        """
        return self.__class__(self._value & int(other), self.version)

    def __xor__(self, other):
        """
        :param other: An `IPAddress` object (or other int-like object).

        :return: bitwise exclusive OR (x ^ y) between the integer value of
            this IP address and ``other``.
        """
        return self.__class__(self._value ^ int(other), self.version)

    def __lshift__(self, numbits):
        """
        :param numbits: size of bitwise shift.

        :return: an `IPAddress` object based on this one with its integer
            value left shifted by ``numbits``.
        """
        return self.__class__(self._value << numbits, self.version)

    def __rshift__(self, numbits):
        """
        :param numbits: size of bitwise shift.

        :return: an `IPAddress` object based on this one with its integer
            value right shifted by ``numbits``.
        """
        return self.__class__(self._value >> numbits, self.version)

    def __nonzero__(self):
        """:return: ``True`` if the numerical value of this IP address is not \
            zero, ``False`` otherwise."""
        #   Python 2.x.
        return bool(self._value)

    __bool__ = __nonzero__  #   Python 3.x.

    def __str__(self):
        """:return: IP address in presentational format"""
        return self._module.int_to_str(self._value)

    def __repr__(self):
        """:return: Python statement to create an equivalent object"""
        return "%s('%s')" % (self.__class__.__name__, self)

#-----------------------------------------------------------------------------
class IPListMixin(object):
    """
    A mixin class providing shared list-like functionality to classes
    representing groups of IP addresses.

    """
    def __iter__(self):
        """
        :return: An iterator providing access to all `IPAddress` objects
            within range represented by this ranged IP object.
        """
        start_ip = IPAddress(self.first, self.version)
        end_ip = IPAddress(self.last, self.version)
        return iter_iprange(start_ip, end_ip)

    @property
    def size(self):
        """
        The total number of IP addresses within this ranged IP object.
        """
        return int(self.last - self.first + 1)

    def __len__(self):
        """
        :return: the number of IP addresses in this ranged IP object. Raises
            an `IndexError` if size > system max int (a Python 2.x
            limitation). Use the .size property for subnets of any size.
        """
        size = self.size
        if size > _sys_maxint:
            raise IndexError(("range contains more than %d (index size max) "
               "IP addresses! Use the .size property instead." % _sys_maxint))
        return size

    def __getitem__(self, index):
        """
        :return: The IP address(es) in this `IPNetwork` object referenced by
            index or slice. As slicing can produce large sequences of objects
            an iterator is returned instead of the more usual `list`.
        """
        item = None

        if hasattr(index, 'indices'):
            if self._module.version == 6:
                raise TypeError('IPv6 slices are not supported!')

            (start, stop, step) = index.indices(self.size)

            if (start + step < 0) or (step > stop):
                #   step value exceeds start and stop boundaries.
                item = iter([IPAddress(self.first, self.version)])
            else:
                start_ip = IPAddress(self.first + start, self.version)
                end_ip = IPAddress(self.first + stop - step, self.version)
                item = iter_iprange(start_ip, end_ip, step)
        else:
            try:
                index = int(index)
                if (- self.size) <= index < 0:
                    #   negative index.
                    item = IPAddress(self.last + index + 1, self.version)
                elif 0 <= index <= (self.size - 1):
                    #   Positive index or zero index.
                    item = IPAddress(self.first + index, self.version)
                else:
                    raise IndexError('index out range for address range size!')
            except ValueError:
                raise TypeError('unsupported index type %r!' % index)

        return item

    def __contains__(self, other):
        """
        :param other: an `IPAddress` or ranged IP object.

        :return: ``True`` if other falls within the boundary of this one,
            ``False`` otherwise.
        """
        if self.version != other.version:
            return False
        if hasattr(other, '_value') and not hasattr(other, '_prefixlen'):
            return other._value >= self.first and other._value <= self.last
        return other.first >= self.first and other.last <= self.last

    def __nonzero__(self):
        """
        Ranged IP objects always represent a sequence of at least one IP
        address and are therefore always True in the boolean context.
        """
        #   Python 2.x.
        return True

    __bool__ = __nonzero__  #   Python 3.x.

#-----------------------------------------------------------------------------
def parse_ip_network(module, addr, implicit_prefix=False, flags=0):
    if isinstance(addr, tuple):
        #   CIDR integer tuple
        try:
            val1, val2 = addr
        except ValueError:
            raise AddrFormatError('invalid %s tuple!' % module.family_name)

        if 0 <= val1 <= module.max_int:
            value = val1
            if 0 <= val2 <= module.width:
                prefixlen = val2
            else:
                raise AddrFormatError('invalid prefix for %s tuple!' \
                    % module.family_name)
        else:
            raise AddrFormatError('invalid address value for %s tuple!' \
                % module.family_name)
    elif isinstance(addr, _str_type):
        #   CIDR-like string subnet
        if implicit_prefix:
            #TODO: deprecate this option in netaddr 0.8.x
            addr = cidr_abbrev_to_verbose(addr)
        try:
            if '/' in addr:
                val1, val2 = addr.split('/', 1)
            else:
                val1 = addr
                val2 = None
        except ValueError:
            raise AddrFormatError('invalid IPNetwork address %s!' % addr)

        try:
            ip = IPAddress(val1, module.version, flags=INET_PTON)
        except AddrFormatError:
            if module.version == 4:
                #   Try a partial IPv4 network address...
                expanded_addr = _ipv4.expand_partial_address(val1)
                ip = IPAddress(expanded_addr, module.version, flags=INET_PTON)
            else:
                raise AddrFormatError('invalid IPNetwork address %s!' % addr)
        value = ip._value

        try:
            #   Integer CIDR prefix.
            prefixlen = int(val2)
        except TypeError:
            if val2 is None:
                #   No prefix was specified.
                prefixlen = module.width
        except ValueError:
            #   Not an integer prefix, try a netmask/hostmask prefix.
            mask = IPAddress(val2, module.version, flags=INET_PTON)
            if mask.is_netmask():
                prefixlen = module.netmask_to_prefix[mask._value]
            elif mask.is_hostmask():
                prefixlen = module.hostmask_to_prefix[mask._value]
            else:
                raise AddrFormatError('addr %r is not a valid IPNetwork!' \
                    % addr)

        if not 0 <= prefixlen <= module.width:
            raise AddrFormatError('invalid prefix for %s address!' \
                % module.family_name)
    else:
        raise TypeError('unexpected type %s for addr arg' % type(addr))

    if flags & NOHOST:
        #   Remove host bits.
        netmask = module.prefix_to_netmask[prefixlen]
        value = value & netmask

    return value, prefixlen

#-----------------------------------------------------------------------------
class IPNetwork(BaseIP, IPListMixin):
    """
    An IPv4 or IPv6 network or subnet.

    A combination of an IP address and a network mask.

    Accepts CIDR and several related variants :

    a) Standard CIDR::

        x.x.x.x/y -> 192.0.2.0/24
        x::/y -> fe80::/10

    b) Hybrid CIDR format (netmask address instead of prefix), where 'y' \
       address represent a valid netmask::

        x.x.x.x/y.y.y.y -> 192.0.2.0/255.255.255.0
        x::/y:: -> fe80::/ffc0::

    c) ACL hybrid CIDR format (hostmask address instead of prefix like \
       Cisco's ACL bitmasks), where 'y' address represent a valid netmask::

        x.x.x.x/y.y.y.y -> 192.0.2.0/0.0.0.255
        x::/y:: -> fe80::/3f:ffff:ffff:ffff:ffff:ffff:ffff:ffff

    d) Abbreviated CIDR format (as of netaddr 0.7.x this requires the \
       optional constructor argument ``implicit_prefix=True``)::

        x       -> 192
        x/y     -> 10/8
        x.x/y   -> 192.168/16
        x.x.x/y -> 192.168.0/24

        which are equivalent to::

        x.0.0.0/y   -> 192.0.0.0/24
        x.0.0.0/y   -> 10.0.0.0/8
        x.x.0.0/y   -> 192.168.0.0/16
        x.x.x.0/y   -> 192.168.0.0/24

    """
    __slots__ = ('_prefixlen',)

    def __init__(self, addr, implicit_prefix=False, version=None, flags=0):
        """
        Constructor.

        :param addr: an IPv4 or IPv6 address with optional CIDR prefix,
            netmask or hostmask. May be an IP address in presentation
            (string) format, an tuple containing and integer address and a
            network prefix, or another IPAddress/IPNetwork object (copy
            construction).

        :param implicit_prefix: (optional) if True, the constructor uses
            classful IPv4 rules to select a default prefix when one is not
            provided. If False it uses the length of the IP address version.
            (default: False)

        :param version: (optional) optimizes version detection if specified
            and distinguishes between IPv4 and IPv6 for addresses with an
            equivalent integer value.

        :param flags: (optional) decides which rules are applied to the
            interpretation of the addr value. Currently only supports the
            NOHOST option. See the netaddr.core docs for further details.

        """
        super(IPNetwork, self).__init__()

        value, prefixlen, module = None, None, None

        if hasattr(addr, '_prefixlen'):
            #   IPNetwork object copy constructor
            value = addr._value
            module = addr._module
            prefixlen = addr._prefixlen
        elif hasattr(addr, '_value'):
            #   IPAddress object copy constructor
            value = addr._value
            module = addr._module
            prefixlen = module.width
        elif version == 4:
            value, prefixlen = parse_ip_network(_ipv4, addr,
                implicit_prefix=implicit_prefix, flags=flags)
            module = _ipv4
        elif version == 6:
            value, prefixlen = parse_ip_network(_ipv6, addr,
                implicit_prefix=implicit_prefix, flags=flags)
            module = _ipv6
        else:
            if version is not None:
                raise ValueError('%r is an invalid IP version!' % version)
            try:
                module = _ipv4
                value, prefixlen = parse_ip_network(module, addr,
                    implicit_prefix, flags)
            except AddrFormatError:
                try:
                    module = _ipv6
                    value, prefixlen = parse_ip_network(module, addr,
                        implicit_prefix, flags)
                except AddrFormatError:
                    pass

                if value is None:
                    raise AddrFormatError('invalid IPNetwork %s' % addr)

        self._value = value
        self._prefixlen = prefixlen
        self._module = module

    def __getstate__(self):
        """:return: Pickled state of an `IPNetwork` object."""
        return self._value, self._prefixlen, self._module.version

    def __setstate__(self, state):
        """
        :param state: data used to unpickle a pickled `IPNetwork` object.

        """
        value, prefixlen, version = state

        self._value = value

        if version == 4:
            self._module = _ipv4
        elif version == 6:
            self._module = _ipv6
        else:
            raise ValueError('unpickling failed for object state %s' \
                % str(state))

        if 0 <= prefixlen <= self._module.width:
            self._prefixlen = prefixlen
        else:
            raise ValueError('unpickling failed for object state %s' \
                % str(state))

    def _set_prefixlen(self, value):
        if not isinstance(value, _int_type):
            raise TypeError('int argument expected, not %s' % type(value))
        if not 0 <= value <= self._module.width:
            raise AddrFormatError('invalid prefix for an %s address!' \
                % self._module.family_name)
        self._prefixlen = value

    prefixlen = property(lambda self: self._prefixlen, _set_prefixlen,
        doc='size of the bitmask used to separate the network from the host bits')

    @property
    def ip(self):
        """
        The IP address of this `IPNetwork` object. This is may or may not be
        the same as the network IP address which varies according to the value
        of the CIDR subnet prefix.
        """
        return IPAddress(self._value, self.version)

    @property
    def network(self):
        """The network address of this `IPNetwork` object."""
        return IPAddress(self._value & int(self.netmask), self.version)

    @property
    def broadcast(self):
        """The broadcast address of this `IPNetwork` object"""
        return IPAddress(self._value | self.hostmask._value, self.version)

    @property
    def first(self):
        """
        The integer value of first IP address found within this `IPNetwork`
        object.
        """
        return self._value & (self._module.max_int ^ self.hostmask._value)

    @property
    def last(self):
        """
        The integer value of last IP address found within this `IPNetwork`
        object.
        """
        hostmask = (1 << (self._module.width - self._prefixlen)) - 1
        return self._value | hostmask

    @property
    def netmask(self):
        """The subnet mask of this `IPNetwork` object."""
        netmask = self._module.max_int ^ self.hostmask._value
        return IPAddress(netmask, self.version)

    @property
    def hostmask(self):
        """The host mask of this `IPNetwork` object."""
        hostmask = (1 << (self._module.width - self._prefixlen)) - 1
        return IPAddress(hostmask, self.version)

    @property
    def cidr(self):
        """
        The true CIDR address for this `IPNetwork` object which omits any
        host bits to the right of the CIDR subnet prefix.
        """
        ip = IPAddress(self._value & int(self.netmask), self.version)
        cidr = IPNetwork("%s/%d" % (ip, self.prefixlen))
        return cidr

    def __iadd__(self, num):
        """
        Increases the value of this `IPNetwork` object by the current size
        multiplied by ``num``.

        An `IndexError` is raised if result exceeds maximum IP address value
        or is less than zero.

        :param num: (optional) number of `IPNetwork` blocks to increment \
            this IPNetwork's value by.
        """
        new_value = int(self.network) + (self.size * num)

        if (new_value + (self.size - 1)) > self._module.max_int:
            raise IndexError('increment exceeds address boundary!')
        if new_value < 0:
            raise IndexError('increment is less than zero!')

        self._value = new_value
        return self

    def __isub__(self, num):
        """
        Decreases the value of this `IPNetwork` object by the current size
        multiplied by ``num``.

        An `IndexError` is raised if result is less than zero or exceeds
        maximum IP address value.

        :param num: (optional) number of `IPNetwork` blocks to decrement \
            this IPNetwork's value by.
        """
        new_value = int(self.network) - (self.size * num)

        if new_value < 0:
            raise IndexError('decrement is less than zero!')
        if (new_value + (self.size - 1)) > self._module.max_int:
            raise IndexError('decrement exceeds address boundary!')

        self._value = new_value
        return self

    def key(self):
        """
        :return: A key tuple used to uniquely identify this `IPNetwork`.
        """
        return self.version, self.first, self.last

    def sort_key(self):
        """
        :return: A key tuple used to compare and sort this `IPNetwork` correctly.
        """
        net_size_bits = self._module.width - num_bits(self.size)
        host_bits = self._value - self.first
        return self.version, self.first, net_size_bits, host_bits

    def ipv4(self):
        """
        :return: A numerically equivalent version 4 `IPNetwork` object. \
            Raises an `AddrConversionError` if IPv6 address cannot be \
            converted to IPv4.
        """
        ip = None
        klass = self.__class__

        if self.version == 4:
            ip = klass('%s/%d' % (self.ip, self.prefixlen))
        elif self.version == 6:
            if 0 <= self._value <= _ipv4.max_int:
                addr = _ipv4.int_to_str(self._value)
                ip = klass('%s/%d' % (addr, self.prefixlen - 96))
            elif _ipv4.max_int <= self._value <= 0xffffffffffff:
                addr = _ipv4.int_to_str(self._value - 0xffff00000000)
                ip = klass('%s/%d' % (addr, self.prefixlen - 96))
            else:
                raise AddrConversionError('IPv6 address %s unsuitable for ' \
                    'conversion to IPv4!' % self)
        return ip

    def ipv6(self, ipv4_compatible=False):
        """
        .. note:: the IPv4-mapped IPv6 address format is now considered \
        deprecated. See RFC 4291 or later for details.

        :param ipv4_compatible: If ``True`` returns an IPv4-mapped address
            (::ffff:x.x.x.x), an IPv4-compatible (::x.x.x.x) address
            otherwise. Default: False (IPv4-mapped).

        :return: A numerically equivalent version 6 `IPNetwork` object.
        """
        ip = None
        klass = self.__class__

        if self.version == 6:
            if ipv4_compatible and \
                (0xffff00000000 <= self._value <= 0xffffffffffff):
                ip = klass((self._value - 0xffff00000000, self._prefixlen),
                    version=6)
            else:
                ip = klass((self._value, self._prefixlen), version=6)
        elif self.version == 4:
            if ipv4_compatible:
                #   IPv4-Compatible IPv6 address
                ip = klass((self._value, self._prefixlen + 96), version=6)
            else:
                #   IPv4-Mapped IPv6 address
                ip = klass((0xffff00000000 + self._value,
                            self._prefixlen + 96), version=6)

        return ip

    def previous(self, step=1):
        """
        :param step: the number of IP subnets between this `IPNetwork` object
            and the expected subnet. Default: 1 (the previous IP subnet).

        :return: The adjacent subnet preceding this `IPNetwork` object.
        """
        ip_copy = self.__class__('%s/%d' % (self.network, self.prefixlen),
            self.version)
        ip_copy -= step
        return ip_copy

    def next(self, step=1):
        """
        :param step: the number of IP subnets between this `IPNetwork` object
            and the expected subnet. Default: 1 (the next IP subnet).

        :return: The adjacent subnet succeeding this `IPNetwork` object.
        """
        ip_copy = self.__class__('%s/%d' % (self.network, self.prefixlen),
            self.version)
        ip_copy += step
        return ip_copy

    def supernet(self, prefixlen=0):
        """
        Provides a list of supernets for this `IPNetwork` object between the
        size of the current prefix and (if specified) an endpoint prefix.

        :param prefixlen: (optional) a CIDR prefix for the maximum supernet.
            Default: 0 - returns all possible supernets.

        :return: a tuple of supernet `IPNetwork` objects.
        """
        if not 0 <= prefixlen <= self._module.width:
            raise ValueError('CIDR prefix /%d invalid for IPv%d!' \
                % (prefixlen, self.version))

        #   Use a copy of self as we'll be editing it.
        supernet = self.cidr

        supernets = []
        while supernet.prefixlen > prefixlen:
            supernet.prefixlen -= 1
            supernets.append(supernet.cidr)

        return list(reversed(supernets))

    def subnet(self, prefixlen, count=None, fmt=None):
        """
        A generator that divides up this IPNetwork's subnet into smaller
        subnets based on a specified CIDR prefix.

        :param prefixlen: a CIDR prefix indicating size of subnets to be
            returned.

        :param count: (optional) number of consecutive IP subnets to be
            returned.

        :return: an iterator containing IPNetwork subnet objects.
        """
        if not 0 <= self.prefixlen <= self._module.width:
            raise ValueError('CIDR prefix /%d invalid for IPv%d!' \
                % (prefixlen, self.version))

        if not self.prefixlen <= prefixlen:
            #   Don't return anything.
            raise StopIteration

        #   Calculate number of subnets to be returned.
        width = self._module.width
        max_subnets = 2 ** (width - self.prefixlen) // 2 ** (width - prefixlen)

        if count is None:
            count = max_subnets

        if not 1 <= count <= max_subnets:
            raise ValueError('count outside of current IP subnet boundary!')

        base_subnet = self._module.int_to_str(self.first)
        i = 0
        while(i < count):
            subnet = self.__class__('%s/%d' % (base_subnet, prefixlen),
                self.version)
            subnet.value += (subnet.size * i)
            subnet.prefixlen = prefixlen
            i += 1
            yield subnet

    def iter_hosts(self):
        """
        An generator that provides all the IP addresses that can be assigned
        to hosts within the range of this IP object's subnet.

        - for IPv4, the network and broadcast addresses are always excluded. \
          Any subnet that contains less than 4 IP addresses yields an empty list.

        - for IPv6, only the unspecified address '::' is excluded from any \
          yielded IP addresses.

        :return: an IPAddress iterator
        """
        it_hosts = iter([])

        if self.version == 4:
            #   IPv4 logic.
            if self.size >= 4:
                it_hosts = iter_iprange(IPAddress(self.first+1, self.version),
                                        IPAddress(self.last-1, self.version))
        else:
            #   IPv6 logic.
            if self.first == 0:
                if self.size != 1:
                    #   Don't return '::'.
                    it_hosts = iter_iprange(
                        IPAddress(self.first+1, self.version),
                        IPAddress(self.last, self.version))
            else:
                it_hosts = iter(self)

        return it_hosts

    def __str__(self):
        """:return: this IPNetwork in CIDR format"""
        addr = self._module.int_to_str(self._value)
        return "%s/%s" % (addr, self.prefixlen)

    def __repr__(self):
        """:return: Python statement to create an equivalent object"""
        return "%s('%s')" % (self.__class__.__name__, self)

#-----------------------------------------------------------------------------
class IPRange(BaseIP, IPListMixin):
    """
    An arbitrary IPv4 or IPv6 address range.

    Formed from a lower and upper bound IP address. The upper bound IP cannot
    be numerically smaller than the lower bound and the IP version of both
    must match.

    """
    __slots__ = ('_start', '_end')

    def __init__(self, start, end, flags=0):
        """
        Constructor.

        :param start: an IPv4 or IPv6 address that forms the lower
            boundary of this IP range.

        :param end: an IPv4 or IPv6 address that forms the upper
            boundary of this IP range.

        :param flags: (optional) decides which rules are applied to the
            interpretation of the start and end values. Supported constants
            are INET_PTON and ZEROFILL. See the netaddr.core docs for further
            details.

        """
        self._start = IPAddress(start, flags=flags)
        self._module = self._start._module
        self._end = IPAddress(end, self._module.version, flags=flags)
        if int(self._start) > int(self._end):
            raise AddrFormatError('lower bound IP greater than upper bound!')

    def __getstate__(self):
        """:return: Pickled state of an `IPRange` object."""
        return self._start.value, self._end.value, self._module.version

    def __setstate__(self, state):
        """
        :param state: data used to unpickle a pickled `IPRange` object.
        """
        start, end, version = state

        self._start = IPAddress(start, version)
        self._module = self._start._module
        self._end = IPAddress(end, version)

    @property
    def first(self):
        """The integer value of first IP address in this `IPRange` object."""
        return int(self._start)

    @property
    def last(self):
        """The integer value of last IP address in this `IPRange` object."""
        return int(self._end)

    def key(self):
        """
        :return: A key tuple used to uniquely identify this `IPRange`.
        """
        return self.version, self.first, self.last

    def sort_key(self):
        """
        :return: A key tuple used to compare and sort this `IPRange` correctly.
        """
        skey = self._module.width - num_bits(self.size)
        return self.version, self.first, skey

    def cidrs(self):
        """
        The list of CIDR addresses found within the lower and upper bound
        addresses of this `IPRange`.
        """
        return iprange_to_cidrs(self._start, self._end)

    def __str__(self):
        """:return: this `IPRange` in a common representational format."""
        return "%s-%s" % (self._start, self._end)

    def __repr__(self):
        """:return: Python statement to create an equivalent object"""
        return "%s('%s', '%s')" % (self.__class__.__name__,
            self._start, self._end)

#-----------------------------------------------------------------------------
def iter_unique_ips(*args):
    """
    :param args: A list of IP addresses and subnets passed in as arguments.

    :return: A generator that flattens out IP subnets, yielding unique
        individual IP addresses (no duplicates).
    """
    for cidr in cidr_merge(args):
        for ip in cidr:
            yield ip

#-----------------------------------------------------------------------------
def cidr_abbrev_to_verbose(abbrev_cidr):
    """
    A function that converts abbreviated IPv4 CIDRs to their more verbose
    equivalent.

    :param abbrev_cidr: an abbreviated CIDR.

    Uses the old-style classful IP address rules to decide on a default
    subnet prefix if one is not explicitly provided.

    Only supports IPv4 addresses.

    Examples ::

        10                  - 10.0.0.0/8
        10/16               - 10.0.0.0/16
        128                 - 128.0.0.0/16
        128/8               - 128.0.0.0/8
        192.168             - 192.168.0.0/16

    :return: A verbose CIDR from an abbreviated CIDR or old-style classful \
        network address, The original value if it was not recognised as a \
        supported abbreviation.
    """
    #   Internal function that returns a prefix value based on the old IPv4
    #   classful network scheme that has been superseded (almost) by CIDR.
    def classful_prefix(octet):
        octet = int(octet)
        if not 0 <= octet <= 255:
            raise IndexError('Invalid octet: %r!' % octet)
        if 0 <= octet <= 127:       #   Legacy class 'A' classification.
            return 8
        elif 128 <= octet <= 191:   #   Legacy class 'B' classification.
            return 16
        elif 192 <= octet <= 223:   #   Legacy class 'C' classification.
            return 24
        elif 224 <= octet <= 239:   #   Multicast address range.
            return 4
        return 32                   #   Default.

    start = ''
    tokens = []
    prefix = None

    if _is_str(abbrev_cidr):
        if ':' in abbrev_cidr:
            return abbrev_cidr
    try:
        #   Single octet partial integer or string address.
        i = int(abbrev_cidr)
        tokens = [str(i), '0', '0', '0']
        return "%s%s/%s" % (start, '.'.join(tokens), classful_prefix(i))

    except ValueError:
        #   Multi octet partial string address with optional prefix.
        part_addr = abbrev_cidr
        tokens = []

        if part_addr == '':
            #   Not a recognisable format.
            return abbrev_cidr

        if '/' in part_addr:
            (part_addr, prefix) = part_addr.split('/', 1)

        #   Check prefix for validity.
        if prefix is not None:
            try:
                if not 0 <= int(prefix) <= 32:
                    raise ValueError('prefixlen in address %r out of range' \
                        ' for IPv4!' % abbrev_cidr)
            except ValueError:
                return abbrev_cidr

        if '.' in part_addr:
            tokens = part_addr.split('.')
        else:
            tokens = [part_addr]

        if 1 <= len(tokens) <= 4:
            for i in range(4 - len(tokens)):
                tokens.append('0')
        else:
            #   Not a recognisable format.
            return abbrev_cidr

        if prefix is None:
            try:
                prefix = classful_prefix(tokens[0])
            except ValueError:
                return abbrev_cidr

        return "%s%s/%s" % (start, '.'.join(tokens), prefix)

    except TypeError:
        pass
    except IndexError:
        pass

    #   Not a recognisable format.
    return abbrev_cidr

#-----------------------------------------------------------------------------
def cidr_merge(ip_addrs):
    """
    A function that accepts an iterable sequence of IP addresses and subnets
    merging them into the smallest possible list of CIDRs. It merges adjacent
    subnets where possible, those contained within others and also removes
    any duplicates.

    :param ip_addrs: an iterable sequence of IP addresses and subnets.

    :return: a summarized list of `IPNetwork` objects.
    """
    if not hasattr(ip_addrs, '__iter__') or hasattr(ip_addrs, 'keys'):
        raise ValueError('A sequence or iterator is expected!')

    #   Start off using set as we'll remove any duplicates at the start.
    ipv4_bit_cidrs = set()
    ipv6_bit_cidrs = set()

    #   Convert IP addresses and subnets into their CIDR bit strings.
    ipv4_match_all_found = False
    ipv6_match_all_found = False

    for ip in ip_addrs:
        cidr = IPNetwork(ip)
        bits = cidr.network.bits(word_sep='')[0:cidr.prefixlen]

        if cidr.version == 4:
            if bits == '':
                ipv4_match_all_found = True
                ipv4_bit_cidrs = set([''])  # Clear all other IPv4 values.

            if not ipv4_match_all_found:
                ipv4_bit_cidrs.add(bits)
        else:
            if bits == '':
                ipv6_match_all_found = True
                ipv6_bit_cidrs = set([''])  # Clear all other IPv6 values.

            if not ipv6_match_all_found:
                ipv6_bit_cidrs.add(bits)

    #   Merge binary CIDR addresses where possible.
    def _reduce_bit_cidrs(cidrs):
        new_cidrs = []

        cidrs.sort()

        #   Multiple passes are required to obtain precise results.
        while 1:
            finished = True
            while (cidrs):
                if not new_cidrs:
                    new_cidrs.append(cidrs.pop(0))
                if not cidrs:
                    break
                #   lhs and rhs are same size and adjacent.
                (new_cidr, subs) = RE_CIDR_ADJACENT.subn(
                    r'\1', '%s %s' % (new_cidrs[-1], cidrs[0]))
                if subs:
                    #   merge lhs with rhs.
                    new_cidrs[-1] = new_cidr
                    cidrs.pop(0)
                    finished = False
                else:
                    #   lhs contains rhs.
                    (new_cidr, subs) = RE_CIDR_WITHIN.subn(
                        r'\1', '%s %s' % (new_cidrs[-1], cidrs[0]))
                    if subs:
                        #   keep lhs, discard rhs.
                        new_cidrs[-1] = new_cidr
                        cidrs.pop(0)
                        finished = False
                    else:
                        #   no matches - accept rhs.
                        new_cidrs.append(cidrs.pop(0))
            if finished:
                break
            else:
                #   still seeing matches, reset.
                cidrs = new_cidrs
                new_cidrs = []

        if new_cidrs == ['0', '1']:
            #   Special case where summary CIDR result is '0.0.0.0/0' or
            #   '::/0' i.e. the whole IPv4 or IPv6 address space.
            new_cidrs = ['']

        return new_cidrs

    new_cidrs = []

    def _bits_to_cidr(bits, module):
        if bits == '':
            if module.version == 4:
                return IPNetwork('0.0.0.0/0', 4)
            else:
                return IPNetwork('::/0', 6)

        if RE_VALID_CIDR_BITS.match(bits) is None:
            raise ValueError('%r is an invalid bit string!' % bits)

        num_bits = len(bits)

        if bits == '':
            return IPAddress(module.int_to_str(0), module.version)
        else:
            bits = bits + '0' * (module.width - num_bits)
            return IPNetwork((module.bits_to_int(bits), num_bits),
                version=module.version)

    #   Reduce and format lists of reduced CIDRs.
    for bits in _reduce_bit_cidrs(list(ipv4_bit_cidrs)):
        new_cidrs.append(_bits_to_cidr(bits, _ipv4))

    for bits in _reduce_bit_cidrs(list(ipv6_bit_cidrs)):
        new_cidrs.append(_bits_to_cidr(bits, _ipv6))

    return new_cidrs

#-----------------------------------------------------------------------------
def cidr_exclude(target, exclude):
    """
    Removes an exclude IP address or subnet from target IP subnet.

    :param target: the target IP address or subnet to be divided up.

    :param exclude: the IP address or subnet to be removed from target.

    :return: list of `IPNetwork` objects remaining after exclusion.
    """
    cidrs = []

    target = IPNetwork(target)
    exclude = IPNetwork(exclude)

    if exclude.last < target.first:
        #   Exclude subnet's upper bound address less than target
        #   subnet's lower bound.
        return [target.cidr]
    elif target.last < exclude.first:
        #   Exclude subnet's lower bound address greater than target
        #   subnet's upper bound.
        return [target.cidr]

    new_prefixlen = target.prefixlen + 1

    if new_prefixlen <= target._module.width:
        i_lower = target.first
        i_upper = target.first + (2 ** (target._module.width - new_prefixlen))

        lower = IPNetwork((i_lower, new_prefixlen))
        upper = IPNetwork((i_upper, new_prefixlen))

        while exclude.prefixlen >= new_prefixlen:
            if exclude in lower:
                matched = i_lower
                unmatched = i_upper
            elif exclude in upper:
                matched = i_upper
                unmatched = i_lower
            else:
                #   Exclude subnet not within target subnet.
                cidrs.append(target.cidr)
                break

            ip = IPNetwork((unmatched, new_prefixlen))

            cidrs.append(ip)

            new_prefixlen += 1

            if new_prefixlen > target._module.width:
                break

            i_lower = matched
            i_upper = matched + (2 ** (target._module.width - new_prefixlen))

            lower = IPNetwork((i_lower, new_prefixlen))
            upper = IPNetwork((i_upper, new_prefixlen))

    cidrs.sort()

    return cidrs

#-----------------------------------------------------------------------------
def spanning_cidr(ip_addrs):
    """
    Function that accepts a sequence of IP addresses and subnets returning
    a single `IPNetwork` subnet that is large enough to span the lower and
    upper bound IP addresses with a possible overlap on either end.

    :param ip_addrs: sequence of IP addresses and subnets.

    :return: a single spanning `IPNetwork` subnet.
    """
    sorted_ips = sorted(
        [IPNetwork(ip) for ip in ip_addrs])

    if not len(sorted_ips) > 1:
        raise ValueError('IP sequence must contain at least 2 elements!')

    lowest_ip = sorted_ips[0]
    highest_ip = sorted_ips[-1]

    if lowest_ip.version != highest_ip.version:
        raise TypeError('IP sequence cannot contain both IPv4 and IPv6!')

    ip = highest_ip.cidr

    while ip.prefixlen > 0:
        if highest_ip in ip and lowest_ip not in ip:
            ip.prefixlen -= 1
        else:
            break

    return ip.cidr

#-----------------------------------------------------------------------------
def iter_iprange(start, end, step=1):
    """
    A generator that produces IPAddress objects between an arbitrary start
    and stop IP address with intervals of step between them. Sequences
    produce are inclusive of boundary IPs.

    :param start: start IP address.

    :param end: end IP address.

    :param step: (optional) size of step between IP addresses. Default: 1

    :return: an iterator of one or more `IPAddress` objects.
    """
    start = IPAddress(start)
    end = IPAddress(end)

    if start.version != end.version:
        raise TypeError('start and stop IP versions do not match!')
    version = start.version

    step = int(step)
    if step == 0:
        raise ValueError('step argument cannot be zero')

    #   We don't need objects from here, just integers.
    start = int(start)
    stop = int(end)

    negative_step = False

    if step < 0:
        negative_step = True

    index = start - step
    while True:
        index += step
        if negative_step:
            if not index >= stop:
                break
        else:
            if not index <= stop:
                break
        yield IPAddress(index, version)


#-----------------------------------------------------------------------------
def iprange_to_cidrs(start, end):
    """
    A function that accepts an arbitrary start and end IP address or subnet
    and returns a list of CIDR subnets that fit exactly between the boundaries
    of the two with no overlap.

    :param start: the start IP address or subnet.

    :param end: the end IP address or subnet.

    :return: a list of one or more IP addresses and subnets.
    """
    cidr_list = []

    start = IPNetwork(start)
    end = IPNetwork(end)

    iprange = [start.first, end.last]

    #   Get spanning CIDR covering both addresses.
    cidr_span = spanning_cidr([start, end])

    if cidr_span.first == iprange[0] and cidr_span.last == iprange[-1]:
        #   Spanning CIDR matches start and end exactly.
        cidr_list = [cidr_span]
    elif cidr_span.last == iprange[-1]:
        #   Spanning CIDR matches end exactly.
        ip = IPAddress(start)
        first_int_val = int(ip)
        ip -= 1
        cidr_remainder = cidr_exclude(cidr_span, ip)

        first_found = False
        for cidr in cidr_remainder:
            if cidr.first == first_int_val:
                first_found = True
            if first_found:
                cidr_list.append(cidr)
    elif cidr_span.first == iprange[0]:
        #   Spanning CIDR matches start exactly.
        ip = IPAddress(end)
        last_int_val = int(ip)
        ip += 1
        cidr_remainder = cidr_exclude(cidr_span, ip)

        last_found = False
        for cidr in cidr_remainder:
            cidr_list.append(cidr)
            if cidr.last == last_int_val:
                break
    elif cidr_span.first <= iprange[0] and cidr_span.last >= iprange[-1]:
        #   Spanning CIDR overlaps start and end.
        ip = IPAddress(start)
        first_int_val = int(ip)
        ip -= 1
        cidr_remainder = cidr_exclude(cidr_span, ip)

        #   Fix start.
        first_found = False
        for cidr in cidr_remainder:
            if cidr.first == first_int_val:
                first_found = True
            if first_found:
                cidr_list.append(cidr)

        #   Fix end.
        ip = IPAddress(end)
        last_int_val = int(ip)
        ip += 1
        cidr_remainder = cidr_exclude(cidr_list.pop(), ip)

        last_found = False
        for cidr in cidr_remainder:
            cidr_list.append(cidr)
            if cidr.last == last_int_val:
                break

    return cidr_list

#-----------------------------------------------------------------------------
def smallest_matching_cidr(ip, cidrs):
    """
    Matches an IP address or subnet against a given sequence of IP addresses
    and subnets.

    :param ip: a single IP address or subnet.

    :param cidrs: a sequence of IP addresses and/or subnets.

    :return: the smallest (most specific) matching IPAddress or IPNetwork
        object from the provided sequence, None if there was no match.
    """
    match = None

    if not hasattr(cidrs, '__iter__'):
        raise TypeError('IP address/subnet sequence expected, not %r!'
            % cidrs)

    ip = IPAddress(ip)
    for cidr in sorted([IPNetwork(cidr) for cidr in cidrs]):
        if ip in cidr:
            match = cidr
        else:
            if match is not None and cidr.network not in match:
                break

    return match

#-----------------------------------------------------------------------------
def largest_matching_cidr(ip, cidrs):
    """
    Matches an IP address or subnet against a given sequence of IP addresses
    and subnets.

    :param ip: a single IP address or subnet.

    :param cidrs: a sequence of IP addresses and/or subnets.

    :return: the largest (least specific) matching IPAddress or IPNetwork
        object from the provided sequence, None if there was no match.
    """
    match = None

    if not hasattr(cidrs, '__iter__'):
        raise TypeError('IP address/subnet sequence expected, not %r!'
            % cidrs)

    ip = IPAddress(ip)
    for cidr in sorted([IPNetwork(cidr) for cidr in cidrs]):
        if ip in cidr:
            match = cidr
            break

    return match

#-----------------------------------------------------------------------------
def all_matching_cidrs(ip, cidrs):
    """
    Matches an IP address or subnet against a given sequence of IP addresses
    and subnets.

    :param ip: a single IP address.

    :param cidrs: a sequence of IP addresses and/or subnets.

    :return: all matching IPAddress and/or IPNetwork objects from the provided
        sequence, an empty list if there was no match.
    """
    matches = []

    if not hasattr(cidrs, '__iter__'):
        raise TypeError('IP address/subnet sequence expected, not %r!'
            % cidrs)

    ip = IPAddress(ip)
    for cidr in sorted([IPNetwork(cidr) for cidr in cidrs]):
        if ip in cidr:
            matches.append(cidr)
        else:
            if matches and cidr.network not in matches[-1]:
                break

    return matches

#-----------------------------------------------------------------------------
#   Cached IPv4 address range lookups.
#-----------------------------------------------------------------------------
IPV4_LOOPBACK  = IPNetwork('127.0.0.0/8')

IPV4_PRIVATE = (
    IPNetwork('10.0.0.0/8'),                    #   Private-Use Networks
    IPNetwork('172.16.0.0/12'),                 #   Private-Use Networks
    IPNetwork('192.0.2.0/24'),                  #   Test-Net
    IPNetwork('192.168.0.0/16'),                #   Private-Use Networks
    IPRange('239.0.0.0', '239.255.255.255'),    #   Administrative Multicast
)

IPV4_LINK_LOCAL = IPNetwork('169.254.0.0/16')

IPV4_MULTICAST = IPNetwork('224.0.0.0/4')

IPV4_6TO4 = IPNetwork('192.88.99.0/24')    #   6to4 Relay Anycast

IPV4_RESERVED = (
    IPNetwork('128.0.0.0/16'),      #   Reserved but subject to allocation
    IPNetwork('191.255.0.0/16'),    #   Reserved but subject to allocation
    IPNetwork('192.0.0.0/24'),      #   Reserved but subject to allocation
    IPNetwork('223.255.255.0/24'),  #   Reserved but subject to allocation
    IPNetwork('240.0.0.0/4'),       #   Reserved for Future Use

    #   Reserved multicast
    IPRange('234.0.0.0', '238.255.255.255'),
    IPRange('225.0.0.0', '231.255.255.255'),
)

#-----------------------------------------------------------------------------
#   Cached IPv6 address range lookups.
#-----------------------------------------------------------------------------
IPV6_LOOPBACK = IPAddress('::1')

IPV6_PRIVATE = (
    IPNetwork('fc00::/7'),  #   Unique Local Addresses (ULA)
    IPNetwork('fec0::/10'), #   Site Local Addresses (deprecated - RFC 3879)
)

IPV6_LINK_LOCAL = IPNetwork('fe80::/10')

IPV6_MULTICAST = IPNetwork('ff00::/8')

IPV6_RESERVED = (
    IPNetwork('ff00::/12'), IPNetwork('::/8'),
    IPNetwork('0100::/8'), IPNetwork('0200::/7'),
    IPNetwork('0400::/6'), IPNetwork('0800::/5'),
    IPNetwork('1000::/4'), IPNetwork('4000::/3'),
    IPNetwork('6000::/3'), IPNetwork('8000::/3'),
    IPNetwork('A000::/3'), IPNetwork('C000::/3'),
    IPNetwork('E000::/4'), IPNetwork('F000::/5'),
    IPNetwork('F800::/6'), IPNetwork('FE00::/9'),
)
