#
# Copyright (c) 2017 Duo Security
# All Rights Reserved
#
import netaddr

from duoauthproxy.lib import log


def is_valid_single_ip(ip_string):
    """Attempts to convert ip_string into binary format to test validity
    Args:
        ip_string (str): IPv4 or IPv6 address
    Returns:
        bool: True/False
    """
    try:
        if netaddr.valid_ipv4(ip_string, flags=netaddr.core.INET_PTON):
            return True
        elif netaddr.valid_ipv6(ip_string):
            return True
        return False
    except netaddr.AddrFormatError:  # empty strings will raise here
        return False


def ip_range(ip):
    """Convert ip range into netaddr object
    Args:
        ip (str): In range format 127.0.0.1-127.0.0.2
    Returns:
        List of IPNetwork
    """
    ip_start, ip_end = ip.split('-', 1)
    ip_range = netaddr.IPRange(ip_start.strip(), ip_end.strip())
    return ip_range.cidrs()


def ip_cidr(ip):
    """Convert string into netaddr object
    Args:
        ip (str): In CIDR or ip/netmask format
    Returns:
        List of IPNetwork
    """
    return [netaddr.IPNetwork(ip).cidr]


def get_ip_networks(ip):
    """Convert ip string into list of ip netaddr objects
    Args:
        ip (str): In any format
    Returns:
        List of IPNetwork objects
    """
    if '-' in ip:
        return ip_range(ip)
    else:
        return ip_cidr(ip)


def is_valid_ip(ip):
    """Checks the ip to see if it's valid in any of the 4 formats we allow
    Args:
        ip (str): Formats are single, range, cidr, and IP/netmask
    Returns:
        bool: True/False
    """
    if ip is None:
        log.msg("Invalid ip. Ip was None")
        return False
    elif '-' in ip:
        try:
            ip_range(ip)
        except Exception as e:
            log.msg("Invalid ip range: {0}. Exception: {1}".format(ip, e))
            return False
    elif '/' in ip:
        try:
            ip_cidr(ip)
        except Exception as e:
            log.msg("Invalid cidr ip: {0}. Exception: {1}".format(ip, e))
            return False
    else:
        if not is_valid_single_ip(ip):
            log.msg("Invalid single ip: {0}.".format(ip))
            return False

    log.msg("Valid ip check passed for: {0}.".format(ip))
    return True


# Duplicated in third-party/twisted-connect-proxy/connect_proxy.py, make sure to update that if this changes
def is_ip_in_networks(ip, networks):
    """
    Determine if a provided ip address is within any of the provided networks

    Args:
        ip (str) or (IPAddress): the ip to test
        networks ([IPNetwork]): the networks to check

    Returns:
        bool: True if the provided ip is within any of the provided networks; False otherwise
    """
    ip_address = netaddr.IPAddress(ip)

    return any([ip_address in network for network in networks])
