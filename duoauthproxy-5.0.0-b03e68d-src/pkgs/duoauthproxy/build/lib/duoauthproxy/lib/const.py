#
# Copyright (c) 2018 Duo Security
# All Rights Reserved
#
DEFAULT_RADIUS_PORT = 1812
DEFAULT_RADIUS_RETRY_WAIT = 2
DEFAULT_HTTP_CERTS_FILE = (
    "ca-bundle.crt"  # resolves later to $AP_INSTALL_DIR/conf/ca-bundle.crt
)
DEFAULT_LDAP_PORT = 389
DEFAULT_LDAPS_PORT = 636
DEFAULT_HTTP_PORT = 80
FACTOR_CHOICES = ("auto", "phone", "push", "passcode")

DRPC_PROXY_KEY_IDENTIFIER = "proxy_key"
DRPC_API_HOST_IDENTIFIER = "api_host"
DRPC_SIGNING_SKEY_IDENTIFIER = "signing_skey"
DRPC_ENCRYPTION_SKEY_IDENTIFIER = "encryption_skey"

AD_TRANSPORT_CLEAR = "clear"
AD_TRANSPORT_LDAPS = "ldaps"
AD_TRANSPORT_STARTTLS = "starttls"
AD_TRANSPORTS_WITH_SSL = [AD_TRANSPORT_LDAPS, AD_TRANSPORT_STARTTLS]
AD_TRANSPORTS = AD_TRANSPORTS_WITH_SSL + [AD_TRANSPORT_CLEAR]

AD_AUTH_TYPE_PLAIN = "plain"
AD_AUTH_TYPE_NTLM_V1 = "ntlm1"
AD_AUTH_TYPE_NTLM_V2 = "ntlm2"
AD_AUTH_TYPE_SSPI = "sspi"
AD_AUTH_TYPES_WIN = [
    AD_AUTH_TYPE_PLAIN,
    AD_AUTH_TYPE_NTLM_V1,
    AD_AUTH_TYPE_NTLM_V2,
    AD_AUTH_TYPE_SSPI,
]
AD_AUTH_TYPES_NIX = [
    AD_AUTH_TYPE_PLAIN,
    AD_AUTH_TYPE_NTLM_V1,
    AD_AUTH_TYPE_NTLM_V2,
]

DEFAULT_SSL_VERIFY_DEPTH = 9

LDAP_SUCCESSFUL_BIND_NEEDED_ERROR = "000004DC"
