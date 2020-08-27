RADIUS_ATTRIBUTES = """
#
# Version $Id: dictionary,v 1.1.1.1 2002/10/11 12:25:39 wichert Exp $
#
#	This file contains dictionary translations for parsing
#	requests and generating responses.  All transactions are
#	composed of Attribute/Value Pairs.  The value of each attribute
#	is specified as one of 4 data types.  Valid data types are:
#
#	string  - 0-253 octets
#	ipaddr  - 4 octets in network byte order
#	integer - 32 bit value in big endian order (high byte first)
#	date    - 32 bit value in big endian order - seconds since
#					00:00:00 GMT,  Jan.  1,  1970
#
#	FreeRADIUS includes extended data types which are not defined
#	in RFC 2865 or RFC 2866.  These data types are:
#
#	abinary - Ascend's binary filter format.
#	octets  - raw octets, printed and input as hex strings.
#		  e.g.: 0x123456789abcdef
#
#
#	Enumerated values are stored in the user file with dictionary
#	VALUE translations for easy administration.
#
#	Example:
#
#	ATTRIBUTE	  VALUE
#	---------------   -----
#	Framed-Protocol = PPP
#	7		= 1	(integer encoding)
#

#
#	Following are the proper new names. Use these.
#
ATTRIBUTE	User-Name		1	string
ATTRIBUTE	User-Password		2	octets
ATTRIBUTE	CHAP-Password		3	octets
ATTRIBUTE	NAS-IP-Address		4	ipaddr
ATTRIBUTE	NAS-Port		5	integer
ATTRIBUTE	Service-Type		6	integer
ATTRIBUTE	Framed-Protocol		7	integer
ATTRIBUTE	Framed-IP-Address	8	ipaddr
ATTRIBUTE	Framed-IP-Netmask	9	ipaddr
ATTRIBUTE	Framed-Routing		10	integer
ATTRIBUTE	Filter-Id		11	string
ATTRIBUTE	Framed-MTU		12	integer
ATTRIBUTE	Framed-Compression	13	integer
ATTRIBUTE	Login-IP-Host		14	ipaddr
ATTRIBUTE	Login-Service		15	integer
ATTRIBUTE	Login-TCP-Port		16	integer
ATTRIBUTE	Reply-Message		18	string
ATTRIBUTE	Callback-Number		19	string
ATTRIBUTE	Callback-Id		20	string
ATTRIBUTE	Framed-Route		22	string
ATTRIBUTE	Framed-IPX-Network	23	ipaddr
ATTRIBUTE	State			24	octets
ATTRIBUTE	Class			25	octets
ATTRIBUTE	Vendor-Specific		26	octets
ATTRIBUTE	Session-Timeout		27	integer
ATTRIBUTE	Idle-Timeout		28	integer
ATTRIBUTE	Termination-Action	29	integer
ATTRIBUTE	Called-Station-Id	30	string
ATTRIBUTE	Calling-Station-Id	31	string
ATTRIBUTE	NAS-Identifier		32	string
ATTRIBUTE	Proxy-State		33	octets
ATTRIBUTE	Login-LAT-Service	34	string
ATTRIBUTE	Login-LAT-Node		35	string
ATTRIBUTE	Login-LAT-Group		36	octets
ATTRIBUTE	Framed-AppleTalk-Link	37	integer
ATTRIBUTE	Framed-AppleTalk-Network 38	integer
ATTRIBUTE	Framed-AppleTalk-Zone	39	string

ATTRIBUTE	Acct-Status-Type	40	integer
ATTRIBUTE	Acct-Delay-Time		41	integer
ATTRIBUTE	Acct-Input-Octets	42	integer
ATTRIBUTE	Acct-Output-Octets	43	integer
ATTRIBUTE	Acct-Session-Id		44	string
ATTRIBUTE	Acct-Authentic		45	integer
ATTRIBUTE	Acct-Session-Time	46	integer
ATTRIBUTE       Acct-Input-Packets	47	integer
ATTRIBUTE       Acct-Output-Packets	48	integer
ATTRIBUTE	Acct-Terminate-Cause	49	integer
ATTRIBUTE	Acct-Multi-Session-Id	50	string
ATTRIBUTE	Acct-Link-Count		51	integer
ATTRIBUTE	Acct-Input-Gigawords    52      integer
ATTRIBUTE	Acct-Output-Gigawords   53      integer
ATTRIBUTE	Event-Timestamp         55      date

ATTRIBUTE	CHAP-Challenge		60	string
ATTRIBUTE	NAS-Port-Type		61	integer
ATTRIBUTE	Port-Limit		62	integer
ATTRIBUTE	Login-LAT-Port		63	integer

ATTRIBUTE	Tunnel-Client-Endpoint	66	string

ATTRIBUTE	Acct-Tunnel-Connection	68	string

ATTRIBUTE	ARAP-Password           70      string
ATTRIBUTE	ARAP-Features           71      string
ATTRIBUTE	ARAP-Zone-Access        72      integer
ATTRIBUTE	ARAP-Security           73      integer
ATTRIBUTE	ARAP-Security-Data      74      string
ATTRIBUTE	Password-Retry          75      integer
ATTRIBUTE	Prompt                  76      integer
ATTRIBUTE	Connect-Info		77	string
ATTRIBUTE	Configuration-Token	78	string
ATTRIBUTE	EAP-Message		79	octets
ATTRIBUTE	Message-Authenticator	80	octets
ATTRIBUTE	ARAP-Challenge-Response	84	string	# 10 octets
ATTRIBUTE	Acct-Interim-Interval   85      integer
ATTRIBUTE	NAS-Port-Id		87	string
ATTRIBUTE	Framed-Pool		88	string
ATTRIBUTE	NAS-IPv6-Address	95	octets	# really IPv6
ATTRIBUTE	Framed-Interface-Id	96	octets	# 8 octets
ATTRIBUTE	Framed-IPv6-Prefix	97	octets	# stupid format
ATTRIBUTE	Login-IPv6-Host		98	octets	# really IPv6
ATTRIBUTE	Framed-IPv6-Route	99	string
ATTRIBUTE	Framed-IPv6-Pool	100	string

ATTRIBUTE	Digest-Response		206	string
ATTRIBUTE	Digest-Attributes	207	octets	# stupid format

#
#	Experimental Non Protocol Attributes used by Cistron-Radiusd
#

# 	These attributes CAN go in the reply item list.
ATTRIBUTE	Fall-Through		500	integer
ATTRIBUTE	Exec-Program		502	string
ATTRIBUTE	Exec-Program-Wait	503	string

#	These attributes CANNOT go in the reply item list.
ATTRIBUTE	User-Category		1029	string
ATTRIBUTE	Group-Name		1030	string
ATTRIBUTE	Huntgroup-Name		1031	string
ATTRIBUTE	Simultaneous-Use	1034	integer
ATTRIBUTE	Strip-User-Name		1035	integer
ATTRIBUTE	Hint			1040	string
ATTRIBUTE	Pam-Auth		1041	string
ATTRIBUTE	Login-Time		1042	string
ATTRIBUTE	Stripped-User-Name	1043	string
ATTRIBUTE	Current-Time		1044	string
ATTRIBUTE	Realm			1045	string
ATTRIBUTE	No-Such-Attribute	1046	string
ATTRIBUTE	Packet-Type		1047	integer
ATTRIBUTE	Proxy-To-Realm		1048	string
ATTRIBUTE	Replicate-To-Realm	1049	string
ATTRIBUTE	Acct-Session-Start-Time	1050	date
ATTRIBUTE	Acct-Unique-Session-Id  1051	string
ATTRIBUTE	Client-IP-Address	1052	ipaddr
ATTRIBUTE	Ldap-UserDn		1053	string
ATTRIBUTE	NS-MTA-MD5-Password	1054	string
ATTRIBUTE	SQL-User-Name	 	1055	string
ATTRIBUTE	LM-Password		1057	octets
ATTRIBUTE	NT-Password		1058	octets
ATTRIBUTE	SMB-Account-CTRL	1059	integer
ATTRIBUTE	SMB-Account-CTRL-TEXT	1061	string
ATTRIBUTE	User-Profile		1062	string
ATTRIBUTE	Digest-Realm		1063	string
ATTRIBUTE	Digest-Nonce		1064	string
ATTRIBUTE	Digest-Method		1065	string
ATTRIBUTE	Digest-URI		1066	string
ATTRIBUTE	Digest-QOP		1067	string
ATTRIBUTE	Digest-Algorithm	1068	string
ATTRIBUTE	Digest-Body-Digest	1069	string
ATTRIBUTE	Digest-CNonce		1070	string
ATTRIBUTE	Digest-Nonce-Count	1071	string
ATTRIBUTE	Digest-User-Name	1072	string
ATTRIBUTE	Pool-Name		1073	string
ATTRIBUTE	Ldap-Group		1074	string
ATTRIBUTE	Module-Success-Message	1075	string
ATTRIBUTE	Module-Failure-Message	1076	string
#		X99-Fast		1077	integer

#
#	Non-Protocol Attributes
#	These attributes are used internally by the server
#
ATTRIBUTE	Auth-Type		1000	integer
ATTRIBUTE	Menu			1001	string
ATTRIBUTE	Termination-Menu	1002	string
ATTRIBUTE	Prefix			1003	string
ATTRIBUTE	Suffix			1004	string
ATTRIBUTE	Group			1005	string
ATTRIBUTE	Crypt-Password		1006	string
ATTRIBUTE	Connect-Rate		1007	integer
ATTRIBUTE	Add-Prefix		1008	string
ATTRIBUTE	Add-Suffix		1009	string
ATTRIBUTE	Expiration		1010	date
ATTRIBUTE	Autz-Type		1011	integer

VENDOR		Cisco				9

#
#	Standard attribute
#
BEGIN-VENDOR	Cisco

ATTRIBUTE	Cisco-AVPair				1	string
ATTRIBUTE	Cisco-NAS-Port				2	string

#
#  T.37 Store-and-Forward attributes.
#
ATTRIBUTE	Cisco-Fax-Account-Id-Origin		3	string
ATTRIBUTE	Cisco-Fax-Msg-Id			4	string
ATTRIBUTE	Cisco-Fax-Pages				5	string
ATTRIBUTE	Cisco-Fax-Coverpage-Flag		6	string
ATTRIBUTE	Cisco-Fax-Modem-Time			7	string
ATTRIBUTE	Cisco-Fax-Connect-Speed			8	string
ATTRIBUTE	Cisco-Fax-Recipient-Count		9	string
ATTRIBUTE	Cisco-Fax-Process-Abort-Flag		10	string
ATTRIBUTE	Cisco-Fax-Dsn-Address			11	string
ATTRIBUTE	Cisco-Fax-Dsn-Flag			12	string
ATTRIBUTE	Cisco-Fax-Mdn-Address			13	string
ATTRIBUTE	Cisco-Fax-Mdn-Flag			14	string
ATTRIBUTE	Cisco-Fax-Auth-Status			15	string
ATTRIBUTE	Cisco-Email-Server-Address		16	string
ATTRIBUTE	Cisco-Email-Server-Ack-Flag		17	string
ATTRIBUTE	Cisco-Gateway-Id			18	string
ATTRIBUTE	Cisco-Call-Type				19	string
ATTRIBUTE	Cisco-Port-Used				20	string
ATTRIBUTE	Cisco-Abort-Cause			21	string

#
#  Voice over IP attributes.
#
ATTRIBUTE	h323-remote-address			23	string
ATTRIBUTE	h323-conf-id				24	string
ATTRIBUTE	h323-setup-time				25	string
ATTRIBUTE	h323-call-origin			26	string
ATTRIBUTE	h323-call-type				27	string
ATTRIBUTE	h323-connect-time			28	string
ATTRIBUTE	h323-disconnect-time			29	string
ATTRIBUTE	h323-disconnect-cause			30	string
ATTRIBUTE	h323-voice-quality			31	string
ATTRIBUTE	h323-gw-id				33	string
ATTRIBUTE	h323-incoming-conf-id			35	string

ATTRIBUTE	Cisco-Policy-Up				37	string
ATTRIBUTE	Cisco-Policy-Down			38	string

ATTRIBUTE	sip-conf-id				100	string
ATTRIBUTE	h323-credit-amount			101	string
ATTRIBUTE	h323-credit-time			102	string
ATTRIBUTE	h323-return-code			103	string
ATTRIBUTE	h323-prompt-id				104	string
ATTRIBUTE	h323-time-and-day			105	string
ATTRIBUTE	h323-redirect-number			106	string
ATTRIBUTE	h323-preferred-lang			107	string
ATTRIBUTE	h323-redirect-ip-address		108	string
ATTRIBUTE	h323-billing-model			109	string
ATTRIBUTE	h323-currency				110	string
ATTRIBUTE	subscriber				111	string
ATTRIBUTE	gw-rxd-cdn				112	string
ATTRIBUTE	gw-final-xlated-cdn			113	string
ATTRIBUTE	remote-media-address			114	string
ATTRIBUTE	release-source				115	string
ATTRIBUTE	gw-rxd-cgn				116	string
ATTRIBUTE	gw-final-xlated-cgn			117	string

# SIP Attributes
ATTRIBUTE	call-id					141	string
ATTRIBUTE	session-protocol			142	string
ATTRIBUTE	method					143	string
ATTRIBUTE	prev-hop-via				144	string
ATTRIBUTE	prev-hop-ip				145	string
ATTRIBUTE	incoming-req-uri			146	string
ATTRIBUTE	outgoing-req-uri			147	string
ATTRIBUTE	next-hop-ip				148	string
ATTRIBUTE	next-hop-dn				149	string
ATTRIBUTE	sip-hdr					150	string

#
#	Extra attributes sent by the Cisco, if you configure
#	"radius-server vsa accounting" (requires IOS11.2+).
#
#	According to
#
#		http://www.cisco.com/en/US/products/hw/iad/ps4349/products_installation_guide_chapter09186a008007e511.html
#
#	the first byte Command-Code value is a binary command code
#	and the other bytes after it are an string argument to the
#	command:
#
#		Command code	Command			Argument
#
#		\001		Account Logon		Account name
#		\002		Account Logoff		Account name
#		\004		Account PING		Service name
#		\013		Service Logon		Service name
#		\014		Service Logoff		Service name
#		\016		Service Access Order	DNS server search order
#							separated by semicolons
#		\017		Service Message		Message text
#
ATTRIBUTE	Cisco-Multilink-ID			187	integer
ATTRIBUTE	Cisco-Num-In-Multilink			188	integer
ATTRIBUTE	Cisco-Pre-Input-Octets			190	integer
ATTRIBUTE	Cisco-Pre-Output-Octets			191	integer
ATTRIBUTE	Cisco-Pre-Input-Packets			192	integer
ATTRIBUTE	Cisco-Pre-Output-Packets		193	integer
ATTRIBUTE	Cisco-Maximum-Time			194	integer
ATTRIBUTE	Cisco-Disconnect-Cause			195	integer
ATTRIBUTE	Cisco-Data-Rate				197	integer
ATTRIBUTE	Cisco-PreSession-Time			198	integer
ATTRIBUTE	Cisco-PW-Lifetime			208	integer
ATTRIBUTE	Cisco-IP-Direct				209	integer
ATTRIBUTE	Cisco-PPP-VJ-Slot-Comp			210	integer
ATTRIBUTE	Cisco-PPP-Async-Map			212	integer
ATTRIBUTE	Cisco-IP-Pool-Definition		217	string
ATTRIBUTE	Cisco-Assign-IP-Pool			218	integer
ATTRIBUTE	Cisco-Route-IP				228	integer
ATTRIBUTE	Cisco-Link-Compression			233	integer
ATTRIBUTE	Cisco-Target-Util			234	integer
ATTRIBUTE	Cisco-Maximum-Channels			235	integer
ATTRIBUTE	Cisco-Data-Filter			242	integer
ATTRIBUTE	Cisco-Call-Filter			243	integer
ATTRIBUTE	Cisco-Idle-Limit			244	integer
ATTRIBUTE	Cisco-Subscriber-Password		249	string
ATTRIBUTE	Cisco-Account-Info			250	string
ATTRIBUTE	Cisco-Service-Info			251	string
ATTRIBUTE	Cisco-Command-Code			252	string
ATTRIBUTE	Cisco-Control-Info			253	string
ATTRIBUTE	Cisco-Xmit-Rate				255	integer

END-VENDOR	Cisco

VENDOR		Juniper				2636

BEGIN-VENDOR	Juniper

ATTRIBUTE	Juniper-Local-User-Name			1	string
ATTRIBUTE	Juniper-Allow-Commands			2	string
ATTRIBUTE	Juniper-Deny-Commands			3	string
ATTRIBUTE	Juniper-Allow-Configuration		4	string
ATTRIBUTE	Juniper-Deny-Configuration		5	string
ATTRIBUTE	Juniper-Interactive-Command		8	string
ATTRIBUTE	Juniper-Configuration-Change		9	string
ATTRIBUTE	Juniper-User-Permissions		10	string

END-VENDOR	Juniper

VENDOR		Microsoft			311

BEGIN-VENDOR	Microsoft
ATTRIBUTE	MS-CHAP-Response			1	octets
ATTRIBUTE	MS-CHAP-Error				2	octets
ATTRIBUTE	MS-CHAP-CPW-1				3	octets
ATTRIBUTE	MS-CHAP-CPW-2				4	octets
ATTRIBUTE	MS-CHAP-LM-Enc-PW			5	octets
ATTRIBUTE	MS-CHAP-NT-Enc-PW			6	octets
##ATTRIBUTE	MS-MPPE-Encryption-Policy		7	octets  ##[wireshark]
ATTRIBUTE	MS-MPPE-Encryption-Policy		7	integer ##[wireshark]
# This is referred to as both singular and plural in the RFC.
# Plural seems to make more sense.
##ATTRIBUTE	MS-MPPE-Encryption-Type			8	octets  ##[wireshark]
##ATTRIBUTE	MS-MPPE-Encryption-Types		8	octets  ##[wireshark]
ATTRIBUTE	MS-MPPE-Encryption-Type			8	integer ##[wireshark]
ATTRIBUTE	MS-MPPE-Encryption-Types		8	integer ##[wireshark]
ATTRIBUTE	MS-RAS-Vendor				9	integer	# content is Vendor-ID
ATTRIBUTE	MS-CHAP-Domain				10	octets
ATTRIBUTE	MS-CHAP-Challenge			11	octets
ATTRIBUTE	MS-CHAP-MPPE-Keys			12	octets
ATTRIBUTE	MS-BAP-Usage				13	integer
ATTRIBUTE	MS-Link-Utilization-Threshold		14	integer # values are 1-100
ATTRIBUTE	MS-Link-Drop-Time-Limit			15	integer
ATTRIBUTE	MS-MPPE-Send-Key			16	octets
ATTRIBUTE	MS-MPPE-Recv-Key			17	octets
ATTRIBUTE	MS-RAS-Version				18	string
ATTRIBUTE	MS-Old-ARAP-Password			19	octets
ATTRIBUTE	MS-New-ARAP-Password			20	octets
ATTRIBUTE	MS-ARAP-PW-Change-Reason		21	integer

ATTRIBUTE	MS-Filter				22	octets
ATTRIBUTE	MS-Acct-Auth-Type			23	integer
ATTRIBUTE	MS-Acct-EAP-Type			24	integer

ATTRIBUTE	MS-CHAP2-Response			25	octets
ATTRIBUTE	MS-CHAP2-Success			26	octets
ATTRIBUTE	MS-CHAP2-CPW				27	octets

ATTRIBUTE	MS-Primary-DNS-Server			28	ipaddr
ATTRIBUTE	MS-Secondary-DNS-Server			29	ipaddr
ATTRIBUTE	MS-Primary-NBNS-Server			30	ipaddr
ATTRIBUTE	MS-Secondary-NBNS-Server		31	ipaddr

#ATTRIBUTE	MS-ARAP-Challenge	33	octets

## MS-RNAP
#
# http://download.microsoft.com/download/9/5/E/95EF66AF-9026-4BB0-A41D-A4F81802D92C/%5BMS-RNAP%5D.pdf

ATTRIBUTE	MS-RAS-Client-Name			34	string
ATTRIBUTE	MS-RAS-Client-Version			35	string
ATTRIBUTE	MS-Quarantine-IPFilter			36	octets
ATTRIBUTE	MS-Quarantine-Session-Timeout		37	integer
ATTRIBUTE	MS-User-Security-Identity		40	string
ATTRIBUTE	MS-Identity-Type			41	integer
ATTRIBUTE	MS-Service-Class			42	string
ATTRIBUTE	MS-Quarantine-User-Class		44	string
ATTRIBUTE	MS-Quarantine-State			45	integer
ATTRIBUTE	MS-Quarantine-Grace-Time		46	integer
ATTRIBUTE	MS-Network-Access-Server-Type		47	integer
ATTRIBUTE	MS-AFW-Zone				48	integer

ATTRIBUTE	MS-AFW-Protection-Level			49	integer

ATTRIBUTE	MS-Machine-Name				50	string
ATTRIBUTE	MS-IPv6-Filter				51	octets
ATTRIBUTE	MS-IPv4-Remediation-Servers		52	octets
ATTRIBUTE	MS-IPv6-Remediation-Servers		53	octets
ATTRIBUTE	MS-RNAP-Not-Quarantine-Capable		54	integer

ATTRIBUTE	MS-Quarantine-SOH			55	octets
ATTRIBUTE	MS-RAS-Correlation			56	octets

#  Or this might be 56?
ATTRIBUTE	MS-Extended-Quarantine-State		57	integer

ATTRIBUTE	MS-HCAP-User-Groups			58	string
ATTRIBUTE	MS-HCAP-Location-Group-Name		59	string
ATTRIBUTE	MS-HCAP-User-Name			60	string
ATTRIBUTE	MS-User-IPv4-Address			61	ipaddr
ATTRIBUTE	MS-User-IPv6-Address			62	ipv6addr
ATTRIBUTE	MS-TSG-Device-Redirection		63	integer

END-VENDOR Microsoft
#
#
#  dictionary.paloalto
#
#
VENDOR          PaloAlto                        25461

BEGIN-VENDOR    PaloAlto

ATTRIBUTE       PaloAlto-Admin-Role                         1   string
# PaloAlto-Admin-Role is the name of the role for the user
# it can be the name of a custom Admin role profile configured on the
# PAN device or one of the following predefined roles
# superuser : Superuser
# superreader : Superuser (read-only)
# deviceadmin : Device administrator
# devicereader : Device administrator (read-only)
# vsysadmin : Virtual system administrator
# vsysreader : Virtual system administrator (read-only)

ATTRIBUTE       PaloAlto-Admin-Access-Domain            2       string
# PaloAlto-Admin-Access-Domain is the name of the access domain object defined
# on the PAN device

ATTRIBUTE       PaloAlto-Panorama-Admin-Role            3       string
# PaloAlto-Panorama-Admin-Role is the name of the role for the user
# it can be the name of a custom Admin role profile configured on the
# Panorama server or one of the following predefined roles
# superuser : Superuser
# superreader : Superuser (read-only)
# panorama-admin : Panorama administrator

ATTRIBUTE       PaloAlto-Panorama-Admin-Access-Domain   4       string
# PaloAlto-Panorama-Admin-Access-Domain is the name of the access domain
# object defined on the Panorama server

ATTRIBUTE       PaloAlto-User-Group         5   string
# PaloAlto-User-Group is the name of the group of users

ATTRIBUTE       PaloAlto-User-Domain        6   string
# PaloAlto-User-Domain is the name of the user domain

ATTRIBUTE       PaloAlto-Client-Source-IP   7       string
# PaloAlto-Client-Source-IP is the source IP address of the computer
# on which GlobalProtect client is used to log in

ATTRIBUTE       PaloAlto-Client-OS   8       string
# PaloAlto-Client-OS is the operating system (OS) of the computer
# on which GlobalProtect client is used to log in

ATTRIBUTE       PaloAlto-Client-Hostname   9       string
# PaloAlto-Client-Hostname is the hostname of the computer
# on which the user logs in

ATTRIBUTE       PaloAlto-GlobalProtect-Client-Version  10       string
# PaloAlto-GlobalProtect-Client-Version is the version of GlobalProtect
# client which is used to log in

END-VENDOR PaloAlto
"""
