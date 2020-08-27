# module versions
DUOAUTHPROXY_VER = duoauthproxy
PYTHON_VER = Python-3.8.4
LDAPTOR_VER = ldaptor-19.1.0
CRYPTOGRAPHY_VER = cryptography-2.7
PYPARSING_VER = pyparsing-2.4.2
DECORATOR_VER = decorator-4.4.1
DPKT_VER = dpkt-1.9.2
NETADDR_VER = netaddr-0.7.10
PYOPENSSL_VER = pyOpenSSL-17.5.0
PYRAD_VER = pyrad-2.2
SIX_VER = six-1.11.0
TWISTED_VER = Twisted-19.2.1
TWISTEDCONNECTPROXY_VER = twisted_connect_proxy-1.0.0
ZOPE_INTERFACE_VER = zope.interface-5.1.0
CFFI_VER = cffi-1.12.3
PYCPARSER_VER = pycparser-2.10
IPADDRESS_VER = ipaddress-1.0.17
ORDEREDDICT_VER = ordereddict-1.1
SETUPTOOLS_VER = setuptools-42.0.2
IDNA_VER = idna-2.7
ASN1CRYPTO_VER = asn1crypto-1.2.0
FUNCSIGS_VER = funcsigs-1.0.2
PBR_VER = pbr-3.1.1
DUO_CLIENT_PYTHON_VER = 4.0.0
PSUTIL_VER = psutil-5.4.3
BEHAVE_VER = behave-1.2.6
COLORAMA_VER = colorama-0.3.9
TRACEBACK2_VER = traceback2-1.4.0
PARSE_TYPE_VER = parse_type-0.4.2
PARSE_VER = parse-1.8.4
LINECACHE2_VER = linecache2-1.0.0
CONSTANTLY_VER = constantly-15.1.0
INCREMENTAL_VER = incremental-17.5.0
AUTOMAT_VER = Automat-0.7.0
HYPERLINK_VER = hyperlink-18.0.0
PYHAMCREST_VER = PyHamcrest-1.9.0
ATTRS_VER = attrs-18.1.0
M2R_VER = m2r-0.1.15
DOCUTILS_VER = docutils-0.16
MISTUNE_VER = mistune-0.8.3
SETUPTOOLS_SCM_VER = setuptools_scm-2.1.0
SITE_FILES=_fipscustomize.py sitecustomize.py
OPENSSL_VER = openssl-1.0.2o
OPENSSLFIPS_VER = openssl-fips-2.0.16
MCCABE_VER = mccabe-0.6.1
PYCODESTYLE_VER = pycodestyle-2.5.0
PYFLAKES_VER = pyflakes-2.1.1
CONFIGPARSER_VER = configparser-3.5.0
FLAKE8_VER = flake8-3.7.9
DLINT_VER = dlint-0.7.0
DRPC_VER = drpc-2.5.0
ENTRYPOINTS_VER = entrypoints-0.3
PYTEST_VER = pytest-5.3.5
WCWIDTH_VER = wcwidth-0.1.8
PLUGGY_VER = pluggy-0.13.1
MORE_ITERTOOLS_VER = more-itertools-8.2.0
PACKAGING_VER = packaging-20.1
PY_PACKAGE_VER = py-1.8.1

# required modules located in THIRD_PARTY
PYTHON_DIR = $(THIRD_PARTY)/$(PYTHON_VER)
LDAPTOR = $(THIRD_PARTY)/$(LDAPTOR_VER)
PYPARSING = $(THIRD_PARTY)/$(PYPARSING_VER)
PYRAD = $(THIRD_PARTY)/$(PYRAD_VER)
SIX = $(THIRD_PARTY)/$(SIX_VER)
PYOPENSSL = $(THIRD_PARTY)/$(PYOPENSSL_VER)
TWISTEDCONNECTPROXY = $(THIRD_PARTY)/$(TWISTEDCONNECTPROXY_VER)
TWISTED = $(THIRD_PARTY)/$(TWISTED_VER)
CRYPTOGRAPHY = $(THIRD_PARTY)/$(CRYPTOGRAPHY_VER)
CFFI = $(THIRD_PARTY)/$(CFFI_VER)
PYCPARSER = $(THIRD_PARTY)/$(PYCPARSER_VER)
IPADDRESS = $(THIRD_PARTY)/$(IPADDRESS_VER)
ORDEREDDICT = $(THIRD_PARTY)/$(ORDEREDDICT_VER)
SETUPTOOLS = $(THIRD_PARTY)/$(SETUPTOOLS_VER)
IDNA = $(THIRD_PARTY)/$(IDNA_VER)
DECORATOR = $(THIRD_PARTY)/$(DECORATOR_VER)
DPKT = $(THIRD_PARTY)/$(DPKT_VER)
ZOPE_INTERFACE = $(THIRD_PARTY)/$(ZOPE_INTERFACE_VER)
NETADDR = $(THIRD_PARTY)/$(NETADDR_VER)
ASN1CRYPTO = $(THIRD_PARTY)/$(ASN1CRYPTO_VER)
FUNCSIGS = $(THIRD_PARTY)/$(FUNCSIGS_VER)
PBR = $(THIRD_PARTY)/$(PBR_VER)
DUO_CLIENT_PYTHON = $(THIRD_PARTY)/duo_client_python-$(DUO_CLIENT_PYTHON_VER)
PSUTIL = $(THIRD_PARTY)/$(PSUTIL_VER)
BEHAVE= $(THIRD_PARTY)/$(BEHAVE_VER)
COLORAMA = $(THIRD_PARTY)/$(COLORAMA_VER)
TRACEBACK2 = $(THIRD_PARTY)/$(TRACEBACK2_VER)
PARSE_TYPE = $(THIRD_PARTY)/$(PARSE_TYPE_VER)
PARSE = $(THIRD_PARTY)/$(PARSE_VER)
LINECACHE2 = $(THIRD_PARTY)/$(LINECACHE2_VER)
CONSTANTLY = $(THIRD_PARTY)/$(CONSTANTLY_VER)
INCREMENTAL = $(THIRD_PARTY)/$(INCREMENTAL_VER)
AUTOMAT = $(THIRD_PARTY)/$(AUTOMAT_VER)
HYPERLINK = $(THIRD_PARTY)/$(HYPERLINK_VER)
PYHAMCREST = $(THIRD_PARTY)/$(PYHAMCREST_VER)
ATTRS = $(THIRD_PARTY)/$(ATTRS_VER)
M2R = $(THIRD_PARTY)/$(M2R_VER)
DOCUTILS = $(THIRD_PARTY)/$(DOCUTILS_VER)
MISTUNE = $(THIRD_PARTY)/$(MISTUNE_VER)
SETUPTOOLS_SCM = $(THIRD_PARTY)/$(SETUPTOOLS_SCM_VER)
OPENSSL=$(THIRD_PARTY)/$(OPENSSL_VER)
OPENSSLFIPS=$(THIRD_PARTY)/$(OPENSSLFIPS_VER)
MCCABE = $(THIRD_PARTY)/$(MCCABE_VER)
PYCODESTYLE = $(THIRD_PARTY)/$(PYCODESTYLE_VER)
PYFLAKES = $(THIRD_PARTY)/$(PYFLAKES_VER)
CONFIGPARSER = $(THIRD_PARTY)/$(CONFIGPARSER_VER)
FLAKE8 = $(THIRD_PARTY)/$(FLAKE8_VER)
DLINT = $(THIRD_PARTY)/$(DLINT_VER)
DRPC = $(THIRD_PARTY)/$(DRPC_VER)
ENTRYPOINTS = $(THIRD_PARTY)/$(ENTRYPOINTS_VER)
PYTEST = $(THIRD_PARTY)/$(PYTEST_VER)
WCWIDTH = $(THIRD_PARTY)/$(WCWIDTH_VER)
PLUGGY = $(THIRD_PARTY)/$(PLUGGY_VER)
MORE_ITERTOOLS = $(THIRD_PARTY)/$(MORE_ITERTOOLS_VER)
PACKAGING = $(THIRD_PARTY)/$(PACKAGING_VER)
PY_PACKAGE = $(THIRD_PARTY)/$(PY_PACKAGE_VER)

# artifacts
PYTHON_ARTIFACTS = $(AUTHPROXY_BUILD_ENV)/usr/local/bin/python3.8 $(AUTHPROXY_BUILD_ENV)/usr/local/lib/libpython3.8.a
LDAPTOR_ARTIFACT = $(AUTHPROXY_BUILD_SITE_DIR)/$(LDAPTOR_VER)-$(PY).egg
CRYPTOGRAPHY_ARTIFACT = $(AUTHPROXY_BUILD_SITE_DIR)/$(CRYPTOGRAPHY_VER)-$(PY)-linux-$(ARCH).egg
PYPARSING_ARTIFACT = $(AUTHPROXY_BUILD_SITE_DIR)/$(PYPARSING_VER)-$(PY).egg
DECORATOR_ARTIFACT = $(AUTHPROXY_BUILD_SITE_DIR)/$(DECORATOR_VER)-$(PY).egg-info
DPKT_ARTIFACT = $(AUTHPROXY_BUILD_SITE_DIR)/$(DPKT_VER)-$(PY).egg
NETADDR_ARTIFACT = $(AUTHPROXY_BUILD_SITE_DIR)/$(NETADDR_VER)-$(PY).egg-info
PYOPENSSL_ARTIFACT = $(AUTHPROXY_BUILD_SITE_DIR)/$(PYOPENSSL_VER)-$(PY).egg
PYRAD_ARTIFACT = $(AUTHPROXY_BUILD_SITE_DIR)/$(PYRAD_VER)-$(PY).egg
SIX_ARTIFACT = $(AUTHPROXY_BUILD_SITE_DIR)/$(SIX_VER)-$(PY).egg
TWISTED_ARTIFACT = $(AUTHPROXY_BUILD_SITE_DIR)/$(TWISTED_VER)-$(PY)-linux-$(ARCH).egg
TWISTEDCONNECTPROXY_ARTIFACT = $(AUTHPROXY_BUILD_SITE_DIR)/twisted_connect_proxy-1.0-$(PY).egg
ZOPE_INTERFACE_ARTIFACT = $(AUTHPROXY_BUILD_SITE_DIR)/$(ZOPE_INTERFACE_VER)-$(PY)-linux-$(ARCH).egg
CFFI_ARTIFACT = $(AUTHPROXY_BUILD_SITE_DIR)/$(CFFI_VER)-$(PY)-linux-$(ARCH).egg
PYCPARSER_ARTIFACT = $(AUTHPROXY_BUILD_SITE_DIR)/$(PYCPARSER_VER)-$(PY).egg-info
IPADDRESS_ARTIFACT = $(AUTHPROXY_BUILD_SITE_DIR)/$(IPADDRESS_VER)-$(PY).egg
ORDEREDDICT_ARTIFACT = $(AUTHPROXY_BUILD_SITE_DIR)/$(ORDEREDDICT_VER)-$(PY).egg-info
SETUPTOOLS_ARTIFACT = $(AUTHPROXY_BUILD_SITE_DIR)/$(SETUPTOOLS_VER)-$(PY).egg
IDNA_ARTIFACT = $(AUTHPROXY_BUILD_SITE_DIR)/$(IDNA_VER)-$(PY).egg
ASN1CRYPTO_ARTIFACT = $(AUTHPROXY_BUILD_SITE_DIR)/$(ASN1CRYPTO_VER)-$(PY).egg
FUNCSIGS_ARTIFACT = $(AUTHPROXY_BUILD_SITE_DIR)/$(FUNCSIGS_VER)-$(PY).egg
PBR_ARTIFACT = $(AUTHPROXY_BUILD_SITE_DIR)/$(PBR_VER)-$(PY).egg-info
DUO_CLIENT_PYTHON_ARTIFACT=$(AUTHPROXY_BUILD_SITE_DIR)/duo_client-$(DUO_CLIENT_PYTHON_VER)-$(PY).egg-info
PSUTIL_ARTIFACT = $(AUTHPROXY_BUILD_SITE_DIR)/$(PSUTIL_VER)-$(PY)-linux-$(ARCH).egg
BEHAVE_ARTIFACT = $(AUTHPROXY_BUILD_SITE_DIR)/$(BEHAVE_VER)-$(PY).egg
COLORAMA_ARTIFACT = $(AUTHPROXY_BUILD_SITE_DIR)/$(COLORAMA_VER)-$(PY).egg
TRACEBACK2_ARTIFACT = $(AUTHPROXY_BUILD_SITE_DIR)/$(TRACEBACK2_VER)-$(PY).egg-info
PARSE_TYPE_ARTIFACT = $(AUTHPROXY_BUILD_SITE_DIR)/$(PARSE_TYPE_VER)-$(PY).egg
PARSE_ARTIFACT = $(AUTHPROXY_BUILD_SITE_DIR)/$(PARSE_VER)-$(PY).egg
LINECACHE2_ARTIFACT = $(AUTHPROXY_BUILD_SITE_DIR)/$(LINECACHE2_VER)-$(PY).egg-info
CONSTANTLY_ARTIFACT = $(AUTHPROXY_BUILD_SITE_DIR)/$(CONSTANTLY_VER)-$(PY).egg
INCREMENTAL_ARTIFACT = $(AUTHPROXY_BUILD_SITE_DIR)/$(INCREMENTAL_VER)-$(PY).egg
AUTOMAT_ARTIFACT = $(AUTHPROXY_BUILD_SITE_DIR)/$(AUTOMAT_VER)-$(PY).egg
HYPERLINK_ARTIFACT = $(AUTHPROXY_BUILD_SITE_DIR)/$(HYPERLINK_VER)-$(PY).egg
PYHAMCREST_ARTIFACT = $(AUTHPROXY_BUILD_SITE_DIR)/$(PYHAMCREST_VER)-$(PY).egg
ATTRS_ARTIFACT = $(AUTHPROXY_BUILD_SITE_DIR)/$(ATTRS_VER)-$(PY).egg
M2R_ARTIFACT = $(AUTHPROXY_BUILD_SITE_DIR)/$(M2R_VER)-$(PY).egg
DOCUTILS_ARTIFACT = $(AUTHPROXY_BUILD_SITE_DIR)/$(DOCUTILS_VER)-$(PY).egg
MISTUNE_ARTIFACT = $(AUTHPROXY_BUILD_SITE_DIR)/$(MISTUNE_VER)-$(PY).egg
SETUPTOOLS_SCM_ARTIFACT = $(AUTHPROXY_BUILD_SITE_DIR)/$(SETUPTOOLS_SCM_VER)-$(PY).egg
DUOAUTHPROXY_ARTIFACT = $(AUTHPROXY_BUILD_SITE_DIR)/$(DUOAUTHPROXY_VER)-$(DUOAUTHPROXY_BUILD_VER)-$(PY).egg-info
TAPFILE_ARTIFACT = $(AUTHPROXY_BUILD_ENV)/bin/duoauthproxy.tap
SITE_ARTIFACTS = $(AUTHPROXY_BUILD)/usr/local/lib/python3.8/_fipscustomize.py $(AUTHPROXY_BUILD)/usr/local/lib/python3.8/sitecustomize.py
OPENSSL_ARTIFACTS = $(AUTHPROXY_BUILD_ENV)/usr/local/openssl/lib/libcrypto.so.1.0.0 $(AUTHPROXY_BUILD_ENV)/usr/local/openssl/lib/libssl.so.1.0.0
FIPS_ARTIFACTS = $(THIRD_PARTY)/$(OPENSSLFIPS_VER)/dist/lib/fipscanister.o $(THIRD_PARTY)/$(OPENSSLFIPS_VER)/dist/lib/fipscanister.o.sha1
SCRIPT_ARTIFACTS = authproxy authproxyctl install authproxy_connectivity_tool authproxy_primary_only authproxy_support
MCCABE_ARTIFACT = $(AUTHPROXY_BUILD_SITE_DIR)/$(MCCABE_VER)-$(PY).egg
PYCODESTYLE_ARTIFACT = $(AUTHPROXY_BUILD_SITE_DIR)/$(PYCODESTYLE_VER)-$(PY).egg
PYFLAKES_ARTIFACT = $(AUTHPROXY_BUILD_SITE_DIR)/$(PYFLAKES_VER)-$(PY).egg
CONFIGPARSER_ARTIFACT = $(AUTHPROXY_BUILD_SITE_DIR)/$(CONFIGPARSER_VER)-$(PY).egg
FLAKE8_ARTIFACT = $(AUTHPROXY_BUILD_SITE_DIR)/$(FLAKE8_VER)-$(PY).egg
DLINT_ARTIFACT = $(AUTHPROXY_BUILD_SITE_DIR)/$(DLINT_VER)-$(PY).egg
DRPC_ARTIFACT = $(AUTHPROXY_BUILD_SITE_DIR)/$(DRPC_VER)-$(PY).egg
ENTRYPOINTS_ARTIFACT = $(AUTHPROXY_BUILD_SITE_DIR)/$(ENTRYPOINTS_VER)-$(PY).egg
WCWIDTH_ARTIFACT = $(AUTHPROXY_BUILD_SITE_DIR)/$(WCWIDTH_VER)-$(PY).egg
PLUGGY_ARTIFACT = $(AUTHPROXY_BUILD_SITE_DIR)/$(PLUGGY_VER)-$(PY).egg
MORE_ITERTOOLS_ARTIFACT = $(AUTHPROXY_BUILD_SITE_DIR)/$(MORE_ITERTOOLS_VER)-$(PY).egg
PACKAGING_ARTIFACT = $(AUTHPROXY_BUILD_SITE_DIR)/$(PACKAGING_VER)-$(PY).egg
PY_PACKAGE_ARTIFACT = $(AUTHPROXY_BUILD_SITE_DIR)/$(PY_PACKAGE_VER)-$(PY).egg
PYTEST_ARTIFACT = $(AUTHPROXY_BUILD_SITE_DIR)/$(PYTEST_VER)-$(PY).egg
