include config.mk

# make sure pushd/popd will be available
SHELL := /bin/bash

ENV_PYTHON = $(AUTHPROXY_BUILD_ENV)/usr/local/bin/python3
PYTHONPATH = $(AUTHPROXY_BUILD_ENV)/usr/local/lib/python3.8.0

# The build directory for the FIPS object module. This
# env var is used implicitly when building FIPS and OpenSSL.
export FIPSDIR=$(AUTHPROXY_BUILD_ENV)/fips

# The build directory OpenSSL
OPENSSL_DIST=$(AUTHPROXY_BUILD_ENV)/usr/local/openssl

PYTHON_INSTALL_TARGET = install
PYTHON_DEFAULT_TARGET = all

# Set the library path when make is running. This is to ensure that
# targets are able to find our custom openssl libraries during the
# auth proxy installation
export LD_LIBRARY_PATH=$(AUTHPROXY_BUILD_ENV)/usr/local/openssl/lib

.PHONY: all dist proxy python rebuild
all: dist

rebuild: clean all

fips $(FIPS_ARTIFACTS):
	pushd $(OPENSSLFIPS) && \
	$(MAKE) -f Makefile.duo all && \
	$(MAKE) -f Makefile.duo install && \
	popd

openssl $(OPENSSL_ARTIFACTS): $(FIPS_ARTIFACTS)
	pushd $(OPENSSL) && \
	INSTALL_DIR="$(AUTHPROXY_BUILD_ENV)" $(MAKE) -f Makefile.duo all && \
	$(MAKE) -f Makefile.duo install && \
	popd

python $(PYTHON_ARTIFACTS): $(OPENSSL_ARTIFACTS)
	pushd $(PYTHON_DIR) && \
	INSTALL_DIR="$(AUTHPROXY_BUILD_ENV)" $(MAKE) -f ./Makefile.duo $(PYTHON_DEFAULT_TARGET) && \
	INSTALL_DIR="$(AUTHPROXY_BUILD_ENV)" $(MAKE) -f ./Makefile.duo $(PYTHON_INSTALL_TARGET) && \
	popd

pbr $(PBR_ARTIFACT): $(PYTHON_ARTIFACTS)
	pushd $(PBR) && \
	$(ENV_PYTHON) setup.py install && \
	popd

pycparser $(PYCPARSER_ARTIFACT): $(PYTHON_ARTIFACTS)
	pushd $(PYCPARSER) && \
	$(ENV_PYTHON) setup.py install && \
	popd

cffi $(CFFI_ARTIFACT): $(PYTHON_ARTIFACTS) $(SETUPTOOLS_ARTIFACT) $(PYCPARSER_ARTIFACT)
	pushd $(CFFI) && \
	$(ENV_PYTHON) setup.py install && \
	popd

ordereddict $(ORDEREDDICT_ARTIFACT):$(PYTHON_ARTIFACTS)
	pushd $(ORDEREDDICT) && \
	$(ENV_PYTHON) setup.py install && \
	popd

ipaddress $(IPADDRESS_ARTIFACT): $(PYTHON_ARTIFACTS)
	pushd $(IPADDRESS) && \
	$(ENV_PYTHON) setup.py install && \
	popd

setuptools $(SETUPTOOLS_ARTIFACT): $(PYTHON_ARTIFACTS)
	pushd $(SETUPTOOLS) && \
	$(ENV_PYTHON) bootstrap.py && \
	$(ENV_PYTHON) setup.py install && \
	popd

asn1crypto $(ASN1CRYPTO_ARTIFACT): $(PYTHON_ARTIFACTS)
	pushd $(ASN1CRYPTO) && \
	$(ENV_PYTHON) setup.py install && \
	popd

idna $(IDNA_ARTIFACT): $(PYTHON_ARTIFACTS)
	pushd $(IDNA) && \
	$(ENV_PYTHON) setup.py install && \
	popd

six $(SIX_ARTIFACT): $(PYTHON_ARTIFACTS)
	pushd $(SIX) && \
	$(ENV_PYTHON) setup.py install && \
	popd

duo_client_python $(DUO_CLIENT_PYTHON_ARTIFACT): $(PYTHON_ARTIFACTS) $(SIX_ARTIFACT)
	pushd $(DUO_CLIENT_PYTHON) && \
	$(ENV_PYTHON) setup.py install && \
	popd

cryptography $(CRYPTOGRAPHY_ARTIFACT): $(PYTHON_ARTIFACTS) $(CFFI_ARTIFACT) $(IPADDRESS_ARTIFACT)
cryptography $(CRYPTOGRAPHY_ARTIFACT): $(SETUPTOOLS_ARTIFACT) $(ASN1CRYPTO_ARTIFACT)
cryptography $(CRYPTOGRAPHY_ARTIFACT): $(IDNA_ARTIFACT) $(SIX_ARTIFACT) $(OPENSSL_ARTIFACTS)
cryptography $(CRYPTOGRAPHY_ARTIFACT):
	pushd $(CRYPTOGRAPHY) && \
	CFLAGS="-I$(OPENSSL_DIST)/include" \
	LDFLAGS="-L$(OPENSSL_DIST)/lib -Wl,-z,origin -Wl,-rpath,\\$$\$\ORIGIN/../../../../../../openssl/lib" \
	$(ENV_PYTHON) setup.py install && \
	popd

pyopenssl $(PYOPENSSL_ARTIFACT): $(PYTHON_ARTIFACTS) $(CRYPTOGRAPHY_ARTIFACT)
	pushd $(PYOPENSSL) && \
	$(ENV_PYTHON) setup.py build_ext build install && \
	popd

zope_interface $(ZOPE_INTERFACE_ARTIFACT): $(PYTHON_ARTIFACTS) $(SETUPTOOLS_ARTIFACT)
	pushd $(ZOPE_INTERFACE) && \
	$(ENV_PYTHON) setup.py install && \
	popd

attrs $(ATTRS_ARTIFACT): $(PYTHON_ARTIFACTS)
	pushd $(ATTRS) && \
	$(ENV_PYTHON) setup.py install && \
	popd

pyhamcrest $(PYHAMCREST_ARTIFACT): $(PYTHON_ARTIFACTS)
	pushd $(PYHAMCREST) && \
	$(ENV_PYTHON) setup.py install && \
	popd

hyperlink $(HYPERLINK_ARTIFACT): $(PYTHON_ARTIFACTS) $(IDNA_ARTIFACT)
	pushd $(HYPERLINK) && \
	$(ENV_PYTHON) setup.py install && \
	popd

docutils $(DOCUTILS_ARTIFACT): $(PYTHON_ARTIFACTS)
	pushd $(DOCUTILS) && \
	$(ENV_PYTHON) setup.py install && \
	popd

mistune $(MISTUNE_ARTIFACT): $(PYTHON_ARTIFACTS)
	pushd $(MISTUNE) && \
	$(ENV_PYTHON) setup.py install && \
	popd

m2r $(M2R_ARTIFACT): $(PYTHON_ARTIFACTS) $(DOCUTILS_ARTIFACT) $(MISTUNE_ARTIFACT)
	pushd $(M2R) && \
	$(ENV_PYTHON) setup.py install && \
	popd

setuptools_scm $(SETUPTOOLS_SCM_ARTIFACT): $(PYTHON_ARTIFACTS)
	pushd $(SETUPTOOLS_SCM) && \
	$(ENV_PYTHON) setup.py install && \
	popd

automat $(AUTOMAT_ARTIFACT): $(PYTHON_ARTIFACTS) $(SIX_ARTIFACT) $(M2R_ARTIFACT)
automat $(AUTOMAT_ARTIFACT): $(SETUPTOOLS_SCM_ARTIFACT) $(ATTRS_ARTIFACT)
automat $(AUTOMAT_ARTIFACT):
	pushd $(AUTOMAT) && \
	$(ENV_PYTHON) setup.py install && \
	popd

incremental $(INCREMENTAL_ARTIFACT): $(PYTHON_ARTIFACTS)
	pushd $(INCREMENTAL) && \
	$(ENV_PYTHON) setup.py install && \
	popd

constantly $(CONSTANTLY_ARTIFACT): $(PYTHON_ARTIFACTS)
	pushd $(CONSTANTLY) && \
	$(ENV_PYTHON) setup.py install && \
	popd

twisted $(TWISTED_ARTIFACT): $(PYTHON_ARTIFACTS) $(PYOPENSSL_ARTIFACT) $(ZOPE_INTERFACE_ARTIFACT)
twisted $(TWISTED_ARTIFACT): $(CONSTANTLY_ARTIFACT) $(INCREMENTAL_ARTIFACT) $(AUTOMAT_ARTIFACT)
twisted $(TWISTED_ARTIFACT): $(ATTRS_ARTIFACT) $(HYPERLINK_ARTIFACT) $(PYHAMCREST_ARTIFACT)
twisted $(TWISTED_ARTIFACT):
	pushd $(TWISTED) && \
	$(ENV_PYTHON) setup.py install && \
	popd

decorator $(DECORATOR_ARTIFACT): $(PYTHON_ARTIFACTS)
	pushd $(DECORATOR) && \
	$(ENV_PYTHON) setup.py install && \
	popd

dpkt $(DPKT_ARTIFACT):$(PYTHON_ARTIFACTS)
	pushd $(DPKT) && \
	$(ENV_PYTHON) setup.py install && \
	popd

pyparsing $(PYPARSING_ARTIFACT): $(PYTHON_ARTIFACTS)
	pushd $(PYPARSING) && \
	$(ENV_PYTHON) setup.py install && \
	popd

behave $(BEHAVE_ARTIFACT): $(PYTHON_ARTIFACTS) $(COLORAMA_ARTIFACT) $(TRACEBACK2_ARTIFACT)
behave $(BEHAVE_ARTIFACT): $(SIX_ARTIFACT) $(PARSE_TYPE_ARTIFACT) $(LINECACHE2_ARTIFACT)
behave $(BEHAVE_ARTIFACT):
	pushd $(BEHAVE) && \
	$(ENV_PYTHON) setup.py install && \
	popd

colorama $(COLORAMA_ARTIFACT): $(PYTHON_ARTIFACTS) $(SETUPTOOLS_ARTIFACT) $(PBR_ARTIFACT)
	pushd $(COLORAMA) && \
	$(ENV_PYTHON) setup.py install && \
	popd

traceback2 $(TRACEBACK2_ARTIFACT): $(PYTHON_ARTIFACTS) $(PBR_ARTIFACT)
	pushd $(TRACEBACK2) && \
	$(ENV_PYTHON) setup.py install && \
	popd

parse_type $(PARSE_TYPE_ARTIFACT): $(PYTHON_ARTIFACTS) $(PARSE_ARTIFACT)
	pushd $(PARSE_TYPE) && \
	$(ENV_PYTHON) setup.py install && \
	popd

parse $(PARSE_ARTIFACT): $(PYTHON_ARTIFACTS)
	pushd $(PARSE) && \
	$(ENV_PYTHON) setup.py install && \
	popd

linecache2 $(LINECACHE2_ARTIFACT): $(PYTHON_ARTIFACTS)
	pushd $(LINECACHE2) && \
	$(ENV_PYTHON) setup.py install && \
	popd

# hacked up to avoid the gettext requirement.
# it appears to only be relelvant to their webui,
# which we are not using
ldaptor $(LDAPTOR_ARTIFACT): $(PYTHON_ARTIFACTS) $(TWISTED_ARTIFACT) $(PYPARSING_ARTIFACT)
	pushd $(LDAPTOR) && \
	$(ENV_PYTHON) setup.py install && \
	popd

netaddr $(NETADDR_ARTIFACT): $(PYTHON_ARTIFACTS)
	pushd $(NETADDR) && \
	$(ENV_PYTHON) setup.py install && \
	popd

psutil $(PSUTIL_ARTIFACT): $(PYTHON_ARTIFACTS)
	pushd $(PSUTIL) && \
	$(ENV_PYTHON) setup.py install && \
	popd

pyrad $(PYRAD_ARTIFACT): $(PYTHON_ARTIFACTS) $(SIX_ARTIFACT) $(NETADDR_ARTIFACT)
	pushd $(PYRAD) && \
	$(ENV_PYTHON) setup.py install && \
	popd

twistedconnectproxy $(TWISTEDCONNECTPROXY_ARTIFACT): $(PYTHON_ARTIFACTS) $(NETADDR_ARTIFACT)
	pushd $(TWISTEDCONNECTPROXY) && \
	$(ENV_PYTHON) setup.py install && \
	popd

entrypoints $(ENTRYPOINTS_ARTIFACT): $(PYTHON_ARTIFACTS)
	pushd $(ENTRYPOINTS) && \
	$(ENV_PYTHON) setup.py install && \
	popd

mccabe $(MCCABE_ARTIFACT): $(PYTHON_ARTIFACTS) $(SETUPTOOLS_ARTIFACT)
	pushd $(MCCABE) && \
	$(ENV_PYTHON) setup.py install && \
	popd

pycodestyle $(PYCODESTYLE_ARTIFACT): $(PYTHON_ARTIFACTS)
	pushd $(PYCODESTYLE) && \
	$(ENV_PYTHON) setup.py install && \
	popd

pyflakes $(PYFLAKES_ARTIFACT): $(PYTHON_ARTIFACTS)
	pushd $(PYFLAKES) && \
	$(ENV_PYTHON) setup.py install && \
	popd

configparser $(CONFIGPARSER_ARTIFACT): $(PYTHON_ARTIFACTS)
	pushd $(CONFIGPARSER) && \
	$(ENV_PYTHON) setup.py install && \
	popd

flake8 $(FLAKE8_ARTIFACT): $(PYTHON_ARTIFACTS)
flake8 $(FLAKE8_ARTIFACT): $(MCCABE_ARTIFACT) $(PYCODESTYLE_ARTIFACT) $(PYFLAKES_ARTIFACT) $(SETUPTOOLS_ARTIFACT) $(CONFIGPARSER_ARTIFACT) $(ENTRYPOINTS_ARTIFACT)
flake8 $(FLAKE8_ARTIFACT):
	pushd $(FLAKE8) && \
	$(ENV_PYTHON) setup.py install && \
	popd

dlint $(DLINT_ARTIFACT): $(PYTHON_ARTIFACTS) $(FLAKE8_ARTIFACT)
	pushd $(DLINT) && \
	$(ENV_PYTHON) setup.py install && \
	popd

wcwidth $(WCWIDTH_ARTIFACT): $(PYTHON_ARTIFACTS)
	pushd $(WCWIDTH) && \
	$(ENV_PYTHON) setup.py install && \
	popd

pytest $(PYTEST_ARTIFACT):  $(PYTHON_ARTIFACTS) $(WCWIDTH_ARTIFACT) $(PLUGGY_ARTIFACT) $(MORE_ITERTOOLS_ARTIFACT) $(PACKAGING_ARTIFACT) $(PY_PACKAGE_ARTIFACT)
	pushd $(PYTEST) && \
	$(ENV_PYTHON) setup.py install && \
	popd

pluggy $(PLUGGY_ARTIFACT): $(PYTHON_ARTIFACTS)
	pushd $(PLUGGY) && \
	$(ENV_PYTHON) setup.py install && \
	popd

more_itertools $(MORE_ITERTOOLS_ARTIFACT): $(PYTHON_ARTIFACTS)
	pushd $(MORE_ITERTOOLS) && \
	$(ENV_PYTHON) setup.py install && \
	popd

packaging $(PACKAGING_ARTIFACT): $(PYTHON_ARTIFACTS)
	pushd $(PACKAGING) && \
	$(ENV_PYTHON) setup.py install && \
	popd

py $(PY_PACKAGE_ARTIFACT): $(PYTHON_ARTIFACTS)
	pushd $(PY_PACKAGE) && \
	$(ENV_PYTHON) setup.py install && \
	popd

drpc $(DRPC_ARTIFACT): $(PYTHON_ARTIFACTS) $(TWISTED_ARTIFACT) $(DECORATOR_ARTIFACT)
drpc $(DRPC_ARTIFACT): $(PYHAMCREST_ARTIFACT) $(ATTRS_ARTIFACT) $(CONSTANTLY_ARTIFACT)
drpc $(DRPC_ARTIFACT): $(HYPERLINK_ARTIFACT) $(INCREMENTAL_ARTIFACT) $(SIX_ARTIFACT)
drpc $(DRPC_ARTIFACT): $(ZOPE_INTERFACE_ARTIFACT) $(AUTOMAT_ARTIFACT) $(IDNA_ARTIFACT)
	pushd $(DRPC) && \
	$(ENV_PYTHON) setup.py install && \
	popd

site $(SITE_ARTIFACTS): $(PYTHON_ARTIFACTS) $(SITE_FILES)
	cp $(SITE_FILES) $(AUTHPROXY_BUILD)/usr/local/lib/python$(PY_VER_NUM)

proxy $(DUOAUTHPROXY_ARTIFACT): $(PYTHON_ARTIFACTS) $(TWISTED_ARTIFACT) $(LDAPTOR_ARTIFACT) $(DPKT_ARTIFACT)
proxy $(DUOAUTHPROXY_ARTIFACT): $(PYRAD_ARTIFACT) $(NETADDR_ARTIFACT) $(TWISTEDCONNECTPROXY_ARTIFACT)
proxy $(DUOAUTHPROXY_ARTIFACT): $(DECORATOR_ARTIFACT) $(DUO_CLIENT_PYTHON_ARTIFACT) $(PSUTIL_ARTIFACT)
proxy $(DUOAUTHPROXY_ARTIFACT): $(COLORAMA_ARTIFACT) $(DRPC_ARTIFACT)
proxy $(DUOAUTHPROXY_ARTIFACT): $(shell find $(PROXY_MODULE_DIR) -type f ! -name '*.pyc') $(SITE_ARTIFACTS)
proxy $(DUOAUTHPROXY_ARTIFACT):
	pushd $(AUTHPROXY) && \
	$(ENV_PYTHON) setup.py install && \
	popd

$(AUTHPROXY_BUILD_ENV)/conf:
	mkdir -p $(AUTHPROXY_BUILD_ENV)/conf

$(AUTHPROXY_BUILD_ENV)/log:
	mkdir -p $(AUTHPROXY_BUILD_ENV)/log

$(AUTHPROXY_BUILD_ENV)/run:
	mkdir -p $(AUTHPROXY_BUILD_ENV)/run

$(AUTHPROXY_BUILD_ENV)/bin:
	mkdir -p $(AUTHPROXY_BUILD_ENV)/bin

$(AUTHPROXY_BUILD_ENV)/doc:
	mkdir -p $(AUTHPROXY_BUILD_ENV)/doc

$(AUTHPROXY_BUILD_ENV)/usr/local/bin:
	mkdir -p $(AUTHPROXY_BUILD_ENV)/usr/local/bin

$(TAPFILE_ARTIFACT): $(AUTHPROXY)/scripts/duoauthproxy.tap | $(AUTHPROXY_BUILD_ENV)/bin
	cp $(AUTHPROXY)/scripts/duoauthproxy.tap $(TAPFILE_ARTIFACT)

$(AUTHPROXY)/build/scripts-$(PY_VER_NUM)/install: $(PYTHON_ARTIFACTS)

$(AUTHPROXY_BUILD_ENV)/install: $(AUTHPROXY)/scripts/install
	cp $(AUTHPROXY)/scripts/install $(AUTHPROXY_BUILD_ENV)/install

$(AUTHPROXY_BUILD_ENV)/doc/%: doc/% | $(AUTHPROXY_BUILD_ENV)/doc
	cp $< $@

$(AUTHPROXY_BUILD_ENV)/conf/%: conf/% | $(AUTHPROXY_BUILD_ENV)/conf
	cp $< $@

$(AUTHPROXY_BUILD_ENV)/usr/local/bin/%: scripts/% | $(AUTHPROXY_BUILD_ENV)/usr/local/bin
	cp $< $@

# the patsubst/shell combination allows for two directories to stay in sync
# between the source and build directory when combined with the above wildcard
# rules for doc/ and conf/
dist: $(DUOAUTHPROXY_ARTIFACT) $(AUTHPROXY_BUILD_ENV)/install $(TAPFILE_ARTIFACT)
dist: $(patsubst %,$(AUTHPROXY_BUILD_ENV)/%,$(shell find doc -type f))
dist: $(patsubst %,$(AUTHPROXY_BUILD_ENV)/%,$(shell find conf -type f))
dist: $(patsubst %,$(AUTHPROXY_BUILD_ENV)/usr/local/bin/%,$(SCRIPT_ARTIFACTS))
dist: | $(AUTHPROXY_BUILD_ENV)/conf $(AUTHPROXY_BUILD_ENV)/run
dist: | $(AUTHPROXY_BUILD_ENV)/bin
dist: | $(AUTHPROXY_BUILD_ENV)/log


.PHONY: clean
clean:
	- pushd $(PBR) && \
	$(ENV_PYTHON) setup.py clean -a && \
	popd

	- pushd $(PYCPARSER) && \
	$(ENV_PYTHON) setup.py clean -a && \
	popd

	- pushd $(CFFI) && \
	$(ENV_PYTHON) setup.py clean -a && \
	popd

	- pushd $(ORDEREDDICT) && \
	$(ENV_PYTHON) setup.py clean -a && \
	popd

	- pushd $(IPADDRESS) && \
	$(ENV_PYTHON) setup.py clean -a && \
	popd

	- pushd $(SETUPTOOLS) && \
	$(ENV_PYTHON) setup.py clean -a && \
	popd

	- pushd $(ASN1CRYPTO) && \
	$(ENV_PYTHON) setup.py clean -a && \
	popd

	- pushd $(IDNA) && \
	$(ENV_PYTHON) setup.py clean -a && \
	popd

	- pushd $(SIX) && \
	$(ENV_PYTHON) setup.py clean -a && \
	popd

	- pushd $(DUO_CLIENT_PYTHON) && \
	$(ENV_PYTHON) setup.py clean -a && \
	popd

	- pushd $(CRYPTOGRAPHY) && \
	$(ENV_PYTHON) setup.py clean -a && \
	popd

	- pushd $(PYOPENSSL) && \
	$(ENV_PYTHON) setup.py clean -a && \
	popd

	- pushd $(ZOPE_INTERFACE) && \
	$(ENV_PYTHON) setup.py clean -a && \
	popd

	- pushd $(ATTRS) && \
	$(ENV_PYTHON) setup.py clean -a && \
	popd

	- pushd $(PYHAMCREST) && \
	$(ENV_PYTHON) setup.py clean -a && \
	popd

	- pushd $(HYPERLINK) && \
	$(ENV_PYTHON) setup.py clean -a && \
	popd

	- pushd $(DOCUTILS) && \
	$(ENV_PYTHON) setup.py clean -a && \
	popd

	- pushd $(MISTUNE) && \
	$(ENV_PYTHON) setup.py clean -a && \
	popd

	- pushd $(M2R) && \
	$(ENV_PYTHON) setup.py clean -a && \
	popd

	- pushd $(SETUPTOOLS_SCM) && \
	$(ENV_PYTHON) setup.py clean -a && \
	popd

	- pushd $(AUTOMAT) && \
	$(ENV_PYTHON) setup.py clean -a && \
	popd

	- pushd $(INCREMENTAL) && \
	$(ENV_PYTHON) setup.py clean -a && \
	popd

	- pushd $(CONSTANTLY) && \
	$(ENV_PYTHON) setup.py clean -a && \
	popd

	- pushd $(TWISTED) && \
	$(ENV_PYTHON) setup.py clean -a && \
	popd

	- pushd $(DECORATOR) && \
	$(ENV_PYTHON) setup.py clean -a && \
	popd

	- pushd $(DPKT) && \
	$(ENV_PYTHON) setup.py clean -a && \
	popd

	- pushd $(PYPARSING) && \
	$(ENV_PYTHON) setup.py clean -a && \
	popd

	- pushd $(BEHAVE) && \
	$(ENV_PYTHON) setup.py clean -a && \
	popd

	- pushd $(COLORAMA) && \
	$(ENV_PYTHON) setup.py clean -a && \
	popd

	- pushd $(TRACEBACK2) && \
	$(ENV_PYTHON) setup.py clean -a && \
	popd

	- pushd $(PARSE_TYPE) && \
	$(ENV_PYTHON) setup.py clean -a && \
	popd

	- pushd $(PARSE) && \
	$(ENV_PYTHON) setup.py clean -a && \
	popd

	- pushd $(LINECACHE2) && \
	$(ENV_PYTHON) setup.py clean -a && \
	popd

	- pushd $(LDAPTOR) && \
	$(ENV_PYTHON) setup.py clean -a && \
	popd

	- pushd $(NETADDR) && \
	$(ENV_PYTHON) setup.py clean -a && \
	popd

	- pushd $(PSUTIL) && \
	$(ENV_PYTHON) setup.py clean -a && \
	popd

	- pushd $(PYRAD) && \
	$(ENV_PYTHON) setup.py clean -a && \
	popd

	- pushd $(ENTRYPOINTS) && \
	$(ENV_PYTHON) setup.py clean -a && \
	popd

	# twisted-connect-proxy depends on twisted
	# which isn't available if we run setup.py clean
	# just remove the build directory ourselves
	- pushd $(TWISTEDCONNECTPROXY) && \
	rm -rf build/ \
	popd

	- pushd $(AUTHPROXY) && \
	$(ENV_PYTHON) setup.py clean -a && \
	popd

	- pushd $(PYTHON_DIR) && \
	$(MAKE)  -f Makefile.duo clean && \
	popd

	- pushd $(OPENSSL) && \
	rm -rf dist && \
	$(MAKE) -f Makefile.duo clean && \
	popd

	- pushd $(OPENSSLFIPS) && \
	rm -rf dist && \
	$(MAKE) -f Makefile.duo clean && \
	popd

	- rm -rf $(AUTHPROXY_BUILD_ENV)

.PHONY: test audits dlint-audits integrations

test: dist $(PYTEST_ARTIFACT)
	pushd $(AUTHPROXY) ; \
	PYTHONPATH=$(AUTHPROXY_BUILD_ENV) $(ENV_PYTHON) -m pytest test_duoauthproxy \
		--junit-xml=reports/pytest.xml || exit 1 ; \
	PYTHONPATH=$(AUTHPROXY_BUILD_ENV) $(ENV_PYTHON) -m pytest -p test_duoauthproxy.plugins.fips \
		test_duoauthproxy --junit-xml=reports/pytest_fips.xml --junit-prefix=fips|| exit 1 ; \
	popd

audits:
	@status=0; \
	failures=""; \
	for script in test_duoauthproxy/audits/check*.py; do \
		echo "*** Running $$script"; \
		$(SYSTEM_PYTHON) ./$$script; \
		this_status=$$?; \
		if [ $$this_status -ne 0 ]; then \
			failures+=" $${script}"; \
			status=$$(($$status+1)); \
		fi; \
	done; \
	if [ $$status -eq 0 ]; then \
		echo "All audits passed!"; \
	else \
		echo "There were audit failures: $$failures"; \
	fi; \
	exit $$status

dlint-audits:
	# Copy Dlint dependencies
	cp -R ../third-party/$(ENTRYPOINTS_VER) pkgs/$(ENTRYPOINTS_VER)
	cp -R ../third-party/$(MCCABE_VER) pkgs/$(MCCABE_VER)
	cp -R ../third-party/$(PYCODESTYLE_VER) pkgs/$(PYCODESTYLE_VER)
	cp -R ../third-party/$(PYFLAKES_VER) pkgs/$(PYFLAKES_VER)
	cp -R ../third-party/$(CONFIGPARSER_VER) pkgs/$(CONFIGPARSER_VER)
	cp -R ../third-party/$(FLAKE8_VER) pkgs/$(FLAKE8_VER)
	cp -R ../third-party/$(DLINT_VER) pkgs/$(DLINT_VER)
	$(MAKE) dlint
	# Run the Dlint audits from the src directory
	cd .. && \
	$(AUTHPROXY_BUILD_ENV)/usr/local/bin/flake8 --select="DUO" duoauthproxy/

ci-unittests: $(PYTHON_ARTIFACTS)
	cp -R ../third-party/$(PY_PACKAGE_VER) pkgs/$(PY_PACKAGE_VER)
	cp -R ../third-party/$(PACKAGING_VER) pkgs/$(PACKAGING_VER)
	cp -R ../third-party/$(MORE_ITERTOOLS_VER) pkgs/$(MORE_ITERTOOLS_VER)
	cp -R ../third-party/$(PLUGGY_VER) pkgs/$(PLUGGY_VER)
	cp -R ../third-party/$(WCWIDTH_VER) pkgs/$(WCWIDTH_VER)
	cp -R ../third-party/$(PYTEST_VER) pkgs/$(PYTEST_VER)
	# These need to be one command so that the exit status of the first command
	# can be used as the exit status at the end of the subshell. Otherwise the
	# first line would fail and the rest of the command wouldn't be processed
	$(MAKE) test ;\
	TEST_EXIT_CODE=$$?;\
	cp -R pkgs/duoauthproxy/reports ../;\
	exit $$TEST_EXIT_CODE

integrations: all
	# copy over behave and dependencies. the source distribution tar has already been created
	# so its fine to add this
	cp -R ../third-party/$(BEHAVE_VER) pkgs/$(BEHAVE_VER)
	cp -R ../third-party/$(COLORAMA_VER) pkgs/$(COLORAMA_VER)
	cp -R ../third-party/$(TRACEBACK2_VER) pkgs/$(TRACEBACK2_VER)
	cp -R ../third-party/$(PARSE_TYPE_VER) pkgs/$(PARSE_TYPE_VER)
	cp -R ../third-party/$(PARSE_VER) pkgs/$(PARSE_VER)
	cp -R ../third-party/$(LINECACHE2_VER) pkgs/$(LINECACHE2_VER)
	# copy over test for integrations
	cp -R ../test_duoauthproxy pkgs/$(DUOAUTHPROXY_VER)/test_duoauthproxy
	$(MAKE) behave
	# Run the behave tests from the src directory
	cd .. && \
	$(AUTHPROXY_BUILD_ENV)/usr/local/bin/behave test_duoauthproxy/features --tags=-windows --tags=-non_batched --junit  --junit-directory ./reports
