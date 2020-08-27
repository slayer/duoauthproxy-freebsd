SYSTEM_PYTHON ?= python

# basic config
AUTHPROXY_ROOT = $(shell pwd)
AUTHPROXY_BUILD = duoauthproxy-build
PY = py3.8
PY_VER_NUM = 3.8
ARCH = $(shell uname -p)

# third-party dir
THIRD_PARTY = $(AUTHPROXY_ROOT)/pkgs
AUTHPROXY_BUILD_SITE_DIR = $(AUTHPROXY_BUILD)/usr/local/lib/python$(PY_VER_NUM)/site-packages
AUTHPROXY_BUILD_ENV = $(AUTHPROXY_ROOT)/$(AUTHPROXY_BUILD)
PROXY_MODULE_DIR = $(THIRD_PARTY)/duoauthproxy

# authproxy module path
AUTHPROXY = $(AUTHPROXY_ROOT)/pkgs/$(DUOAUTHPROXY_VER)

# include package variables
include pkgs.mk
