### Generated automatically from Makefile.fips by Configure.

##
## Makefile for OpenSSL: fipscanister.o only
##

VERSION=1.1.0-dev
MAJOR=1
MINOR=1.0
SHLIB_VERSION_NUMBER=1.1.0
SHLIB_VERSION_HISTORY=
SHLIB_MAJOR=1
SHLIB_MINOR=1.0
SHLIB_EXT=.so.$(SHLIB_MAJOR).$(SHLIB_MINOR)
PLATFORM=BSD-x86_64
OPTIONS=-Wa,--noexecstack no-bf no-camellia no-cast no-ec_nistp_64_gcc_128 no-gmp no-idea no-jpake no-krb5 no-md2 no-md5 no-mdc2 no-rc2 no-rc4 no-rc5 no-rfc3779 no-ripemd no-seed no-srp no-ssl2 no-ssl3 no-store no-tls1 no-tlsext no-zlib no-zlib-dynamic no-static-engine
CONFIGURE_ARGS=BSD-x86_64 -Wa,--noexecstack no-bf no-camellia no-cast no-idea no-md2 no-md5 no-mdc2 no-rc2 no-rc4 no-rc5 no-ripemd no-seed
SHLIB_TARGET=bsd-gcc-shared

# HERE indicates where this Makefile lives.  This can be used to indicate
# where sub-Makefiles are expected to be.  Currently has very limited usage,
# and should probably not be bothered with at all.
HERE=.

# INSTALL_PREFIX is for package builders so that they can configure
# for, say, /usr/ and yet have everything installed to /tmp/somedir/usr/.
# Normally it is left empty.
INSTALL_PREFIX=
INSTALLTOP=/root/duoauthproxy-4.0.2-5b2d5d6-src/pkgs/openssl-fips-2.0.16/dist

# Do not edit this manually. Use Configure --openssldir=DIR do change this!
OPENSSLDIR=/root/duoauthproxy-4.0.2-5b2d5d6-src/pkgs/openssl-fips-2.0.16/dist

# NO_IDEA - Define to build without the IDEA algorithm
# NO_RC4  - Define to build without the RC4 algorithm
# NO_RC2  - Define to build without the RC2 algorithm
# THREADS - Define when building with threads, you will probably also need any
#           system defines as well, i.e. _REENTERANT for Solaris 2.[34]
# TERMIO  - Define the termio terminal subsystem, needed if sgtty is missing.
# TERMIOS - Define the termios terminal subsystem, Silicon Graphics.
# LONGCRYPT - Define to use HPUX 10.x's long password modification to crypt(3).
# DEVRANDOM - Give this the value of the 'random device' if your OS supports
#           one.  32 bytes will be read from this when the random
#           number generator is initalised.
# SSL_FORBID_ENULL - define if you want the server to be not able to use the
#           NULL encryption ciphers.
#
# LOCK_DEBUG - turns on lots of lock debug output :-)
# REF_CHECK - turn on some xyz_free() assertions.
# REF_PRINT - prints some stuff on structure free.
# CRYPTO_MDEBUG - turns on my 'memory leak' detecting stuff
# MFUNC - Make all Malloc/Free/Realloc calls call
#       CRYPTO_malloc/CRYPTO_free/CRYPTO_realloc which can be setup to
#       call application defined callbacks via CRYPTO_set_mem_functions()
# MD5_ASM needs to be defined to use the x86 assembler for MD5
# SHA1_ASM needs to be defined to use the x86 assembler for SHA1
# RMD160_ASM needs to be defined to use the x86 assembler for RIPEMD160
# Do not define B_ENDIAN or L_ENDIAN if 'unsigned long' == 8.  It must
# equal 4.
# PKCS1_CHECK - pkcs1 tests.

CC= gcc
CFLAG= -DOPENSSL_FIPSCANISTER -fPIC -DOPENSSL_PIC -DOPENSSL_THREADS -pthread -D_THREAD_SAFE -D_REENTRANT -DDSO_DLFCN -DHAVE_DLFCN_H -Wa,--noexecstack -DL_ENDIAN -DTERMIOS -O3 -Wall -DOPENSSL_IA32_SSE2 -DOPENSSL_BN_ASM_MONT -DOPENSSL_BN_ASM_MONT5 -DOPENSSL_BN_ASM_GF2m -DSHA1_ASM -DSHA256_ASM -DSHA512_ASM -DMD5_ASM -DAES_ASM -DWHIRLPOOL_ASM -DGHASH_ASM
DEPFLAG= -DOPENSSL_NO_BF -DOPENSSL_NO_CAMELLIA -DOPENSSL_NO_CAST -DOPENSSL_NO_EC_NISTP_64_GCC_128 -DOPENSSL_NO_GMP -DOPENSSL_NO_IDEA -DOPENSSL_NO_JPAKE -DOPENSSL_NO_MD2 -DOPENSSL_NO_MD5 -DOPENSSL_NO_MDC2 -DOPENSSL_NO_RC2 -DOPENSSL_NO_RC4 -DOPENSSL_NO_RC5 -DOPENSSL_NO_RFC3779 -DOPENSSL_NO_RIPEMD -DOPENSSL_NO_SEED -DOPENSSL_NO_SRP -DOPENSSL_NO_SSL2 -DOPENSSL_NO_SSL3 -DOPENSSL_NO_STORE -DOPENSSL_NO_TLS1 -DOPENSSL_NO_TLSEXT
PEX_LIBS= 
EX_LIBS= 
EXE_EXT= 
ARFLAGS= 
AR= ar $(ARFLAGS) r
RANLIB= /usr/bin/ranlib
NM= nm
PERL= /usr/local/bin/perl
TAR= tar
TARFLAGS= --no-recursion
MAKEDEPPROG= gcc
LIBDIR=lib

# We let the C compiler driver to take care of .s files. This is done in
# order to be excused from maintaining a separate set of architecture
# dependent assembler flags. E.g. if you throw -mcpu=ultrasparc at SPARC
# gcc, then the driver will automatically translate it to -xarch=v8plus
# and pass it down to assembler.
#AS=$(CC) -c
ASFLAG=$(CFLAG)

# For x86 assembler: Set PROCESSOR to 386 if you want to support
# the 80386.
PROCESSOR= 

# CPUID module collects small commonly used assembler snippets
CPUID_OBJ= x86_64cpuid.o
BN_ASM= x86_64-gcc.o x86_64-mont.o x86_64-mont5.o x86_64-gf2m.o 
DES_ENC= des_enc.o fcrypt_b.o
AES_ENC= aes-x86_64.o aesni-x86_64.o 
BF_ENC= bf_enc.o
CAST_ENC= c_enc.o
RC4_ENC= rc4-x86_64.o rc4-md5-x86_64.o
RC5_ENC= rc5_enc.o
MD5_ASM_OBJ= md5-x86_64.o
SHA1_ASM_OBJ= sha1-x86_64.o sha256-x86_64.o sha512-x86_64.o
RMD160_ASM_OBJ= 
WP_ASM_OBJ= wp-x86_64.o
CMLL_ENC= cmll-x86_64.o cmll_misc.o
MODES_ASM_OBJ= ghash-x86_64.o
PERLASM_SCHEME= elf

# KRB5 stuff
KRB5_INCLUDES=
LIBKRB5=

# Zlib stuff
ZLIB_INCLUDE=
LIBZLIB=

# This is the location of fipscanister.o and friends.
# The FIPS module build will place it $(INSTALLTOP)/lib
# but since $(INSTALLTOP) can only take the default value
# when the module is built it will be in /usr/local/ssl/lib
# $(INSTALLTOP) for this build may be different so hard
# code the path.

FIPSLIBDIR=

# This is set to "y" if fipscanister.o is compiled internally as
# opposed to coming from an external validated location.

FIPSCANISTERINTERNAL=y

# This is set if we only build fipscanister.o

FIPSCANISTERONLY=y

# The location of the library which contains fipscanister.o
# normally it will be libcrypto unless fipsdso is set in which
# case it will be libfips. If not compiling in FIPS mode at all
# this is empty making it a useful test for a FIPS compile.

FIPSCANLIB=libcrypto

# Shared library base address. Currently only used on Windows.
#

BASEADDR=0xFB00000

DIRS=   crypto fips test 
ENGDIRS= ccgost
SHLIBDIRS= crypto ssl

# dirs in crypto to build
SDIRS=  \
	sha hmac des aes modes \
	bn ec rsa dsa ecdsa dh \
	buffer evp ecdh cmac
# keep in mind that the above list is adjusted by ./Configure
# according to no-xxx arguments...

LINKDIRS=  \
	objects sha hmac des aes modes \
	bn ec rsa dsa ecdh cmac ecdsa dh engine \
	buffer bio stack lhash rand err \
	evp asn1 ui

# tests to perform.  "alltests" is a special word indicating that all tests
# should be performed.
TESTS = alltests

MAKEFILE= Makefile

MANDIR=$(OPENSSLDIR)/man
MAN1=1
MAN3=3
MANSUFFIX=
HTMLSUFFIX=html
HTMLDIR=$(OPENSSLDIR)/html
SHELL=/bin/sh

TOP=    .
ONEDIRS=out tmp
EDIRS=  times doc bugs util include certs ms shlib mt demos perl sf dep VMS
WDIRS=  windows
LIBS=   
SHARED_CRYPTO=libcrypto$(SHLIB_EXT)
SHARED_SSL=libssl$(SHLIB_EXT)
SHARED_LIBS=$(SHARED_CRYPTO) $(SHARED_SSL)
SHARED_LIBS_LINK_EXTS=.so.$(SHLIB_MAJOR) .so
SHARED_LDFLAGS= -Wl,-rpath,$(LIBRPATH)

GENERAL=        Makefile
BASENAME=       openssl
NAME=           $(BASENAME)-$(VERSION)
TARFILE=        openssl-fips-2.0.tar
WTARFILE=       $(NAME)-win.tar
EXHEADER=       e_os2.h
HEADER=         e_os.h

all: Makefile build_all openssl.pc libssl.pc libcrypto.pc

# as we stick to -e, CLEARENV ensures that local variables in lower
# Makefiles remain local and variable. $${VAR+VAR} is tribute to Korn
# shell, which [annoyingly enough] terminates unset with error if VAR
# is not present:-( TOP= && unset TOP is tribute to HP-UX /bin/sh,
# which terminates unset with error if no variable was present:-(
CLEARENV=	TOP= && unset TOP $${LIB+LIB} $${LIBS+LIBS}	\
		$${INCLUDE+INCLUDE} $${INCLUDES+INCLUDES}	\
		$${DIR+DIR} $${DIRS+DIRS} $${SRC+SRC}		\
		$${LIBSRC+LIBSRC} $${LIBOBJ+LIBOBJ} $${ALL+ALL}	\
		$${EXHEADER+EXHEADER} $${HEADER+HEADER}		\
		$${GENERAL+GENERAL} $${CFLAGS+CFLAGS}		\
		$${ASFLAGS+ASFLAGS} $${AFLAGS+AFLAGS}		\
		$${LDCMD+LDCMD} $${LDFLAGS+LDFLAGS}		\
		$${SHAREDCMD+SHAREDCMD} $${SHAREDFLAGS+SHAREDFLAGS}	\
		$${SHARED_LIB+SHARED_LIB} $${LIBEXTRAS+LIBEXTRAS}

BUILDENV=	PLATFORM='$(PLATFORM)' PROCESSOR='$(PROCESSOR)' \
		CC='$(CC)' CFLAG='$(CFLAG)' 			\
		ASFLAG='$(CFLAG) -c'			\
		AR='$(AR)' NM='$(NM)' RANLIB='$(RANLIB)'	\
		CROSS_COMPILE='$(CROSS_COMPILE)'	\
		PERL='$(PERL)' ENGDIRS='$(ENGDIRS)'		\
		SDIRS='$(SDIRS)' LIBRPATH='$(INSTALLTOP)/$(LIBDIR)'	\
		INSTALL_PREFIX='$(INSTALL_PREFIX)'		\
		INSTALLTOP='$(INSTALLTOP)' OPENSSLDIR='$(OPENSSLDIR)'	\
		LIBDIR='$(LIBDIR)'				\
		MAKEDEPEND='$$$${TOP}/util/domd $$$${TOP} -MD $(MAKEDEPPROG)' \
		DEPFLAG='-DOPENSSL_NO_DEPRECATED $(DEPFLAG)'	\
		MAKEDEPPROG='$(MAKEDEPPROG)'			\
		SHARED_LDFLAGS='$(SHARED_LDFLAGS)'		\
		KRB5_INCLUDES='$(KRB5_INCLUDES)' LIBKRB5='$(LIBKRB5)'	\
		ZLIB_INCLUDE='$(ZLIB_INCLUDE)' LIBZLIB='$(LIBZLIB)'	\
		EXE_EXT='$(EXE_EXT)' SHARED_LIBS='$(SHARED_LIBS)'	\
		SHLIB_EXT='$(SHLIB_EXT)' SHLIB_TARGET='$(SHLIB_TARGET)'	\
		PEX_LIBS='$(PEX_LIBS)' EX_LIBS='$(EX_LIBS)'	\
		CPUID_OBJ='$(CPUID_OBJ)'			\
		BN_ASM='$(BN_ASM)' DES_ENC='$(DES_ENC)' 	\
		AES_ENC='$(AES_ENC)' CMLL_ENC='$(CMLL_ENC)'	\
		BF_ENC='$(BF_ENC)' CAST_ENC='$(CAST_ENC)'	\
		RC4_ENC='$(RC4_ENC)' RC5_ENC='$(RC5_ENC)'	\
		SHA1_ASM_OBJ='$(SHA1_ASM_OBJ)'			\
		MD5_ASM_OBJ='$(MD5_ASM_OBJ)'			\
		RMD160_ASM_OBJ='$(RMD160_ASM_OBJ)'		\
		WP_ASM_OBJ='$(WP_ASM_OBJ)'			\
		MODES_ASM_OBJ='$(MODES_ASM_OBJ)'		\
		PERLASM_SCHEME='$(PERLASM_SCHEME)'		\
		FIPSLIBDIR='${FIPSLIBDIR}'			\
		FIPSCANLIB="$${FIPSCANLIB:-$(FIPSCANLIB)}"	\
		FIPSCANISTERINTERNAL='${FIPSCANISTERINTERNAL}'	\
		FIPSCANISTERONLY='${FIPSCANISTERONLY}'	\
		FIPS_EX_OBJ='${FIPS_EX_OBJ}'	\
		THIS=$${THIS:-$@} MAKEFILE=Makefile MAKEOVERRIDES=
# MAKEOVERRIDES= effectively "equalizes" GNU-ish and SysV-ish make flavors,
# which in turn eliminates ambiguities in variable treatment with -e.

# BUILD_CMD is a generic macro to build a given target in a given
# subdirectory.  The target must be given through the shell variable
# `target' and the subdirectory to build in must be given through `dir'.
# This macro shouldn't be used directly, use RECURSIVE_BUILD_CMD or
# BUILD_ONE_CMD instead.
#
# BUILD_ONE_CMD is a macro to build a given target in a given
# subdirectory if that subdirectory is part of $(DIRS).  It requires
# exactly the same shell variables as BUILD_CMD.
#
# RECURSIVE_BUILD_CMD is a macro to build a given target in all
# subdirectories defined in $(DIRS).  It requires that the target
# is given through the shell variable `target'.
BUILD_CMD=  if [ -d "$$dir" ]; then \
	    (	cd $$dir && echo "making $$target in $$dir..." && \
		$(CLEARENV) && $(MAKE) -e $(BUILDENV) TOP=.. DIR=$$dir $$target \
	    ) || exit 1; \
	    fi
RECURSIVE_BUILD_CMD=for dir in $(DIRS); do $(BUILD_CMD); done
BUILD_ONE_CMD=\
	if expr " $(DIRS) " : ".* $$dir " >/dev/null 2>&1; then \
		$(BUILD_CMD); \
	fi

reflect:
	@[ -n "$(THIS)" ] && $(CLEARENV) && $(MAKE) $(THIS) -e $(BUILDENV)

FIPS_EX_OBJ= ../crypto/aes/aes_cfb.o \
	../crypto/aes/aes_ecb.o \
	../crypto/aes/aes_ofb.o \
	../crypto/bn/bn_add.o \
	../crypto/bn/bn_blind.o \
	../crypto/bn/bn_ctx.o \
	../crypto/bn/bn_div.o \
	../crypto/bn/bn_exp2.o \
	../crypto/bn/bn_exp.o \
	../crypto/bn/bn_gcd.o \
	../crypto/bn/bn_gf2m.o \
	../crypto/bn/bn_lib.o \
	../crypto/bn/bn_mod.o \
	../crypto/bn/bn_mont.o \
	../crypto/bn/bn_mul.o \
	../crypto/bn/bn_nist.o \
	../crypto/bn/bn_prime.o \
	../crypto/bn/bn_rand.o \
	../crypto/bn/bn_recp.o \
	../crypto/bn/bn_shift.o \
	../crypto/bn/bn_sqr.o \
	../crypto/bn/bn_word.o \
	../crypto/bn/bn_x931p.o \
	../crypto/buffer/buf_str.o \
	../crypto/cmac/cmac.o \
	../crypto/cryptlib.o \
	../crypto/des/cfb64ede.o \
	../crypto/des/cfb64enc.o \
	../crypto/des/cfb_enc.o \
	../crypto/des/ecb3_enc.o \
	../crypto/des/ofb64ede.o \
	../crypto/des/fcrypt.o \
	../crypto/des/set_key.o \
	../crypto/dh/dh_check.o \
	../crypto/dh/dh_gen.o \
	../crypto/dh/dh_key.o \
	../crypto/dsa/dsa_gen.o \
	../crypto/dsa/dsa_key.o \
	../crypto/dsa/dsa_ossl.o \
	../crypto/ec/ec_curve.o \
	../crypto/ec/ec_cvt.o \
	../crypto/ec/ec_key.o \
	../crypto/ec/ec_lib.o \
	../crypto/ec/ecp_mont.o \
	../crypto/ec/ec_mult.o \
	../crypto/ec/ecp_nist.o \
	../crypto/ec/ecp_smpl.o \
	../crypto/ec/ec2_mult.o \
	../crypto/ec/ec2_smpl.o \
	../crypto/ecdh/ech_key.o \
	../crypto/ecdh/ech_ossl.o \
	../crypto/ecdsa/ecs_ossl.o \
	../crypto/evp/e_aes.o \
	../crypto/evp/e_des3.o \
	../crypto/evp/e_null.o \
	../crypto/evp/m_sha1.o \
	../crypto/evp/m_dss1.o \
	../crypto/evp/m_dss.o \
	../crypto/evp/m_ecdsa.o \
	../crypto/hmac/hmac.o \
	../crypto/modes/cbc128.o \
	../crypto/modes/ccm128.o \
	../crypto/modes/cfb128.o \
	../crypto/modes/ctr128.o \
	../crypto/modes/gcm128.o \
	../crypto/modes/ofb128.o \
	../crypto/modes/xts128.o \
	../crypto/rsa/rsa_eay.o \
	../crypto/rsa/rsa_gen.o \
	../crypto/rsa/rsa_crpt.o \
	../crypto/rsa/rsa_none.o \
	../crypto/rsa/rsa_oaep.o \
	../crypto/rsa/rsa_pk1.o \
	../crypto/rsa/rsa_pss.o \
	../crypto/rsa/rsa_ssl.o \
	../crypto/rsa/rsa_x931.o \
	../crypto/rsa/rsa_x931g.o \
	../crypto/sha/sha1dgst.o \
	../crypto/sha/sha256.o \
	../crypto/sha/sha512.o \
	../crypto/thr_id.o \
	../crypto/uid.o

sub_all: build_all
build_all: build_libs

build_libs: build_crypto build_fips

build_fips:
	@dir=fips; target=all; [ -z "$(FIPSCANLIB)" ] || $(BUILD_ONE_CMD)

build_crypto:
	if [ -n "$(FIPSCANLIB)" ]; then \
		EXCL_OBJ='$(AES_ENC) $(BN_ASM) $(DES_ENC) $(CPUID_OBJ) $(SHA1_ASM_OBJ) $(MODES_ASM_OBJ) $(FIPS_EX_OBJ)' ; export EXCL_OBJ ; \
		ARX='$(PERL) $${TOP}/util/arx.pl $(AR)' ; \
	else \
		ARX='${AR}' ; \
	fi ; export ARX ; \
	if [ $(FIPSCANISTERINTERNAL) = "y" ]; then \
		AS='$(PERL) $${TOP}/util/fipsas.pl $${TOP} $${<} $(CC)' ; \
	else \
		AS='$(CC) -c' ; \
	fi ; export AS ; \
		dir=crypto; target=fips; $(BUILD_ONE_CMD)
build_ssl:
	@dir=ssl; target=all; $(BUILD_ONE_CMD)
build_engines:
	@dir=engines; target=all; $(BUILD_ONE_CMD)
build_apps:
	@dir=apps; target=all; $(BUILD_ONE_CMD)
build_tests:
	@dir=test; target=fipsexe; $(BUILD_ONE_CMD)
build_algvs:
	@dir=test; target=fipsalgvs; $(BUILD_ONE_CMD)
build_tools:
	@dir=tools; target=all; $(BUILD_ONE_CMD)

all_testapps: build_libs build_testapps
build_testapps:
	@dir=crypto; target=testapps; $(BUILD_ONE_CMD)

libcrypto$(SHLIB_EXT): libcrypto.a build_fips
	@if [ "$(SHLIB_TARGET)" != "" ]; then \
		if [ "$(FIPSCANLIB)" = "libcrypto" ]; then \
			FIPSLD_CC="$(CC)"; CC=fips/fipsld; \
			export CC FIPSLD_CC; \
		fi; \
		$(MAKE) SHLIBDIRS=crypto build-shared; \
	else \
		echo "There's no support for shared libraries on this platform" >&2; \
		exit 1; \
	fi

libssl$(SHLIB_EXT): libcrypto$(SHLIB_EXT) libssl.a
	@if [ "$(SHLIB_TARGET)" != "" ]; then \
		$(MAKE) SHLIBDIRS=ssl SHLIBDEPS='-lcrypto' build-shared; \
	else \
		echo "There's no support for shared libraries on this platform" >&2; \
		exit 1; \
	fi

clean-shared:
	@set -e; for i in $(SHLIBDIRS); do \
		if [ -n "$(SHARED_LIBS_LINK_EXTS)" ]; then \
			tmp="$(SHARED_LIBS_LINK_EXTS)"; \
			for j in $${tmp:-x}; do \
				( set -x; rm -f lib$$i$$j ); \
			done; \
		fi; \
		( set -x; rm -f lib$$i$(SHLIB_EXT) ); \
		if [ "$(PLATFORM)" = "Cygwin" ]; then \
			( set -x; rm -f cyg$$i$(SHLIB_EXT) lib$$i$(SHLIB_EXT).a ); \
		fi; \
	done

link-shared:
	@ set -e; for i in $(SHLIBDIRS); do \
		$(MAKE) -f $(HERE)/Makefile.shared -e $(BUILDENV) \
			LIBNAME=$$i LIBVERSION=$(SHLIB_MAJOR).$(SHLIB_MINOR) \
			LIBCOMPATVERSIONS=";$(SHLIB_VERSION_HISTORY)" \
			symlink.$(SHLIB_TARGET); \
		libs="$$libs -l$$i"; \
	done

build-shared: do_$(SHLIB_TARGET) link-shared

do_$(SHLIB_TARGET):
	@ set -e; libs='-L. $(SHLIBDEPS)'; for i in $(SHLIBDIRS); do \
		if [ "$$i" = "ssl" -a -n "$(LIBKRB5)" ]; then \
			libs="$(LIBKRB5) $$libs"; \
		fi; \
		$(CLEARENV) && $(MAKE) -f Makefile.shared -e $(BUILDENV) \
			LIBNAME=$$i LIBVERSION=$(SHLIB_MAJOR).$(SHLIB_MINOR) \
			LIBCOMPATVERSIONS=";$(SHLIB_VERSION_HISTORY)" \
			LIBDEPS="$$libs $(EX_LIBS)" \
			link_a.$(SHLIB_TARGET); \
		libs="-l$$i $$libs"; \
	done

libcrypto.pc: Makefile
	@ ( echo 'prefix=$(INSTALLTOP)'; \
	    echo 'exec_prefix=$${prefix}'; \
	    echo 'libdir=$${exec_prefix}/$(LIBDIR)'; \
	    echo 'includedir=$${prefix}/include'; \
	    echo ''; \
	    echo 'Name: OpenSSL-libcrypto'; \
	    echo 'Description: OpenSSL cryptography library'; \
	    echo 'Version: '$(VERSION); \
	    echo 'Requires: '; \
	    echo 'Libs: -L$${libdir} -lcrypto $(EX_LIBS)'; \
	    echo 'Cflags: -I$${includedir} $(KRB5_INCLUDES)' ) > libcrypto.pc

libssl.pc: Makefile
	@ ( echo 'prefix=$(INSTALLTOP)'; \
	    echo 'exec_prefix=$${prefix}'; \
	    echo 'libdir=$${exec_prefix}/$(LIBDIR)'; \
	    echo 'includedir=$${prefix}/include'; \
	    echo ''; \
	    echo 'Name: OpenSSL'; \
	    echo 'Description: Secure Sockets Layer and cryptography libraries'; \
	    echo 'Version: '$(VERSION); \
	    echo 'Requires: '; \
	    echo 'Libs: -L$${libdir} -lssl -lcrypto $(EX_LIBS)'; \
	    echo 'Cflags: -I$${includedir} $(KRB5_INCLUDES)' ) > libssl.pc

openssl.pc: Makefile
	@ ( echo 'prefix=$(INSTALLTOP)'; \
	    echo 'exec_prefix=$${prefix}'; \
	    echo 'libdir=$${exec_prefix}/$(LIBDIR)'; \
	    echo 'includedir=$${prefix}/include'; \
	    echo ''; \
	    echo 'Name: OpenSSL'; \
	    echo 'Description: Secure Sockets Layer and cryptography libraries and tools'; \
	    echo 'Version: '$(VERSION); \
	    echo 'Requires: '; \
	    echo 'Libs: -L$${libdir} -lssl -lcrypto $(EX_LIBS)'; \
	    echo 'Cflags: -I$${includedir} $(KRB5_INCLUDES)' ) > openssl.pc

Makefile: Makefile.fips Configure config
	@echo "Makefile is older than Makefile.org, Configure or config."
	@echo "Reconfigure the source tree (via './config' or 'perl Configure'), please."
	@false

libclean:
	rm -f *.map *.so *.so.* *.dll engines/*.so engines/*.dll *.a engines/*.a */lib */*/lib

clean:	libclean
	rm -f shlib/*.o *.o core a.out fluff testlog make.log cctest cctest.c
	@set -e; target=clean; $(RECURSIVE_BUILD_CMD)
	rm -f $(LIBS)
	rm -f openssl.pc libssl.pc libcrypto.pc
	rm -f speed.* .pure
	rm -f $(TARFILE)
	@set -e; for i in $(ONEDIRS) ;\
	do \
	rm -fr $$i/*; \
	done

makefile.one: files
	$(PERL) util/mk1mf.pl >makefile.one; \
	sh util/do_ms.sh

files:
	$(PERL) $(TOP)/util/files.pl Makefile > $(TOP)/MINFO
	@set -e; target=files; $(RECURSIVE_BUILD_CMD)

links:
	@$(PERL) $(TOP)/util/mkdir-p.pl include/openssl
	@$(PERL) $(TOP)/util/mklink.pl include/openssl $(EXHEADER)
	@set -e; dir=fips target=links; $(BUILD_ONE_CMD)
	@(cd crypto ; TEST='' SDIRS='$(LINKDIRS)' $(MAKE) -e links)

gentests:
	@(cd test && echo "generating dummy tests (if needed)..." && \
	$(CLEARENV) && $(MAKE) -e $(BUILDENV) TESTS='$(TESTS)' OPENSSL_DEBUG_MEMORY=on generate );

dclean:
	rm -rf *.bak include/openssl certs/.0
	@set -e; target=dclean; $(RECURSIVE_BUILD_CMD)

test:   tests

tests:
	@echo "Not implemented in FIPS build" ; false

report:
	@$(PERL) util/selftest.pl

depend:
	@echo make depend not supported ; false

lint:
	@set -e; target=lint; $(RECURSIVE_BUILD_CMD)

tags:
	rm -f TAGS
	find . -name '[^.]*.[ch]' | xargs etags -a

errors:
	$(PERL) util/mkerr.pl -recurse -write
	(cd engines; $(MAKE) PERL=$(PERL) errors)
	$(PERL) util/ck_errf.pl -strict */*.c */*/*.c

stacks:
	$(PERL) util/mkstack.pl -write

util/libeay.num::
	$(PERL) util/mkdef.pl crypto update

util/ssleay.num::
	$(PERL) util/mkdef.pl ssl update

crypto/objects/obj_dat.h: crypto/objects/obj_dat.pl crypto/objects/obj_mac.h
	$(PERL) crypto/objects/obj_dat.pl crypto/objects/obj_mac.h crypto/objects/obj_dat.h
crypto/objects/obj_mac.h: crypto/objects/objects.pl crypto/objects/objects.txt crypto/objects/obj_mac.num
	$(PERL) crypto/objects/objects.pl crypto/objects/objects.txt crypto/objects/obj_mac.num crypto/objects/obj_mac.h
crypto/objects/obj_xref.h: crypto/objects/objxref.pl crypto/objects/obj_xref.txt crypto/objects/obj_mac.num
	$(PERL) crypto/objects/objxref.pl crypto/objects/obj_mac.num crypto/objects/obj_xref.txt >crypto/objects/obj_xref.h

apps/openssl-vms.cnf: apps/openssl.cnf
	$(PERL) VMS/VMSify-conf.pl < apps/openssl.cnf > apps/openssl-vms.cnf

crypto/bn/bn_prime.h: crypto/bn/bn_prime.pl
	$(PERL) crypto/bn/bn_prime.pl >crypto/bn/bn_prime.h


TABLE: Configure
	(echo 'Output of `Configure TABLE'"':"; \
	$(PERL) Configure TABLE) > TABLE

update: errors stacks util/libeay.num util/ssleay.num crypto/objects/obj_dat.h crypto/objects/obj_xref.h apps/openssl-vms.cnf crypto/bn/bn_prime.h TABLE depend

# Build distribution tar-file. As the list of files returned by "find" is
# pretty long, on several platforms a "too many arguments" error or similar
# would occur. Therefore the list of files is temporarily stored into a file
# and read directly, requiring GNU-Tar. Call "make TAR=gtar dist" if the normal
# tar does not support the --files-from option.
tar:
	find . -type d -print | xargs chmod 755
	find . -type f -print | xargs chmod a+r
	find . -type f -perm -0100 -print | xargs chmod a+x
	find * \! -path CVS/\* \! -path \*/CVS/\* \! -name CVS \! -name .cvsignore \! -name STATUS \! -name TABLE | $(BUILDENV) LINKDIRS='$(LINKDIRS)' $(PERL) util/fipsdist.pl | sort > ../$(TARFILE).list; \
	$(TAR) $(TARFLAGS) --files-from ../$(TARFILE).list -cvf - | \
	tardy --user_number=0  --user_name=openssl \
	      --group_number=0 --group_name=openssl \
	      --prefix=openssl-$(VERSION) - |\
	gzip --best >../$(TARFILE).gz; \
	rm -f ../$(TARFILE).list; \
	ls -l ../$(TARFILE).gz

tar-snap:
	@$(TAR) $(TARFLAGS) -cvf - \
		`find * \! -path CVS/\* \! -path \*/CVS/\* \! -name CVS \! -name .cvsignore \! -name STATUS \! -name TABLE \! -name '*.o' \! -name '*.a' \! -name '*.so' \! -name '*.so.*'  \! -name 'openssl' \! -name '*test' \! -name '.#*' \! -name '*~' | sort` |\
	tardy --user_number=0  --user_name=openssl \
	      --group_number=0 --group_name=openssl \
	      --prefix=openssl-$(VERSION) - > ../$(TARFILE);\
	ls -l ../$(TARFILE)

dist:   
	$(PERL) Configure dist fipscanisteronly
	@$(MAKE) dist_pem_h
	@$(MAKE) SDIRS='$(SDIRS)' clean
	@$(MAKE) -f Makefile.fips TAR='$(TAR)' TARFLAGS='$(TARFLAGS)' tar

dist_pem_h:
	(cd crypto/pem; $(MAKE) -e $(BUILDENV) pem.h; $(MAKE) clean)

install: all install_sw

install_sw:
	@$(PERL) $(TOP)/util/mkdir-p.pl $(INSTALL_PREFIX)$(INSTALLTOP)/bin \
		$(INSTALL_PREFIX)$(INSTALLTOP)/$(LIBDIR) \
		$(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl
	@set -e; headerlist="$(EXHEADER)"; for i in $$headerlist;\
	do \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;
	@set -e; target=install; $(RECURSIVE_BUILD_CMD)

# DO NOT DELETE THIS LINE -- make depend depends on it.
