#
# Copyright (c) 2011 Duo Security
# All Rights Reserved
#

from distutils.core import setup
import platform
import duoauthproxy

metadata = dict(
    name="duoauthproxy",
    version=duoauthproxy.__version__,
    company_name="Duo Security",
    copyright="Copyright Duo Security 2010-2011. All rights reserved.",
    )

if platform.system() == 'Windows':
    import py2exe
    import sys
    # We need to append the duoauthproxy folder to the path so that py2exe is able to
    # find our module. This is hard for py2exe to do today because proxy_svc.py and setup.py
    # are not in the same directory.
    sys.path.append('duoauthproxy')

    class Target:
        def __init__(self, **kw):
            self.__dict__.update(kw)

    auth_proxy_service = Target(
        description="Duo Authentication Proxy Service",
        modules=['duoauthproxy.proxy_svc'],
        cmdline_style='pywin32',
        **metadata
        )

    # Py2exe attempts to include all these dlls for psutil when it doesn't need to and in fact causes errors
    system_dlls_to_exclude = [
        'API-MS-Win-Core-Handle-L1-1-0.dll',
        'WINNSI.DLL',
        'API-MS-Win-Core-File-L1-1-0.dll',
        'API-MS-Win-Core-Interlocked-L1-1-0.dll',
        'API-MS-Win-Core-IO-L1-1-0.dll',
        'NSI.dll',
        'WTSAPI32.dll',
        'API-MS-Win-Core-LibraryLoader-L1-1-0.dll',
        'API-MS-Win-Core-Misc-L1-1-0.dll',
        'API-MS-Win-Core-ThreadPool-L1-1-0.dll',
        'IPHLPAPI.DLL',
        'MPR.dll',
        'API-MS-Win-Core-LocalRegistry-L1-1-0.dll',
        'API-MS-Win-Core-Profile-L1-1-0.dll',
        'API-MS-Win-Core-ErrorHandling-L1-1-0.dll',
        'API-MS-Win-Core-SysInfo-L1-1-0.dll',
        'API-MS-Win-Core-DelayLoad-L1-1-0.dll',
        'API-MS-Win-Core-Synch-L1-1-0.dll',
        'API-MS-Win-Core-Heap-L1-1-0.dll',
        'API-MS-Win-Security-Base-L1-1-0.dll',
        'API-MS-Win-Core-ProcessThreads-L1-1-0.dll',
        'API-MS-Win-Core-String-L1-1-0.dll',
        "PSAPI.DLL",
        "mswsock.dll",
        "powrprof.dll",
    ]

    linux_packages_to_exclude = [
        'syslog',
        'readline',
        'psutil._psutil_aix',
        'psutil._psutil_bsd',
        'psutil._psutil_osx',
        'psutil._psutil_posix',
        'psutil._psutil_sunos',
        '_posixshmem',
    ]

    python2_packages_to_exclude = [
        'BytesIO',
        'Crypto',
        'Queue',
        'UserDict',
        'cookielib',
        'sha',
        'sets',
        'urllib.quote',
        'urllib.unquote',
        'ordereddict',
        'collections.Callable',
        'collections.Iterable',
        'collections.Mapping',
        'collections.MutableMapping',
        'collections.Sequence',
    ]

    setup(
        options={
            'py2exe': {
                'dll_excludes': system_dlls_to_exclude,
                'excludes': linux_packages_to_exclude + python2_packages_to_exclude,
                'custom_boot_script': '_fipscustomize.py',
                'skip_archive': True,  # don't zip the byte-compiled modules so we can dynamically import
            }
        },
        console=[
            'scripts/authproxy',
            'scripts/authproxy_passwd',
            'scripts/authproxy_connectivity_tool',
            'scripts/authproxy_primary_only',
            'scripts/authproxy_support',
            'scripts/authproxy_update_sso_enrollment_code',
        ],
        service=[auth_proxy_service],
    )
else:
    setup(
        packages=['duoauthproxy',
                  'duoauthproxy.modules',
                  'duoauthproxy.modules.drpc_plugins',
                  'duoauthproxy.lib',
                  'duoauthproxy.lib.ldap',
                  'duoauthproxy.lib.radius',
                  'duoauthproxy.lib.protect',
                  'duoauthproxy.lib.validation',
                  'duoauthproxy.lib.validation.config',
                  'duoauthproxy.lib.validation.config.check',
                  'duoauthproxy.lib.validation.connectivity',
                  'duoauthproxy.lib.validation.connectivity.check',
                  'duoauthproxy.lib.validation.connectivity.connect',
                  'duoauthproxy.lib.validation.config',
        ],
        scripts=['scripts/authproxy',
                 'scripts/authproxyctl',
                 'scripts/install',
                 'scripts/authproxy_connectivity_tool',
                 'scripts/authproxy_primary_only',
                 'scripts/authproxy_support',
                 'scripts/authproxy_update_sso_enrollment_code',
                 ],
        **metadata
    )
