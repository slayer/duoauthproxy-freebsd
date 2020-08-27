import setuptools
from distutils.core import setup

import twisted_connect_proxy

connect_proxy_classifiers = [
    "Programming Language :: Python :: 3",
    "Intended Audience :: Developers",
    "License :: OSI Approved :: BSD License",
    "Topic :: Software Development :: Libraries",
    "Topic :: Utilities",
]

fp = open("README.md", "r")
try:
    connect_proxy_long_description = fp.read()
finally:
    fp.close()


setup(name="twisted-connect-proxy",
      version="1.0",
      author="Peter Ruibal",
      author_email="ruibalp@gmail.com",
      url="https://github.com/fmoo/twisted-connect-proxy",
      description="Python 2 compatibility utilities",
      long_description=connect_proxy_long_description,
      classifiers=connect_proxy_classifiers,
      packages=setuptools.find_packages(exclude=['tests']),
)
