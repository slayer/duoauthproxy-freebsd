#!/usr/bin/env python

from setuptools import setup, find_packages

import pyrad

setup(name='pyrad',
      version=pyrad.__version__,
      author='Christian Giese',
      author_email='developer@gicnet.de',
      url='https://github.com/pyradius/pyrad',
      license='BSD',
      description='RADIUS tools',
      long_description=open('README.rst').read(),
      classifiers=[
          'Development Status :: 6 - Mature',
          'Intended Audience :: Developers',
          'License :: OSI Approved :: BSD License',
          'Programming Language :: Python :: 2.7',
          'Programming Language :: Python :: 3.4',
          'Programming Language :: Python :: 3.6',
          'Programming Language :: Python :: 3.8',
          'Topic :: Software Development :: Libraries :: Python Modules',
          'Topic :: System :: Systems Administration :: Authentication/Directory',
      ],
      packages=find_packages(exclude=['tests']),
      keywords=['radius', 'authentication'],
      # BEGIN DUO EDIT @iraja: py2exe can't detect packages installed as eggs
      # zip_safe=True,
      # END DUO EDIT
      include_package_data=True,
      install_requires=['six', 'netaddr'],
      tests_require='nose>=0.10.0b1',
      test_suite='nose.collector',
      )
