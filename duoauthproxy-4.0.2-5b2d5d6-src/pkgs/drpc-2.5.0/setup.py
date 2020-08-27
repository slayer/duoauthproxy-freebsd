import os.path
from distutils.core import setup

import drpc
import setuptools

requirements_filename = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), 'requirements.txt')

with open(requirements_filename) as fd:
    install_requires = [i.strip() for i in fd.readlines()]

setup(
    name='drpc',
    version=drpc.__version__,
    description='Implements the DRPC network protocol',
    long_description=open('README.md', 'rt').read(),
    author='Duo Security, Inc.',
    author_email='support@duosecurity.com',
    packages=setuptools.find_packages(exclude=['tests']),
    install_requires=install_requires,
)
