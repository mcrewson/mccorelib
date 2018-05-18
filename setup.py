#!/usr/bin/python2

from glob import glob
from distutils.core import setup

setup(
  name='mccorelib',
  version='0.0.4',
  url='https://github.com/mcrewson/mccorelib',
  author='Mark Crewson',
  author_email='mark@crewson.net',
  license='Apache Software License 2.0',
  description='A small python application framework.',
  packages=['mccorelib', ],
)
