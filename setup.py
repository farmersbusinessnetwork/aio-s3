#!/usr/bin/env python

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

setup(name='aio-s3',
      version='0.5.16',
      description='Asyncio-based client for S3',
      author='Paul Colomiets',
      author_email='paul@colomiets.name',
      url='http://github.com/tailhook/aio-s3',
      packages=[
          'aios3',
      ],
      install_requires=['aiohttp', 'botocore', 'xmltodict'],
      classifiers=[
          'Development Status :: 4 - Beta',
          'Programming Language :: Python :: 3.5',
      ],
      )
