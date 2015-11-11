#!/usr/bin/env python

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

setup(name='aio-s3',
      version='0.3',
      description='Asyncio-based client for S3',
      author='Paul Colomiets',
      author_email='paul@colomiets.name',
      url='http://github.com/tailhook/aio-s3',
      packages=[
          'aios3',
      ],
      requires=['aiohttp', 'xmltodict'],
      classifiers=[
          'Development Status :: 4 - Beta',
          'Programming Language :: Python :: 3',
          'Programming Language :: Python :: 3.4',
      ],
      )
