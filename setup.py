#!/usr/bin/env python

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

try:
    import fbn_certs
except ImportError:
    pass


setup(name='aio-s3',
      version='0.6.8',
      description='Asyncio-based client for S3',
      author='Paul Colomiets',
      author_email='paul@colomiets.name',
      url='http://github.com/tailhook/aio-s3',
      packages=[
          'aios3',
      ],
      install_requires=['aiobotocore>=0.1.1', 'xmltodict'],
      classifiers=[
          'Development Status :: 4 - Beta',
          'Programming Language :: Python :: 3.5',
      ],
      )
