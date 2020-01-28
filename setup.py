# -*- coding: utf-8 -*-
from setuptools import setup
import saml2idp


with open('README.md') as readme:
    description = readme.read()


with open('HISTORY.md') as history:
    changelog = history.read()


setup(
    name='dj-saml-idp',
    version=saml2idp.__version__,
    author='Sebastian Vetter',
    author_email='sebastian@mobify.com',
    description='SAML 2.0 IdP for Django',
    long_description='\n\n'.join([description, changelog]),
    install_requires=[
        'Django<2',
        'pyopenssl>=0.16',
        'beautifulsoup4>=4.8.1',
        'structlog==16.1.0',
        'lxml==4.4.1'
    ],
    license='MIT',
    packages=['saml2idp'],
    url='http://github.com/mobify/dj-saml-idp',
    zip_safe=False,
    include_package_data=True,
)
