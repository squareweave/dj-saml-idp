# -*- coding: utf-8 -*-
"""
Signing code goes here.
"""
from __future__ import absolute_import, print_function, unicode_literals
import base64
import hashlib
import string

import OpenSSL.crypto
from django.utils import six

from . import saml2idp_metadata as smd
from .codex import nice64
from .xml_templates import SIGNED_INFO, SIGNATURE
from .logging import get_saml_logger

logger = get_saml_logger()


def load_certificate(config):
    if smd.CERTIFICATE_DATA in config:
        return config.get(smd.CERTIFICATE_DATA, '')

    certificate_filename = config.get(smd.CERTIFICATE_FILENAME)
    logger.info('Using certificate file: ' + certificate_filename)

    certificate = OpenSSL.crypto.load_certificate(
        OpenSSL.crypto.FILETYPE_PEM, open(certificate_filename, 'rb').read())

    pem_bytes = OpenSSL.crypto.dump_certificate(
        OpenSSL.crypto.FILETYPE_PEM, certificate)

    # PEM files contain a base64 encoded string, so are fine to treat as ASCII
    pem_str = ''.join(pem_bytes.decode('ascii').split('\n')[1:-2])

    return pem_str


def load_private_key(config):
    private_key_data = config.get(smd.PRIVATE_KEY_DATA)

    if private_key_data:
        return OpenSSL.crypto.load_privatekey(
            OpenSSL.crypto.FILETYPE_PEM, private_key_data)

    private_key_file = config.get(smd.PRIVATE_KEY_FILENAME)
    logger.info('Using private key file: {}'.format(private_key_file))

    return OpenSSL.crypto.load_privatekey(
        OpenSSL.crypto.FILETYPE_PEM, open(private_key_file, 'rb').read())


def sign_with_rsa(private_key, data):
    """
    Sign the given sequence of bytes with the private key.
    If 'data' is unicode, it's encoded as utf8 before signing.
    """
    if isinstance(data, six.text_type):
        encoded_data = data.encode('utf8')
    else:
        encoded_data = data

    signed_data = OpenSSL.crypto.sign(private_key, encoded_data, "sha1")
    return base64.b64encode(signed_data).decode('ascii')


def get_signature_xml(subject, reference_uri):
    """
    Returns XML Signature for subject.
    """
    logger.debug('get_signature_xml - Begin.')
    config = smd.SAML2IDP_CONFIG

    private_key = load_private_key(config)
    certificate = load_certificate(config)

    logger.debug('Subject: ' + subject)

    # Hash the subject; we expect that to be a Unicode
    # string, but we'll handle either bytes or Unicode.
    subject_hash = hashlib.sha1()
    if isinstance(subject, six.text_type):
        subject_hash.update(subject.encode('utf8'))
    else:
        subject_hash.update(subject)

    subject_digest = nice64(subject_hash.digest())
    logger.debug('Subject digest: ' + subject_digest)

    # Create signed_info.
    signed_info = string.Template(SIGNED_INFO).substitute({
        'REFERENCE_URI': reference_uri,
        'SUBJECT_DIGEST': subject_digest,
        })
    logger.debug('SignedInfo XML: ' + signed_info)

    rsa_signature = sign_with_rsa(private_key, signed_info)
    logger.debug('RSA Signature: ' + rsa_signature)

    # Put the signed_info and rsa_signature into the XML signature.
    signed_info_short = signed_info.replace(' xmlns:ds="http://www.w3.org/2000/09/xmldsig#"', '')
    signature_xml = string.Template(SIGNATURE).substitute({
        'RSA_SIGNATURE': rsa_signature,
        'SIGNED_INFO': signed_info_short,
        'CERTIFICATE': certificate,
        })
    logger.info('Signature XML: ' + signature_xml)
    return signature_xml
