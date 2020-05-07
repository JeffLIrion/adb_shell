import os
import unittest

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from unittest.mock import patch

from aio_adb_shell.auth.keygen import keygen
from aio_adb_shell.auth.sign_cryptography import CryptographySigner

from .keygen_stub import open_priv_pub


class TestCryptographySigner(unittest.TestCase):
    def setUp(self):
        with patch('aio_adb_shell.auth.sign_cryptography.open', open_priv_pub), patch('aio_adb_shell.auth.keygen.open', open_priv_pub):
            keygen('tests/adbkey')
            self.signer = CryptographySigner('tests/adbkey')

    def test_sign(self):
        """Test that the ``Sign`` method does not raise an exception."""
        # https://www.programcreek.com/python/example/107988/cryptography.hazmat.primitives.hashes.Hash
        hash_ctx = hashes.Hash(hashes.SHA1(), default_backend())
        hash_ctx.update(b'notadb')
        data = hash_ctx.finalize()
        # For reference:
        #   data = b'(\x8b\x9e\x88|JY\xb5\x18\x13b_\xe0\xc4\xfb\xa5\x83\xbdx\xfc'

        self.signer.Sign(data)
        self.assertTrue(True)

    def test_get_public_key(self):
        """Test that the ``GetPublicKey`` method works correctly."""
        with patch('{}.open'.format(__name__), open_priv_pub):
            with open('tests/adbkey.pub', 'rb') as f:
                pub = f.read()

            self.assertEqual(pub, self.signer.GetPublicKey())
