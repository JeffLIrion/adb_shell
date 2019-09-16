from mock import patch
import os
import unittest

from adb_shell.keygen import keygen
from adb_shell.sign_cryptography import CryptographySigner

from .keygen_stub import open_priv_pub


class TestCryptographySigner(unittest.TestCase):
    def setUp(self):
        with patch('adb_shell.sign_cryptography.open', open_priv_pub), patch('adb_shell.keygen.open', open_priv_pub):
            keygen('tests/adbkey')
            self.signer = CryptographySigner('tests/adbkey')

    def test_sign(self):
        """Test that the ``Sign`` method does not raise an exception."""
        with self.assertRaises(ValueError):
            self.signer.Sign(b'notadb')
        self.assertTrue(True)

    def test_get_public_key(self):
        """Test that the ``GetPublicKey`` method works correctly."""
        with patch('{}.open'.format(__name__), open_priv_pub):
            with open('tests/adbkey.pub') as f:
                pub = f.read()

            self.assertEqual(pub, self.signer.GetPublicKey())
