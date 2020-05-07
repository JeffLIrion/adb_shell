import os
import unittest

from unittest.mock import patch

from aio_adb_shell.auth.keygen import keygen
from aio_adb_shell.auth.sign_pycryptodome import PycryptodomeAuthSigner

from .keygen_stub import open_priv_pub


class TestPycryptodomeAuthSigner(unittest.TestCase):
    def setUp(self):
        with patch('aio_adb_shell.auth.sign_pycryptodome.open', open_priv_pub), patch('aio_adb_shell.auth.keygen.open', open_priv_pub):
            keygen('tests/adbkey')
            self.signer = PycryptodomeAuthSigner('tests/adbkey')

    def test_sign(self):
        """Test that the ``Sign`` method does not raise an exception."""
        self.signer.Sign(b'notadb')
        self.assertTrue(True)

    def test_get_public_key(self):
        """Test that the ``GetPublicKey`` method works correctly."""
        with patch('{}.open'.format(__name__), open_priv_pub):
            with open('tests/adbkey.pub', 'rb') as f:
                pub = f.read()

            self.assertEqual(pub, self.signer.GetPublicKey())
