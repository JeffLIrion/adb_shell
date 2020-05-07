import os
import unittest

from unittest.mock import patch

from aio_adb_shell.auth.keygen import keygen
from aio_adb_shell.auth.sign_pythonrsa import PythonRSASigner

from .keygen_stub import open_priv_pub


class TestPythonRSASigner(unittest.TestCase):
    def setUp(self):
        with patch('aio_adb_shell.auth.sign_pythonrsa.open', open_priv_pub), patch('aio_adb_shell.auth.keygen.open', open_priv_pub):
            keygen('tests/adbkey')
            self.signer = PythonRSASigner.FromRSAKeyPath('tests/adbkey')

    def test_sign(self):
        """Test that the ``Sign`` method does not raise an exception."""
        self.signer.Sign(b'notadb')
        self.assertTrue(True)

    def test_get_public_key(self):
        """Test that the ``GetPublicKey`` method works correctly."""
        with patch('{}.open'.format(__name__), open_priv_pub):
            with open('tests/adbkey.pub') as f:
                pub = f.read()

            self.assertEqual(pub, self.signer.GetPublicKey())


class TestPythonRSASignerExceptions(unittest.TestCase):
    def test_value_error(self):
        with patch('aio_adb_shell.auth.sign_pythonrsa.open', open_priv_pub), patch('aio_adb_shell.auth.keygen.open', open_priv_pub):
            with patch('aio_adb_shell.auth.sign_pythonrsa.decoder.decode', return_value=([None, [None]], None)):
                with self.assertRaises(ValueError):
                    keygen('tests/adbkey')
                    self.signer = PythonRSASigner.FromRSAKeyPath('tests/adbkey')

    def test_index_error(self):
        with patch('aio_adb_shell.auth.sign_pythonrsa.open', open_priv_pub), patch('aio_adb_shell.auth.keygen.open', open_priv_pub):
            with patch('aio_adb_shell.auth.sign_pythonrsa.decoder.decode', side_effect=IndexError):
                with self.assertRaises(ValueError):
                    keygen('tests/adbkey')
                    self.signer = PythonRSASigner.FromRSAKeyPath('tests/adbkey')
                
