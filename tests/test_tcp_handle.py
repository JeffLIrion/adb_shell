from mock import patch
import unittest

from adb_shell.tcp_handle import TcpHandle, TcpTimeoutException

from . import patchers


class TestTcpHandle(unittest.TestCase):
    def setUp(self):
        """Create a ``TcpHandle`` and connect to a TCP service.

        """
        self.handle = TcpHandle('IP:5555')
        with patchers.patch_create_connection:
            self.handle.connect()

    def tearDown(self):
        """Close the socket connection."""
        self.handle.close()

    def test_connect_with_timeout(self):
        """TODO

        """
        self.handle.close()
        with patchers.patch_create_connection:
            self.handle.connect(timeout_s=1)
            self.assertTrue(True)

    def test_bulk_read(self):
        """TODO

        """
        # Provide the `recv` return values
        self.handle._connection._recv = b'TEST1TEST2'

        with patchers.patch_select_success:
            self.assertEqual(self.handle.bulk_read(5), b'TEST1')
            self.assertEqual(self.handle.bulk_read(5), b'TEST2')

        with patchers.patch_select_fail:
            with self.assertRaises(TcpTimeoutException):
                self.handle.bulk_read(4)

    def test_bulk_write(self):
        """TODO

        """
        with patchers.patch_select_success:
            self.handle.bulk_write(b'TEST')

        with patchers.patch_select_fail:
            with self.assertRaises(TcpTimeoutException):
                self.handle.bulk_write(b'FAIL')


class TestTcpHandle2(TestTcpHandle):
    def setUp(self):
        """Create a ``TcpHandle`` and connect to a TCP service.

        """
        self.handle = TcpHandle('IP')
        with patchers.patch_create_connection:
            self.handle.connect()
