from mock import patch
import unittest

from adb_shell.tcp_handle import TcpHandle, TcpTimeoutException

from . import patchers


class TestAdbHandle(unittest.TestCase):
    def setUp(self):
        """Create a ``TcpHandle`` and connect to a TCP service.

        """
        self.handle = TcpHandle('IP:5555')
        with patchers.patch_create_connection:
            self.handle.connect()

    def tearDown(self):
        """Close the socket connection."""
        self.handle.close()

    def test_bulk_read(self):
        """TODO

        """
        # Provide the `recv` return values
        self.handle._connection.recv_list = [b'TEST1', b'TEST2']

        with patchers.patch_select_success:
            self.assertEqual(self.handle.bulk_read(1234), b'TEST1')
            self.assertEqual(self.handle.bulk_read(5678), b'TEST2')

        with patchers.patch_select_fail:
            with self.assertRaises(TcpTimeoutException):
                self.handle.bulk_read(b'FAIL')

    def test_bulk_write(self):
        """TODO

        """
        with patchers.patch_select_success:
            self.handle.bulk_write(b'TEST')

        with patchers.patch_select_fail:
            with self.assertRaises(TcpTimeoutException):
                self.handle.bulk_write(b'FAIL')


class TestAdbHandle2(TestAdbHandle):
    def setUp(self):
        """Create a ``TcpHandle`` and connect to a TCP service.

        """
        self.handle = TcpHandle('IP')
        with patchers.patch_create_connection:
            self.handle.connect()
