import unittest

from mock import patch

from adb_shell.exceptions import TcpTimeoutException
from adb_shell.handle.tcp_handle import TcpHandle

from . import patchers


class TestTcpHandle(unittest.TestCase):
    def setUp(self):
        """Create a ``TcpHandle`` and connect to a TCP service.

        """
        self.handle = TcpHandle('host', '5555')
        with patchers.PATCH_CREATE_CONNECTION:
            self.handle.connect()

    def tearDown(self):
        """Close the socket connection."""
        self.handle.close()

    def test_socket_address(self):
        """
        Verify socket_address property works as intended
        :return:
        """
        self.assertEqual(
            self.handle.socket_address,
            'host:5555'
        )

    def test_connect_with_timeout(self):
        """TODO

        """
        self.handle.close()
        with patchers.PATCH_CREATE_CONNECTION:
            self.handle.connect(timeout_s=1)
            self.assertTrue(True)

    def test_bulk_read(self):
        """TODO

        """
        # Provide the `recv` return values
        self.handle._connection._recv = b'TEST1TEST2'

        with patchers.PATCH_SELECT_SUCCESS:
            self.assertEqual(self.handle.bulk_read(5), b'TEST1')
            self.assertEqual(self.handle.bulk_read(5), b'TEST2')

        with patchers.PATCH_SELECT_FAIL:
            with self.assertRaises(TcpTimeoutException):
                self.handle.bulk_read(4)

    def test_close_oserror(self):
        """Test that an `OSError` exception is handled when closing the socket.

        """
        with patch('{}.patchers.FakeSocket.shutdown'.format(__name__), side_effect=OSError):
            self.handle.close()

    def test_bulk_write(self):
        """TODO

        """
        with patchers.PATCH_SELECT_SUCCESS:
            self.handle.bulk_write(b'TEST')

        with patchers.PATCH_SELECT_FAIL:
            with self.assertRaises(TcpTimeoutException):
                self.handle.bulk_write(b'FAIL')
