import unittest

try:
    from unittest.mock import patch
except ImportError:
    from mock import patch

from adb_shell.exceptions import TcpTimeoutException
from adb_shell.transport.tcp_transport import TcpTransport

from . import patchers


class TestTcpTransport(unittest.TestCase):
    def setUp(self):
        """Create a ``TcpTransport`` and connect to a TCP service.

        """
        self.transport = TcpTransport('host', 5555)
        with patchers.PATCH_CREATE_CONNECTION:
            self.transport.connect(transport_timeout_s=1)

    def tearDown(self):
        """Close the socket connection."""
        self.transport.close()

    def test_connect_with_timeout(self):
        """TODO

        """
        self.transport.close()
        with patchers.PATCH_CREATE_CONNECTION:
            self.transport.connect(transport_timeout_s=1)
            self.assertTrue(True)

    def test_bulk_read(self):
        """TODO

        """
        # Provide the `recv` return values
        self.transport._connection._recv = b'TEST1TEST2'

        with patchers.PATCH_SELECT_SUCCESS:
            self.assertEqual(self.transport.bulk_read(5, transport_timeout_s=1), b'TEST1')
            self.assertEqual(self.transport.bulk_read(5, transport_timeout_s=1), b'TEST2')

        with patchers.PATCH_SELECT_FAIL:
            with self.assertRaises(TcpTimeoutException):
                self.transport.bulk_read(4, transport_timeout_s=1)

    def test_close_oserror(self):
        """Test that an `OSError` exception is handled when closing the socket.

        """
        with patch('{}.patchers.FakeSocket.shutdown'.format(__name__), side_effect=OSError):
            self.transport.close()

    def test_bulk_write(self):
        """TODO

        """
        with patchers.PATCH_SELECT_SUCCESS:
            self.transport.bulk_write(b'TEST', transport_timeout_s=1)

        with patchers.PATCH_SELECT_FAIL:
            with self.assertRaises(TcpTimeoutException):
                self.transport.bulk_write(b'FAIL', transport_timeout_s=1)
