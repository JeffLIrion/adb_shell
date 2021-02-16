import unittest

try:
    from unittest.mock import patch
except ImportError:
    from mock import patch

from adb_shell.transport.usb_transport import UsbTransport

from . import patchers


class TestUsbTransport(unittest.TestCase):
    def setUp(self):
        """Create a ``UsbTransport`` and do something...

        """
        self.transport = UsbTransport('TODO', 'TODO')

        if True:
            return
            
        with patchers.PATCH_CREATE_CONNECTION:
            self.transport.connect()

    def tearDown(self):
        """Close the USB connection."""
        self.transport.close()

    def test_connect_with_timeout(self):
        """TODO

        """
        if True:
            return

        self.transport.close()
        with patchers.PATCH_CREATE_CONNECTION:
            self.transport.connect(transport_timeout_s=1)
            self.assertTrue(True)

    def test_bulk_read(self):
        """TODO

        """
        if True:
            return

        # Provide the `recv` return values
        self.transport._connection._recv = b'TEST1TEST2'

        with patchers.PATCH_SELECT_SUCCESS:
            self.assertEqual(self.transport.bulk_read(5), b'TEST1')
            self.assertEqual(self.transport.bulk_read(5), b'TEST2')

        with patchers.PATCH_SELECT_FAIL:
            with self.assertRaises(TcpTimeoutException):
                self.transport.bulk_read(4)

    def test_bulk_write(self):
        """TODO

        """
        if True:
            return

        with patchers.PATCH_SELECT_SUCCESS:
            self.transport.bulk_write(b'TEST')

        with patchers.PATCH_SELECT_FAIL:
            with self.assertRaises(TcpTimeoutException):
                self.transport.bulk_write(b'FAIL')
