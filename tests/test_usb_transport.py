import unittest

from mock import patch

from adb_shell.handle.usb_handle import UsbHandle

from . import patchers


class TestUsbHandle(unittest.TestCase):
    def setUp(self):
        """Create a ``UsbHandle`` and do something...

        """
        self.handle = UsbHandle('TODO', 'TODO')

        if True:
            return
            
        with patchers.PATCH_CREATE_CONNECTION:
            self.handle.connect()

    def tearDown(self):
        """Close the USB connection."""
        self.handle.close()

    def test_connect_with_timeout(self):
        """TODO

        """
        if True:
            return

        self.handle.close()
        with patchers.PATCH_CREATE_CONNECTION:
            self.handle.connect(timeout_s=1)
            self.assertTrue(True)

    def test_bulk_read(self):
        """TODO

        """
        if True:
            return

        # Provide the `recv` return values
        self.handle._connection._recv = b'TEST1TEST2'

        with patchers.PATCH_SELECT_SUCCESS:
            self.assertEqual(self.handle.bulk_read(5), b'TEST1')
            self.assertEqual(self.handle.bulk_read(5), b'TEST2')

        with patchers.PATCH_SELECT_FAIL:
            with self.assertRaises(TcpTimeoutException):
                self.handle.bulk_read(4)

    def test_bulk_write(self):
        """TODO

        """
        if True:
            return

        with patchers.PATCH_SELECT_SUCCESS:
            self.handle.bulk_write(b'TEST')

        with patchers.PATCH_SELECT_FAIL:
            with self.assertRaises(TcpTimeoutException):
                self.handle.bulk_write(b'FAIL')
