import unittest


class TestUsbImportError(unittest.TestCase):
    def test_import_error(self):
        """Test that the package still works when ``libusb1`` is not installed."""
        from adb_shell import adb_device
        from adb_shell.exceptions import InvalidHandleError

        # TODO: I can't manage to trigger an `ImportError` in adb_device.py
        # self.assertIsNone(adb_device.UsbTransport)

        # In lieu of a real `ImportError`, I'll just set this to None
        adb_device.UsbTransport = None

        with self.assertRaises(InvalidHandleError):
            adb_device.AdbDeviceUsb('serial')
