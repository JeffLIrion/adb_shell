import unittest

try:
    from unittest.mock import patch
except ImportError:
    from mock import patch

from adb_shell.transport.usb_transport import UsbTransport


class TestUsbImportError(unittest.TestCase):
    def test_import_error(self):
        """Test that the package still works when ``libusb1`` is not installed."""
        from adb_shell import adb_device
        from adb_shell.exceptions import InvalidTransportError

        # TODO: I can't manage to trigger an `ImportError` in adb_device.py
        # self.assertIsNone(adb_device.UsbTransport)

        # In lieu of a real `ImportError`, I'll just set this to None
        with patch("adb_shell.adb_device.UsbTransport", None):
            with self.assertRaises(InvalidTransportError):
                adb_device.AdbDeviceUsb('serial')

    def test_import_successful(self):
        from adb_shell import adb_device

        if UsbTransport is not None:
            # Make sure `UsbTransport` was imported
            with patch("adb_shell.adb_device.UsbTransport", UsbTransport):
                with patch("adb_shell.adb_device.UsbTransport.find_adb", return_value=UsbTransport("TODO", "TODO")):
                    adb_device.AdbDeviceUsb("serial")
