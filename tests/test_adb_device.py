import logging
from mock import patch
import os
import sys
import unittest

from adb_shell import constants, exceptions
from adb_shell.adb_device import AdbDevice
from adb_shell.adb_message import AdbMessage, unpack
from adb_shell.auth.keygen import keygen
from adb_shell.auth.sign_pythonrsa import PythonRSASigner

from . import patchers
from .keygen_stub import open_priv_pub


# https://stackoverflow.com/a/7483862
_LOGGER = logging.getLogger('adb_shell.adb_device')
_LOGGER.setLevel(logging.DEBUG)
_LOGGER.addHandler(logging.StreamHandler(sys.stdout))


class AdbMessageForTesting(AdbMessage):
    def __init__(self, command, arg0=None, arg1=None, data=b''):
        self.command = sum(c << (i * 8) for i, c in enumerate(bytearray(command)))
        self.magic = self.command ^ 0xFFFFFFFF
        self.arg0 = arg0
        self.arg1 = arg1
        self.data = data


class TestAdbDevice(unittest.TestCase):
    def setUp(self):
        with patchers.patch_tcp_handle:
            self.device = AdbDevice('IP:5555')
            self.device._handle.bulk_read_list = patchers.BULK_READ_LIST[:]

    def tearDown(self):
        self.assertFalse(self.device._handle.bulk_read_list)

    def test_init(self):
        device_with_banner = AdbDevice('IP:5555', 'banner')
        self.assertEqual(device_with_banner._banner, 'banner')

        with patch('socket.gethostname', side_effect=Exception):
            device_banner_unknown = AdbDevice('IP:5555')
            self.assertEqual(device_banner_unknown._banner, 'unknown')

        self.device._handle.bulk_read_list = []

    def test_available(self):
        self.assertFalse(self.device.available)

        self.device._handle.bulk_read_list = []

    def test_connect(self):
        self.assertTrue(self.device.connect())
        self.assertTrue(self.device.available)

    def test_close(self):
        self.assertFalse(self.device.close())
        self.assertFalse(self.device.available)

        self.device._handle.bulk_read_list = []

    def test_shell_no_return(self):
        self.assertTrue(self.device.connect())

        # Provide the `bulk_read` return values
        msg1 = AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'' + b'\0')
        msg2 = AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b'')
        self.device._handle.bulk_read_list = [msg1.pack(), msg1.data, msg2.pack()]

        self.assertEqual(self.device.shell('TEST'), '')

    def test_shell_return_pass(self):
        self.assertTrue(self.device.connect())

        # Provide the `bulk_read` return values
        msg1 = AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00')
        msg2 = AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'PA')
        msg3 = AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'SS')
        msg4 = AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b'')
        self.device._handle.bulk_read_list = [msg1.pack(), msg1.data, msg2.pack(), msg2.data, msg3.pack(), msg3.data, msg4.pack()]

        self.assertEqual(self.device.shell('TEST'), 'PASS')

    def test_shell_error_local_id(self):
        self.assertTrue(self.device.connect())

        # Provide the `bulk_read` return values
        msg1 = AdbMessage(command=constants.OKAY, arg0=1, arg1=1234, data=b'\x00')
        self.device._handle.bulk_read_list = [msg1.pack(), msg1.data]

        with self.assertRaises(exceptions.InvalidResponseError):
            self.device.shell('TEST')

    def test_shell_error_clse(self):
        self.assertTrue(self.device.connect())

        # Provide the `bulk_read` return values
        msg1 = AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b'\x00')
        msg2 = AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b'\x00')
        self.device._handle.bulk_read_list = [msg1.pack(), msg1.data, msg2.pack(), msg2.data]

        self.assertEqual(self.device.shell('TEST'), '')

    def test_shell_error_unknown_command(self):
        self.assertTrue(self.device.connect())

        # Provide the `bulk_read` return values
        msg1 = AdbMessageForTesting(command=constants.FAIL, arg0=1, arg1=1, data=b'\x00')
        self.device._handle.bulk_read_list = [msg1.pack()]

        with self.assertRaises(exceptions.InvalidCommandError):
            self.assertEqual(self.device.shell('TEST'), '')

    def test_shell_error_timeout(self):
        self.assertTrue(self.device.connect())

        # Provide the `bulk_read` return values
        msg1 = AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'' + b'\0')
        self.device._handle.bulk_read_list = [msg1.pack()]

        with self.assertRaises(exceptions.InvalidCommandError):
            self.device.shell('TEST', total_timeout_s=-1)

    @unittest.skipIf(sys.version_info[0] == 3, "``unittest.testCase.assertLogs`` is not implemented in Python 2.")
    def test_shell_warning_data_length_python2(self):
        self.assertTrue(self.device.connect())

        # Provide the `bulk_read` return values
        msg1 = AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00')
        msg2 = AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'PASS')
        self.device._handle.bulk_read_list = [msg1.pack(), msg1.data, msg2.pack(), msg2.data + b'EXTRA']

        with self.assertRaises(exceptions.InvalidChecksumError):
            self.device.shell('TEST')

    @unittest.skipIf(sys.version_info[0] == 2, "``unittest.testCase.assertLogs`` is not implemented in Python 2.")
    def test_shell_warning_data_length_python3(self):
        self.assertTrue(self.device.connect())

        # Provide the `bulk_read` return values
        msg1 = AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00')
        msg2 = AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'PASS')
        self.device._handle.bulk_read_list = [msg1.pack(), msg1.data, msg2.pack(), msg2.data + b'EXTRA']

        with self.assertLogs(level=logging.WARNING) as logs:
            with self.assertRaises(exceptions.InvalidChecksumError):
                self.device.shell('TEST')

        assert "Data_length 4 does not match actual number of bytes read: 9" in logs.output[-1]

    def test_shell_error_checksum(self):
        self.assertTrue(self.device.connect())

        # Provide the `bulk_read` return values
        msg1 = AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00')
        msg2 = AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'PASS')
        self.device._handle.bulk_read_list = [msg1.pack(), msg1.data, msg2.pack(), msg2.data[:-1] + b'0']

        with self.assertRaises(exceptions.InvalidChecksumError):
            self.device.shell('TEST')

    def test_shell_error_local_id2(self):
        self.assertTrue(self.device.connect())

        # Provide the `bulk_read` return values
        msg1 = AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00')
        msg2 = AdbMessage(command=constants.WRTE, arg0=1, arg1=2, data=b'PASS')
        self.device._handle.bulk_read_list = [msg1.pack(), msg1.data, msg2.pack(), msg2.data]

        with self.assertRaises(exceptions.InterleavedDataError):
            self.device.shell('TEST')
            self.device.shell('TEST')

    def test_shell_error_remote_id2(self):
        self.assertTrue(self.device.connect())

        # Provide the `bulk_read` return values
        msg1 = AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00')
        msg2 = AdbMessage(command=constants.WRTE, arg0=2, arg1=1, data=b'PASS')
        self.device._handle.bulk_read_list = [msg1.pack(), msg1.data, msg2.pack(), msg2.data]

        with self.assertRaises(exceptions.InvalidResponseError):
            self.device.shell('TEST')

    def test_connect_no_keys(self):
        self.device._handle.bulk_read_list = patchers.BULK_READ_LIST_WITH_AUTH[:2]
        with self.assertRaises(exceptions.DeviceAuthError):
            self.device.connect()

    def test_connect_with_key_invalid_response(self):
        with patch('adb_shell.auth.sign_pythonrsa.open', open_priv_pub), patch('adb_shell.auth.keygen.open', open_priv_pub):
            keygen('tests/adbkey')
            signer = PythonRSASigner.FromRSAKeyPath('tests/adbkey')

        self.device._handle.bulk_read_list = patchers.BULK_READ_LIST_WITH_AUTH_INVALID[:]

        with self.assertRaises(exceptions.InvalidResponseError):
            self.device.connect([signer])

    def test_connect_with_key(self):
        with patch('adb_shell.auth.sign_pythonrsa.open', open_priv_pub), patch('adb_shell.auth.keygen.open', open_priv_pub):
            keygen('tests/adbkey')
            signer = PythonRSASigner.FromRSAKeyPath('tests/adbkey')

        self.device._handle.bulk_read_list = patchers.BULK_READ_LIST_WITH_AUTH[:]

        self.assertTrue(self.device.connect([signer]))

    def test_connect_with_new_key(self):
        with patch('adb_shell.auth.sign_pythonrsa.open', open_priv_pub), patch('adb_shell.auth.keygen.open', open_priv_pub):
            keygen('tests/adbkey')
            signer = PythonRSASigner.FromRSAKeyPath('tests/adbkey')

        self.device._handle.bulk_read_list = patchers.BULK_READ_LIST_WITH_AUTH_NEW_KEY[:]

        self.assertTrue(self.device.connect([signer]))


class TestAdbDeviceWithBanner(TestAdbDevice):
    def setUp(self):
        with patchers.patch_tcp_handle:
            self.device = AdbDevice('IP:5555', 'banner')
            self.device._handle.bulk_read_list = patchers.BULK_READ_LIST[:]


class TestAdbDeviceBannerError(TestAdbDevice):
    def setUp(self):
        with patch('socket.gethostname', side_effect=Exception):
            with patchers.patch_tcp_handle:
                self.device = AdbDevice('IP:5555')
                self.device._handle.bulk_read_list = patchers.BULK_READ_LIST[:]
