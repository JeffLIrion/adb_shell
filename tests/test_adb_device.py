import logging
from mock import patch
import os
import sys
import unittest

from adb_shell import constants, exceptions
from adb_shell.adb_device import AdbDevice
from adb_shell.adb_message import AdbMessage, unpack

from . import patchers


# https://stackoverflow.com/a/7483862
_LOGGER = logging.getLogger('adb_shell.adb_device')
_LOGGER.setLevel(logging.DEBUG)
_LOGGER.addHandler(logging.StreamHandler(sys.stdout))


class TestAdbDevice(unittest.TestCase):
    def setUp(self):
        with patchers.patch_tcp_handle:
            self.device = AdbDevice('IP:5555')

    def test_init(self):
        device_with_banner = AdbDevice('IP:5555', 'banner')
        self.assertEqual(device_with_banner._banner, 'banner')

        with patch('socket.gethostname', side_effect=Exception):
            device_banner_unknown = AdbDevice('IP:5555')
            self.assertEqual(device_banner_unknown._banner, 'unknown')

    def test_available(self):
        self.assertFalse(self.device.available)

    def test_connect(self):
        self.assertTrue(self.device.connect())
        self.assertTrue(self.device.available)

    def test_close(self):
        self.assertFalse(self.device.close())
        self.assertFalse(self.device.available)

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
        msg2 = AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'PASS')
        msg3 = AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b'')
        self.device._handle.bulk_read_list = [msg1.pack(), msg1.data, msg2.pack(), msg2.data, msg3.pack()]

        self.assertEqual(self.device.shell('TEST'), 'PASS')

    def test_shell_error_local_id(self):
        self.assertTrue(self.device.connect())

        # Provide the `bulk_read` return values
        msg1 = AdbMessage(command=constants.OKAY, arg0=1, arg1=1234, data=b'\x00')
        msg2 = AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b'')
        self.device._handle.bulk_read_list = [msg1.pack(), msg1.data, msg2.pack()]

        with self.assertRaises(exceptions.InvalidResponseError):
            self.device.shell('TEST')

    '''def test_shell_error_cmd(self):
        self.assertTrue(self.device.connect())

        # Provide the `bulk_read` return values
        msg1 = AdbMessage(command=constants.OPEN, arg0=1, arg1=0, data=b'')
        msg2 = AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'\x00')
        self.device._handle.bulk_read_list = [msg1.pack(), msg2.pack(), msg2.data]

        with self.assertRaises(exceptions.InvalidCommandError):
            self.device.shell('TEST')'''




    '''def test_shell3(self):
        self.assertTrue(self.device.connect())

        # Provide the `bulk_read` return values
        msg1 = AdbMessage(command=constants.OPEN, arg0=1, arg1=0, data=b'%s:%s' % (b'shell', 'TEST1234567890123'.encode('utf-8')) + b'\0')
        msg2 = AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'%s:%s' % (b'shell', 'TEST1234567890123'.encode('utf-8')) + b'\0')
        msg3 = AdbMessage(command=constants.WRTE, arg0=1, arg1=0, data='TEST1234567890123456789'.encode('utf-8') + b'\0')
        msg4 = AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b'%s:%s' % (b'shell', 'TEST1234567890123'.encode('utf-8')) + b'\0')
        self.device._handle.bulk_read_list = [msg1.pack(), msg2.pack(), msg2.data, msg3.pack(), msg3.data, msg4.pack(), msg4.data]

        self.assertNotEqual(self.device.shell('TEST'), '')

    def test_shell4(self):
        self.assertTrue(self.device.connect())

        # Provide the `bulk_read` return values
        msg1 = AdbMessage(command=constants.OPEN, arg0=1, arg1=0, data=b'')
        #msg2 = AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'%s:%s' % (b'shell', 'TEST1234567890123'.encode('utf-8')) + b'\0')
        msg2 = AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'PASS')
        msg3 = AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'PASS')
        msg4 = AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b'%s:%s' % (b'shell', 'TEST1234567890123'.encode('utf-8')) + b'\0')
        self.device._handle.bulk_read_list = [msg1.pack(), msg2.pack(), msg2.data, msg3.pack(), msg3.data, msg4.pack(), msg4.data]

        self.assertEqual(self.device.shell('TEST'), 'PASS')'''


class TestAdbDeviceWithBanner(TestAdbDevice):
    def setUp(self):
        with patchers.patch_tcp_handle:
            self.device = AdbDevice('IP:5555', 'banner')


class TestAdbDeviceBannerError(TestAdbDevice):
    def setUp(self):
        with patch('socket.gethostname', side_effect=Exception):
            with patchers.patch_tcp_handle:
                self.device = AdbDevice('IP:5555')
