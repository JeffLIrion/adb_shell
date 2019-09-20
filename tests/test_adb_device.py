import logging
from mock import patch
import os
import sys
import unittest

from adb_shell import constants
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
        self.assertTrue(True)

    def test_available(self):
        self.assertFalse(self.device.available)

    def test_connect(self):
        self.assertTrue(self.device.connect())
        self.assertTrue(self.device.available)

    def test_close(self):
        self.assertFalse(self.device.close())
        self.assertFalse(self.device.available)

    def test_shell(self):
        self.assertTrue(self.device.connect())

        # Provide the `bulk_read` return values
        msg1 = AdbMessage(command=constants.OPEN, arg0=1, arg1=0, data=b'%s:%s' % (b'shell', 'TEST1234567890123'.encode('utf-8')) + b'\0')
        msg2 = AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'%s:%s' % (b'shell', 'TEST1234567890123'.encode('utf-8')) + b'\0')
        msg3 = AdbMessage(command=constants.CLSE, arg0=1, arg1=0, data=b'%s:%s' % (b'shell', 'TEST1234567890123'.encode('utf-8')) + b'\0')
        self.device._handle.bulk_read_list = [msg1.pack(), msg2.pack(), msg2.data, msg3.pack(), msg3.data]

        self.assertEqual(self.device.shell('TEST'), '')


class TestAdbDeviceWithBanner(TestAdbDevice):
    def setUp(self):
        with patchers.patch_tcp_handle:
            self.device = AdbDevice('IP:5555', 'banner')


class TestAdbDeviceBannerError(TestAdbDevice):
    def setUp(self):
        with patch('socket.gethostname', side_effect=Exception):
            with patchers.patch_tcp_handle:
                self.device = AdbDevice('IP:5555')
