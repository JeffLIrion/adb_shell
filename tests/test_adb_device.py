from mock import patch
import os
import unittest

from adb_shell.adb_device import AdbDevice


class TestAdbDevice(unittest.TestCase):
    def setUp(self):
        self.device = AdbDevice('IP:PORT')

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
