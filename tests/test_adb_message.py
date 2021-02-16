import os
import unittest

try:
    from unittest.mock import patch
except ImportError:
    from mock import patch

from adb_shell import constants
from adb_shell.adb_device import AdbDevice
from adb_shell.adb_message import AdbMessage, checksum, int_to_cmd, unpack


class TestAdbMessage(unittest.TestCase):
    def test_checksum_bytearray(self):
        cs = checksum(bytearray('TEST', 'utf-8'))
        self.assertEqual(cs, 320)

    def test_checksum_bytes(self):
        cs = checksum(b'TEST')
        self.assertEqual(cs, 320)

    def test_checksum_unicode(self):
        cs = checksum(u'TEST')
        self.assertEqual(cs, 320)

    def test_unpack_error(self):
        with self.assertRaises(ValueError):
            unpack(b'TEST')

    def test_constants(self):
        for key, val in constants.ID_TO_WIRE.items():
            self.assertEqual(key, int_to_cmd(val))
