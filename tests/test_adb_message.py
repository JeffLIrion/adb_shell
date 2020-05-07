import os
import unittest

from unittest.mock import patch

from aio_adb_shell import constants
from aio_adb_shell.adb_device import AdbDevice
from aio_adb_shell.adb_message import AdbMessage, checksum, unpack


def from_int(n):
    return ''.join(chr((n >> (i * 8)) % 256) for i in range(4)).encode('utf-8')


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
            self.assertEqual(key, from_int(val))
