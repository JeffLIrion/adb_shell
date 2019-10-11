import logging
from mock import patch
import os
import struct
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


def to_int(cmd):
    return sum(c << (i * 8) for i, c in enumerate(bytearray(cmd)))


class AdbMessageForTesting(AdbMessage):
    def __init__(self, command, arg0=None, arg1=None, data=b''):
        self.command = to_int(command)
        self.magic = self.command ^ 0xFFFFFFFF
        self.arg0 = arg0
        self.arg1 = arg1
        self.data = data


class TestAdbDevice(unittest.TestCase):
    def setUp(self):
        with patchers.patch_tcp_handle:
            self.device = AdbDevice('IP:5555')
            self.device._handle._bulk_read = b''.join(patchers.BULK_READ_LIST)

    def tearDown(self):
        self.assertFalse(self.device._handle._bulk_read)

    def test_init(self):
        device_with_banner = AdbDevice('IP:5555', 'banner')
        self.assertEqual(device_with_banner._banner, 'banner')

        with patch('socket.gethostname', side_effect=Exception):
            device_banner_unknown = AdbDevice('IP:5555')
            self.assertEqual(device_banner_unknown._banner, 'unknown')

        self.device._handle._bulk_read = b''

    def test_available(self):
        self.assertFalse(self.device.available)

        self.device._handle._bulk_read = b''

    def test_close(self):
        self.assertFalse(self.device.close())
        self.assertFalse(self.device.available)

        self.device._handle._bulk_read = b''

    # ======================================================================= #
    #                                                                         #
    #                             `connect` tests                             #
    #                                                                         #
    # ======================================================================= #
    def test_connect(self):
        self.assertTrue(self.device.connect())
        self.assertTrue(self.device.available)

    def test_connect_no_keys(self):
        self.device._handle._bulk_read = b''.join(patchers.BULK_READ_LIST_WITH_AUTH[:2])
        with self.assertRaises(exceptions.DeviceAuthError):
            self.device.connect()

        self.assertFalse(self.device.available)

    def test_connect_with_key_invalid_response(self):
        with patch('adb_shell.auth.sign_pythonrsa.open', open_priv_pub), patch('adb_shell.auth.keygen.open', open_priv_pub):
            keygen('tests/adbkey')
            signer = PythonRSASigner.FromRSAKeyPath('tests/adbkey')

        self.device._handle._bulk_read = b''.join(patchers.BULK_READ_LIST_WITH_AUTH_INVALID)

        with self.assertRaises(exceptions.InvalidResponseError):
            self.device.connect([signer])

        self.assertFalse(self.device.available)

    def test_connect_with_key(self):
        with patch('adb_shell.auth.sign_pythonrsa.open', open_priv_pub), patch('adb_shell.auth.keygen.open', open_priv_pub):
            keygen('tests/adbkey')
            signer = PythonRSASigner.FromRSAKeyPath('tests/adbkey')

        self.device._handle._bulk_read = b''.join(patchers.BULK_READ_LIST_WITH_AUTH)

        self.assertTrue(self.device.connect([signer]))

    def test_connect_with_new_key(self):
        with patch('adb_shell.auth.sign_pythonrsa.open', open_priv_pub), patch('adb_shell.auth.keygen.open', open_priv_pub):
            keygen('tests/adbkey')
            signer = PythonRSASigner.FromRSAKeyPath('tests/adbkey')

        self.device._handle._bulk_read = b''.join(patchers.BULK_READ_LIST_WITH_AUTH_NEW_KEY)

        self.assertTrue(self.device.connect([signer]))

    # ======================================================================= #
    #                                                                         #
    #                              `shell` tests                              #
    #                                                                         #
    # ======================================================================= #
    def test_shell_no_return(self):
        self.assertTrue(self.device.connect())

        # Provide the `bulk_read` return values
        msg1 = AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00')
        msg2 = AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b'')
        self.device._handle._bulk_read = b''.join([msg1.pack(), msg1.data, msg2.pack()])

        self.assertEqual(self.device.shell('TEST'), '')

    def test_shell_return_pass(self):
        self.assertTrue(self.device.connect())

        # Provide the `bulk_read` return values
        msg1 = AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00')
        msg2 = AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'PA')
        msg3 = AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'SS')
        msg4 = AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b'')
        self.device._handle._bulk_read = b''.join([msg1.pack(), msg1.data, msg2.pack(), msg2.data, msg3.pack(), msg3.data, msg4.pack()])

        self.assertEqual(self.device.shell('TEST'), 'PASS')

    def test_shell_multiple_clse(self):
        # https://github.com/JeffLIrion/adb_shell/issues/15#issuecomment-536795938
        self.assertTrue(self.device.connect())

        # Provide the `bulk_read` return values
        msg1 = AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'')
        msg2 = AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'PASS')
        msg3 = AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b'')
        self.device._handle._bulk_read = b''.join([b'OKAY\xd9R\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xb0\xb4\xbe\xa6',
                                                   b'WRTE\xd9R\x00\x00\x01\x00\x00\x00\x01\x00\x00\x002\x00\x00\x00\xa8\xad\xab\xba',
                                                   b'2',
                                                   b'WRTE\xd9R\x00\x00\x01\x00\x00\x00\x0c\x02\x00\x00\xc0\x92\x00\x00\xa8\xad\xab\xba',
                                                   b'Wake Locks: size=2\ncom.google.android.tvlauncher\n\n- STREAM_MUSIC:\n   Muted: true\n   Min: 0\n   Max: 15\n   Current: 2 (speaker): 15, 4 (headset): 10, 8 (headphone): 10, 80 (bt_a2dp): 10, 1000 (digital_dock): 10, 4000000 (usb_headset): 3, 40000000 (default): 15\n   Devices: speaker\n- STREAM_ALARM:\n   Muted: true\n   Min: 1\n   Max: 7\n   Current: 2 (speaker): 7, 4 (headset): 5, 8 (headphone): 5, 80 (bt_a2dp): 5, 1000 (digital_dock): 5, 4000000 (usb_headset): 1, 40000000 (default): 7\n   Devices: speaker\n- STREAM_NOTIFICATION:\n',
                                                   b'CLSE\xd9R\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xbc\xb3\xac\xba',
                                                   msg1.pack(),
                                                   b'CLSE\xdaR\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xbc\xb3\xac\xba',
                                                   msg2.pack(),
                                                   msg2.data,
                                                   msg3.pack()])

        self.device.shell("dumpsys power | grep 'Display Power' | grep -q 'state=ON' && echo -e '1\\c' && dumpsys power | grep mWakefulness | grep -q Awake && echo -e '1\\c' && dumpsys audio | grep paused | grep -qv 'Buffer Queue' && echo -e '1\\c' || (dumpsys audio | grep started | grep -qv 'Buffer Queue' && echo '2\\c' || echo '0\\c') && dumpsys power | grep Locks | grep 'size=' && CURRENT_APP=$(dumpsys window windows | grep mCurrentFocus) && CURRENT_APP=${CURRENT_APP#*{* * } && CURRENT_APP=${CURRENT_APP%%/*} && echo $CURRENT_APP && (dumpsys media_session | grep -A 100 'Sessions Stack' | grep -A 100 $CURRENT_APP | grep -m 1 'state=PlaybackState {' || echo) && dumpsys audio | grep '\\- STREAM_MUSIC:' -A 12")
        self.assertEqual(self.device.shell('TEST'), 'PASS')

    # ======================================================================= #
    #                                                                         #
    #                           `shell` error tests                           #
    #                                                                         #
    # ======================================================================= #
    def test_shell_error_local_id(self):
        self.assertTrue(self.device.connect())

        # Provide the `bulk_read` return values
        msg1 = AdbMessage(command=constants.OKAY, arg0=1, arg1=1234, data=b'\x00')
        self.device._handle._bulk_read = b''.join([msg1.pack(), msg1.data])

        with self.assertRaises(exceptions.InvalidResponseError):
            self.device.shell('TEST')

    def test_shell_error_clse(self):
        self.assertTrue(self.device.connect())

        # Provide the `bulk_read` return values
        msg1 = AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b'\x00')
        msg2 = AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b'\x00')
        self.device._handle._bulk_read = b''.join([msg1.pack(), msg1.data, msg2.pack(), msg2.data])

        self.assertEqual(self.device.shell('TEST'), '')

    def test_shell_error_unknown_command(self):
        self.assertTrue(self.device.connect())

        # Provide the `bulk_read` return values
        msg1 = AdbMessageForTesting(command=constants.FAIL, arg0=1, arg1=1, data=b'\x00')
        self.device._handle._bulk_read = msg1.pack()

        with self.assertRaises(exceptions.InvalidCommandError):
            self.assertEqual(self.device.shell('TEST'), '')

    def test_shell_error_timeout(self):
        self.assertTrue(self.device.connect())

        # Provide the `bulk_read` return values
        msg1 = AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'')
        self.device._handle._bulk_read = msg1.pack()

        with self.assertRaises(exceptions.InvalidCommandError):
            self.device.shell('TEST', total_timeout_s=-1)

    def test_shell_error_timeout_multiple_clse(self):
        self.assertTrue(self.device.connect())

        # Provide the `bulk_read` return values
        msg1 = AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'')
        msg2 = AdbMessage(command=constants.CLSE, arg0=2, arg1=1, data=b'')
        self.device._handle._bulk_read = b''.join([msg1.pack(), msg2.pack()])

        with self.assertRaises(exceptions.InvalidCommandError):
            self.device.shell('TEST', total_timeout_s=-1)

    def test_shell_data_length_exceeds_max(self):
        self.assertTrue(self.device.connect())

        # Provide the `bulk_read` return values
        msg1 = AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00')
        msg2 = AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'0'*(constants.MAX_ADB_DATA+1))
        msg3 = AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b'')
        self.device._handle._bulk_read = b''.join([msg1.pack(), msg1.data, msg2.pack(), msg2.data, msg3.pack()])

        self.device.shell('TEST')
        self.assertTrue(True)

    def test_shell_error_checksum(self):
        self.assertTrue(self.device.connect())

        # Provide the `bulk_read` return values
        msg1 = AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00')
        msg2 = AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'PASS')
        self.device._handle._bulk_read = b''.join([msg1.pack(), msg1.data, msg2.pack(), msg2.data[:-1] + b'0'])

        with self.assertRaises(exceptions.InvalidChecksumError):
            self.device.shell('TEST')

    def test_shell_error_local_id2(self):
        self.assertTrue(self.device.connect())

        # Provide the `bulk_read` return values
        msg1 = AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00')
        msg2 = AdbMessage(command=constants.WRTE, arg0=1, arg1=2, data=b'PASS')
        self.device._handle._bulk_read = b''.join([msg1.pack(), msg1.data, msg2.pack(), msg2.data])

        with self.assertRaises(exceptions.InterleavedDataError):
            self.device.shell('TEST')
            self.device.shell('TEST')

    def test_shell_error_remote_id2(self):
        self.assertTrue(self.device.connect())

        # Provide the `bulk_read` return values
        msg1 = AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00')
        msg2 = AdbMessage(command=constants.WRTE, arg0=2, arg1=1, data=b'PASS')
        self.device._handle._bulk_read = b''.join([msg1.pack(), msg1.data, msg2.pack(), msg2.data])

        with self.assertRaises(exceptions.InvalidResponseError):
            self.device.shell('TEST')


class TestAdbDeviceWithBanner(TestAdbDevice):
    def setUp(self):
        with patchers.patch_tcp_handle:
            self.device = AdbDevice('IP:5555', 'banner')
            self.device._handle._bulk_read = b''.join(patchers.BULK_READ_LIST)


class TestAdbDeviceBannerError(TestAdbDevice):
    def setUp(self):
        with patch('socket.gethostname', side_effect=Exception):
            with patchers.patch_tcp_handle:
                self.device = AdbDevice('IP:5555')
                self.device._handle._bulk_read = b''.join(patchers.BULK_READ_LIST)
