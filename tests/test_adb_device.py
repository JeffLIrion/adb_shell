import logging
from mock import patch
import os
import struct
import sys
import unittest

sys.path.insert(0, '..')
from adb_shell import constants, exceptions
from adb_shell.adb_device import AdbDevice
from adb_shell.adb_message import AdbMessage, unpack
from adb_shell.auth.keygen import keygen
from adb_shell.auth.sign_pythonrsa import PythonRSASigner

try:
    from . import patchers
    from .keygen_stub import open_priv_pub
except:
    import patchers
    from keygen_stub import open_priv_pub


# https://stackoverflow.com/a/7483862
_LOGGER = logging.getLogger('adb_shell.adb_device')
_LOGGER.setLevel(logging.DEBUG)
_LOGGER.addHandler(logging.StreamHandler(sys.stdout))


def to_int(cmd):
    return sum(c << (i * 8) for i, c in enumerate(bytearray(cmd)))


def pack(msg):
    ints = [to_int(msg[4*i:4*(i+1)]) for i in range(6)]
    return struct.pack(b'<6I', *ints)


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

    def test_connect_with_key_invalid_response(self):
        with patch('adb_shell.auth.sign_pythonrsa.open', open_priv_pub), patch('adb_shell.auth.keygen.open', open_priv_pub):
            keygen('tests/adbkey')
            signer = PythonRSASigner.FromRSAKeyPath('tests/adbkey')

        self.device._handle._bulk_read = b''.join(patchers.BULK_READ_LIST_WITH_AUTH_INVALID)

        with self.assertRaises(exceptions.InvalidResponseError):
            self.device.connect([signer])

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
        msg1 = AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'' + b'\0')
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
        msg1 = AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'' + b'\0')
        self.device._handle._bulk_read = msg1.pack()

        with self.assertRaises(exceptions.InvalidCommandError):
            self.device.shell('TEST', total_timeout_s=-1)

    @unittest.skipIf(sys.version_info[0] == 3, "``unittest.testCase.assertLogs`` is not implemented in Python 2.")
    def test_shell_warning_data_length_python2(self):
        self.assertTrue(self.device.connect())

        # Provide the `bulk_read` return values
        msg1 = AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00')
        msg2 = AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'0'*(constants.MAX_ADB_DATA+1))
        msg3 = AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b'')
        self.device._handle._bulk_read = b''.join([msg1.pack(), msg1.data, msg2.pack(), msg2.data, msg3.pack()])

        self.device.shell('TEST')
        self.assertTrue(True)

    @unittest.skipIf(sys.version_info[0] == 2, "``unittest.testCase.assertLogs`` is not implemented in Python 2.")
    def test_shell_warning_data_length_python3(self):
        self.assertTrue(self.device.connect())

        # Provide the `bulk_read` return values
        msg1 = AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00')
        msg2 = AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'0'*(constants.MAX_ADB_DATA+1))
        msg3 = AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b'')
        self.device._handle._bulk_read = b''.join([msg1.pack(), msg1.data, msg2.pack(), msg2.data, msg3.pack()])

        with self.assertLogs(level=logging.WARNING) as logs:
            self.device.shell('TEST')

        assert any(["Data_length 4097 does not match actual number of bytes read: 4096" in output for output in logs.output])

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

    '''def test_shell_issue_136_log1(self):
        # https://github.com/google/python-adb/issues/136#issuecomment-438690462
        # https://pastebin.com/raw/K4CM3kVV
        self.assertTrue(self.device.connect())

        # Provide the `bulk_read` return values
        msg1 = AdbMessage(command=constants.OKAY, arg0=27630, arg1=1, data=b'\x00')
        msg2 = AdbMessage(command=constants.WRTE, arg0=27630, arg1=1, data=b'Display Power: state=OFF\n')
        msg3 = AdbMessage(command=constants.CLSE, arg0=27630, arg1=1, data=b'')
        self.device._handle._bulk_read = b''.join([msg1.pack(), msg1.data, msg2.pack(), msg2.data, msg3.pack()])

        self.device.shell('dumpsys power | grep "Display Power"')
        self.assertTrue(True)'''

    def test_shell_issue_136_log2_3(self):
        # https://github.com/google/python-adb/issues/136#issuecomment-438690462
        # https://pastebin.com/raw/0k1GaNaa
        # https://pastebin.com/raw/q33Qna0u
        # python -m unittest test_adb_device.TestAdbDevice.test_shell_issue_136_log2_3
        self.assertTrue(self.device.connect())

        # Provide the `bulk_read` return values
        msg1 = AdbMessage(command=constants.CLSE, arg0=27630, arg1=1, data=b'')
        msg2 = AdbMessage(command=constants.OKAY, arg0=27640, arg1=1, data=b'')
        msg3 = b'Display Power: state=ON\n'
        self.device._handle._bulk_read = b''.join([msg1.pack(), msg2.pack(), pack(msg3)])

        with self.assertRaises(exceptions.InvalidCommandError):
            self.device.shell('dumpsys power | grep "Display Power"')

    def test_shell_issue_136_log2_3b(self):
        # https://github.com/google/python-adb/issues/136#issuecomment-438690462
        # https://pastebin.com/raw/0k1GaNaa
        # https://pastebin.com/raw/q33Qna0u
        # python -m unittest test_adb_device.TestAdbDevice.test_shell_issue_136_log2_3b
        self.assertTrue(self.device.connect())

        # Provide the `bulk_read` return values
        msg1 = AdbMessage(command=constants.OKAY, arg0=27640, arg1=1, data=b'')
        msg2 = AdbMessage(command=constants.WRTE, arg0=27640, arg1=1, data=b'Display Power: state=ON\n')
        msg3 = AdbMessage(command=constants.CLSE, arg0=27640, arg1=1, data=b'')
        self.device._handle._bulk_read = b''.join([msg1.pack(), msg2.pack(), msg2.data, msg3.pack()])

        self.assertEqual('Display Power: state=ON\n', self.device.shell('dumpsys power | grep "Display Power"'))

    def test_shell_issue_136_log2_3c(self):
        # https://github.com/google/python-adb/issues/136#issuecomment-438690462
        # https://pastebin.com/raw/0k1GaNaa
        # https://pastebin.com/raw/q33Qna0u
        # python -m unittest test_adb_device.TestAdbDevice.test_shell_issue_136_log2_3c
        self.assertTrue(self.device.connect())

        # Provide the `bulk_read` return values
        msg1 = AdbMessage(command=constants.CLSE, arg0=27630, arg1=1, data=b'')
        msg2 = AdbMessage(command=constants.OKAY, arg0=27640, arg1=1, data=b'')
        msg3 = AdbMessage(command=constants.WRTE, arg0=27640, arg1=1, data=b'Display Power: state=ON\n')
        msg4 = AdbMessage(command=constants.CLSE, arg0=27640, arg1=1, data=b'')
        self.device._handle._bulk_read = b''.join([msg1.pack(), msg1.pack(), msg1.pack(), msg2.pack(), msg3.pack(), msg3.data, msg4.pack()])

        self.device.shell('TEST')
        self.assertEqual('Display Power: state=ON\n', self.device.shell('dumpsys power | grep "Display Power"'))

    def test_shell_issue_136_log2_3d(self):
        # https://github.com/google/python-adb/issues/136#issuecomment-438690462
        # https://pastebin.com/raw/0k1GaNaa
        # https://pastebin.com/raw/q33Qna0u
        # python -m unittest test_adb_device.TestAdbDevice.test_shell_issue_136_log2_3d
        self.assertTrue(self.device.connect())

        # Provide the `bulk_read` return values
        msg1 = AdbMessage(command=constants.OKAY, arg0=27640, arg1=1, data=b'')
        msg2 = AdbMessage(command=constants.WRTE, arg0=27640, arg1=1, data=b'Display Power: state=ON\n')
        msg3 = AdbMessage(command=constants.CLSE, arg0=27640, arg1=1, data=b'')
        msg4 = AdbMessage(command=constants.OKAY, arg0=27641, arg1=1, data=b'')
        msg5 = AdbMessage(command=constants.WRTE, arg0=27641, arg1=1, data=b'Display Power: state=ON\n')
        msg6 = AdbMessage(command=constants.CLSE, arg0=27641, arg1=1, data=b'')
        msg7 = AdbMessage(command=constants.OKAY, arg0=27642, arg1=1, data=b'')
        msg8 = AdbMessage(command=constants.WRTE, arg0=27642, arg1=1, data=b'Display Power: state=ON\n')
        msg9 = AdbMessage(command=constants.CLSE, arg0=27642, arg1=1, data=b'')
        self.device._handle._bulk_read = b''.join([msg1.pack(), msg2.pack(), msg2.data, msg3.pack(), msg3.pack(), msg3.pack(), msg4.pack(), msg5.pack(), msg5.data, msg6.pack(), msg6.pack(), msg6.pack(), msg7.pack(), msg8.pack(), msg8.data, msg9.pack()])
        self.device._handle._bulk_read = b''.join([msg1.pack(), msg2.pack(), msg2.data, msg3.pack(), msg4.pack(), msg5.pack(), msg5.data, msg6.pack(), msg7.pack(), msg8.pack(), msg8.data, msg9.pack()])
        self.device._handle._bulk_read = b''.join([msg1.pack(), msg2.pack(), msg2.data, msg3.pack(), msg3.pack(), msg4.pack(), msg5.pack(), msg5.data, msg6.pack(), msg6.pack(), msg7.pack(), msg8.pack(), msg8.data, msg9.pack()])

        self.device.shell('dumpsys power | grep "Display Power"')
        self.device.shell('dumpsys power | grep "Display Power"')
        self.device.shell('dumpsys power | grep "Display Power"')
        '''self.assertEqual('Display Power: state=ON\n', self.device.shell('dumpsys power | grep "Display Power"'))
        self.assertEqual('Display Power: state=ON\n', self.device.shell('dumpsys power | grep "Display Power"'))
        self.assertEqual('Display Power: state=ON\n', self.device.shell('dumpsys power | grep "Display Power"'))'''

    def test_shell_new_logs(self):
        # https://github.com/JeffLIrion/adb_shell/issues/15#issuecomment-536795938
        self.assertTrue(self.device.connect())

        # Provide the `bulk_read` return values
        msg1 = AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'')
        msg2 = AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'PASS')
        msg3 = AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b'')
        self.device._handle._bulk_read = b''.join([msg1.pack(), msg1.data, msg2.pack(), msg2.data, msg3.pack()])
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

        self.device.shell('Update command (success)')
        self.device.shell('Update command (fail)')

    def test_shell_new_logs2(self):
        # https://github.com/JeffLIrion/adb_shell/issues/15#issuecomment-536795938
        self.assertTrue(self.device.connect())

        # Provide the `bulk_read` return values
        msg1 = AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'')
        msg2 = AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'PASS')
        msg3 = AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b'')
        self.device._handle._bulk_read = b''.join([msg1.pack(), msg1.data, msg2.pack(), msg2.data, msg3.pack()])
        self.device._handle._bulk_read = b''.join([b'OKAY\xe9R\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xb0\xb4\xbe\xa6',
                                                   b'WRTE\xe9R\x00\x00\x01\x00\x00\x00\x01\x00\x00\x002\x00\x00\x00\xa8\xad\xab\xba',
                                                   b'2',
                                                   b'WRTE\xe9R\x00\x00\x01\x00\x00\x00\x0c\x02\x00\x00\xbf\x92\x00\x00\xa8\xad\xab\xba',
                                                   b'Wake Locks: size=1\ncom.google.android.tvlauncher\n\n- STREAM_MUSIC:\n   Muted: true\n   Min: 0\n   Max: 15\n   Current: 2 (speaker): 15, 4 (headset): 10, 8 (headphone): 10, 80 (bt_a2dp): 10, 1000 (digital_dock): 10, 4000000 (usb_headset): 3, 40000000 (default): 15\n   Devices: speaker\n- STREAM_ALARM:\n   Muted: true\n   Min: 1\n   Max: 7\n   Current: 2 (speaker): 7, 4 (headset): 5, 8 (headphone): 5, 80 (bt_a2dp): 5, 1000 (digital_dock): 5, 4000000 (usb_headset): 1, 40000000 (default): 7\n   Devices: speaker\n- STREAM_NOTIFICATION:\n',
                                                   b'CLSE\xe9R\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xbc\xb3\xac\xba',
                                                   msg1.pack(),
                                                   b'CLSE\xe9R\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xbc\xb3\xac\xba',
                                                   msg2.pack(),
                                                   msg2.data,
                                                   msg3.pack()])

        self.device.shell('Update command (success)')
        self.device.shell('Update command (fail)')


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
