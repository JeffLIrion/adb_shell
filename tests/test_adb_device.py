import logging
from io import BytesIO

from mock import patch
import sys
import unittest

from adb_shell import constants, exceptions
from adb_shell.adb_device import AdbDevice, DeviceFile
from adb_shell.adb_message import AdbMessage
from adb_shell.auth.keygen import keygen
from adb_shell.auth.sign_pythonrsa import PythonRSASigner

from . import patchers
from .filesync_helpers import FileSyncMessage, FileSyncListMessage, FileSyncStatMessage
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

    def test_shell_data_length_exceeds_max(self):
        self.assertTrue(self.device.connect())

        # Provide the `bulk_read` return values
        msg1 = AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00')
        msg2 = AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'0'*(constants.MAX_ADB_DATA+1))
        msg3 = AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b'')
        self.device._handle._bulk_read = b''.join([msg1.pack(), msg1.data, msg2.pack(), msg2.data, msg3.pack()])

        self.device.shell('TEST')
        self.assertTrue(True)

    def test_shell_multibytes_sequence_exceeds_max(self):
        self.assertTrue(self.device.connect())

        # Provide the `bulk_read` return values
        msg1 = AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00')
        msg2 = AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'0'*(constants.MAX_ADB_DATA-1) + b'\xe3\x81\x82')
        msg3 = AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b'')
        self.device._handle._bulk_read = b''.join([msg1.pack(), msg1.data, msg2.pack(), msg2.data, msg3.pack()])

        res = self.device.shell('TEST')
        self.assertEqual(u'0'*(constants.MAX_ADB_DATA-1) + u'\u3042', res)

    def test_shell_with_multibytes_sequence_over_two_messages(self):
        self.assertTrue(self.device.connect())

        # Provide the `bulk_read` return values
        msg1 = AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00')
        msg2 = AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'\xe3')
        msg3 = AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'\x81\x82')
        msg4 = AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b'')
        self.device._handle._bulk_read = b''.join([msg1.pack(), msg1.data, msg2.pack(), msg2.data,
                                                   msg3.pack(), msg3.data, msg4.pack()])

        res = self.device.shell('TEST')
        self.assertEqual(u'\u3042', res)

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

    def test_issue29(self):
        # https://github.com/JeffLIrion/adb_shell/issues/29
        with patch('adb_shell.auth.sign_pythonrsa.open', open_priv_pub), patch('adb_shell.auth.keygen.open', open_priv_pub):
            keygen('tests/adbkey')
            signer = PythonRSASigner.FromRSAKeyPath('tests/adbkey')

        msg1 = AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00')
        msg2 = AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b'')

        self.device._handle._bulk_read = b''.join([b'AUTH\x01\x00\x00\x00\x00\x00\x00\x00\x14\x00\x00\x00\xc5\n\x00\x00\xbe\xaa\xab\xb7',  # Line 22
                                                   b"\x17\xbf\xbf\xff\xc7\xa2eo'Sh\xdf\x8e\xf5\xff\xe0\tJ6H",  # Line 23
                                                   b"CNXN\x00\x00\x00\x01\x00\x10\x00\x00i\x00\x00\x00.'\x00\x00\xbc\xb1\xa7\xb1",  # Line 26
                                                   b'device::ro.product.name=once;ro.product.model=MIBOX3;ro.product.device=once;features=stat_v2,cmd,shell_v2',  # Line 27
                                                   b'OKAY\x99\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xb0\xb4\xbe\xa6',  # Line 290 (modified --> Line 30)
                                                   b'CLSE\xa2\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xbc\xb3\xac\xba',  # Line 291
                                                   b'CLSE\xa2\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xbc\xb3\xac\xba',  # Line 292
                                                   b'WRTE\x99\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x001\x00\x00\x00\xa8\xad\xab\xba',  # Line 31
                                                   b'1',  # Line 32
                                                   b'WRTE\x99\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x001\x00\x00\x00\xa8\xad\xab\xba',  # Line 35
                                                   b'1',  # Line 36
                                                   b'WRTE\x99\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x000\x00\x00\x00\xa8\xad\xab\xba',  # Line 39
                                                   b'0',  # Line 40
                                                   b'WRTE\x99\x00\x00\x00\x01\x00\x00\x00\x13\x00\x00\x000\x06\x00\x00\xa8\xad\xab\xba',  # Line 43
                                                   b'Wake Locks: size=0\n',  # Line 44
                                                   b'WRTE\x99\x00\x00\x00\x01\x00\x00\x00\x1e\x00\x00\x00V\x0b\x00\x00\xa8\xad\xab\xba',  # Line 47
                                                   b'com.google.android.youtube.tv\n',  # Line 48
                                                   b'WRTE\x99\x00\x00\x00\x01\x00\x00\x00\x98\x00\x00\x00\xa13\x00\x00\xa8\xad\xab\xba',  # Line 51
                                                   b'      state=PlaybackState {state=0, position=0, buffered position=0, speed=0.0, updated=0, actions=0, custom actions=[], active item id=-1, error=null}\n',  # Line 52
                                                   b'WRTE\x99\x00\x00\x00\x01\x00\x00\x00.\x01\x00\x00\xceP\x00\x00\xa8\xad\xab\xba',  # Line 55
                                                   b'- STREAM_MUSIC:\n   Muted: false\n   Min: 0\n   Max: 15\n   Current: 2 (speaker): 11, 4 (headset): 10, 8 (headphone): 10, 400 (hdmi): 6, 40000000 (default): 11\n   Devices: hdmi\n- STREAM_ALARM:\n   Muted: false\n   Min: 0\n   Max: 7\n   Current: 40000000 (default): 6\n   Devices: speaker\n- STREAM_NOTIFICATION:\n',  # Line 56
                                                   b'CLSE\x99\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xbc\xb3\xac\xba',  # Line 59
                                                   b'AUTH\x01\x00\x00\x00\x00\x00\x00\x00\x14\x00\x00\x00\x94\t\x00\x00\xbe\xaa\xab\xb7',  # Line 297
                                                   b'P\xa5\x86\x97\xe8\x01\xb09\x8c>F\x9d\xc6\xbd\xc0J\x80!\xbb\x1a',  # Line 298
                                                   b"CNXN\x00\x00\x00\x01\x00\x10\x00\x00i\x00\x00\x00.'\x00\x00\xbc\xb1\xa7\xb1",  # Line 301
                                                   b'device::ro.product.name=once;ro.product.model=MIBOX3;ro.product.device=once;features=stat_v2,cmd,shell_v2',  # Line 302
                                                   b'OKAY\xa5\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xb0\xb4\xbe\xa6',  # Line 305
                                                   b'CLSE\xa5\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xbc\xb3\xac\xba',  # Line 306
                                                   msg1.pack(),
                                                   msg1.data,
                                                   msg2.pack(),
                                                   b'AUTH\x01\x00\x00\x00\x00\x00\x00\x00\x14\x00\x00\x00e\x0c\x00\x00\xbe\xaa\xab\xb7',  # Line 315
                                                   b'\xd3\xef\x7f_\xa6\xc0`b\x19\\z\xe4\xf3\xe2\xed\x8d\xe1W\xfbH',  # Line 316
                                                   b"CNXN\x00\x00\x00\x01\x00\x10\x00\x00i\x00\x00\x00.'\x00\x00\xbc\xb1\xa7\xb1",  # Line 319
                                                   b'device::ro.product.name=once;ro.product.model=MIBOX3;ro.product.device=once;features=stat_v2,cmd,shell_v2',  # Line 320
                                                   b'OKAY\xa7\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xb0\xb4\xbe\xa6',  # Line 323
                                                   b'CLSE\xa7\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xbc\xb3\xac\xba',  # Line 324
                                                   msg1.pack(),
                                                   msg1.data,
                                                   msg2.pack(),
                                                   b'AUTH\x01\x00\x00\x00\x00\x00\x00\x00\x14\x00\x00\x00\x93\x08\x00\x00\xbe\xaa\xab\xb7',  # Line 333
                                                   b's\xd4_e\xa4s\x02\x95\x0f\x1e\xec\n\x95Y9[`\x8e\xe1f',  # Line 334
                                                   b"CNXN\x00\x00\x00\x01\x00\x10\x00\x00i\x00\x00\x00.'\x00\x00\xbc\xb1\xa7\xb1",  # Line 337
                                                   b'device::ro.product.name=once;ro.product.model=MIBOX3;ro.product.device=once;features=stat_v2,cmd,shell_v2',  # Line 338
                                                   b'OKAY\xa9\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xb0\xb4\xbe\xa6',  # Line 341
                                                   b'CLSE\xa9\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xbc\xb3\xac\xba',  # Line 342
                                                   msg1.pack(),
                                                   msg1.data,
                                                   msg2.pack()])

        self.assertTrue(self.device.connect([signer]))

        self.device.shell('Android TV update command')
        
        self.assertTrue(self.device.connect([signer]))
        self.device.shell('Android TV update command')
        self.device.shell('Android TV update command')
        self.assertTrue(self.device.connect([signer]))
        self.device.shell('Android TV update command')
        self.device.shell('Android TV update command')
        self.assertTrue(self.device.connect([signer]))
        self.device.shell('Android TV update command')
        self.device.shell('Android TV update command')

    # ======================================================================= #
    #                                                                         #
    #                         `filesync` tests                                #
    #                                                                         #
    # ======================================================================= #
    def test_list(self):
        # Provide the `bulk_read` return values
        read1 = AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00')
        read2 = AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00')
        read3 = AdbMessage(
            command=constants.WRTE, arg0=1, arg1=1,
            data=b''.join([
                FileSyncListMessage(constants.DENT, 1, 2, 3, data=b'file1').pack() + b'file1',
                FileSyncListMessage(constants.DENT, 4, 5, 6, data=b'file2').pack() + b'file2',
                FileSyncListMessage(constants.DONE, 0, 0, 0).pack(),
            ])
        )
        read4 = AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b'')
        self.device._handle._bulk_read = b''.join([read1.pack(), read1.data,
                                                   read2.pack(), read2.data,
                                                   read3.pack(), read3.data,
                                                   read4.pack(), read4.data])

        # Expected `bulk_write` values
        send1 = AdbMessage(command=constants.OPEN, arg0=1, arg1=0, data=b'sync:\x00')
        send2 = AdbMessage(
            command=constants.WRTE, arg0=1, arg1=1,
            data=FileSyncMessage(command=constants.LIST, data=b'/dir').pack() + b'/dir'
        )
        send3 = AdbMessage(command=constants.OKAY, arg0=1, arg1=1)
        send4 = AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b'')
        expected_bulk_write = b''.join([send1.pack(), send1.data,
                                        send2.pack(), send2.data,
                                        send3.pack(), send3.data,
                                        send4.pack(), send4.data])

        expected_result = [DeviceFile(filename=bytearray(b'file1'), mode=1, size=2, mtime=3),
                          DeviceFile(filename=bytearray(b'file2'), mode=4, size=5, mtime=6)]
        self.assertEqual(expected_result, self.device.list('/dir'))
        self.assertEqual(expected_bulk_write, self.device._handle._bulk_write)

    def test_push(self):
        filedata = b'Ohayou sekai.\nGood morning world!'
        mtime = 100

        # Provide the `bulk_read` return values
        read1 = AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00')
        read2 = AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00')
        read3 = AdbMessage(
            command=constants.WRTE, arg0=1, arg1=1,
            data=FileSyncMessage(constants.OKAY).pack()
        )
        read4 = AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b'')
        self.device._handle._bulk_read = b''.join([read1.pack(), read1.data,
                                                   read2.pack(), read2.data,
                                                   read3.pack(), read3.data,
                                                   read4.pack(), read4.data])

        # Expected `bulk_write` values
        send1 = AdbMessage(command=constants.OPEN, arg0=1, arg1=0, data=b'sync:\x00')
        send2 = AdbMessage(
            command=constants.WRTE, arg0=1, arg1=1,
            data=b''.join([
                FileSyncMessage(command=constants.SEND, data=b'/data,33272').pack() + b'/data,33272',
                FileSyncMessage(command=constants.DATA, data=filedata).pack() + filedata,
                FileSyncMessage(command=constants.DONE, arg0=mtime).pack()
            ])
        )
        send3 = AdbMessage(command=constants.OKAY, arg0=1, arg1=1)
        send4 = AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b'')
        expected_bulk_write = b''.join([send1.pack(), send1.data,
                                        send2.pack(), send2.data,
                                        send3.pack(), send3.data,
                                        send4.pack(), send4.data])

        self.device.push(BytesIO(filedata), '/data', mtime=mtime)

        self.assertEqual(expected_bulk_write, self.device._handle._bulk_write)

    def test_pull(self):
        filedata = b'Ohayou sekai.\nGood morning world!'

        # Provide the `bulk_read` return values
        read1 = AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00')
        read2 = AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00')
        read3 = AdbMessage(
            command=constants.WRTE, arg0=1, arg1=1,
            data=b''.join([
                FileSyncMessage(command=constants.DATA, data=filedata).pack() + filedata,
                FileSyncMessage(command=constants.DONE).pack()
            ])
        )
        read4 = AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b'')
        self.device._handle._bulk_read = b''.join([read1.pack(), read1.data,
                                                   read2.pack(), read2.data,
                                                   read3.pack(), read3.data,
                                                   read4.pack(), read4.data])

        # Expected `bulk_write` values
        send1 = AdbMessage(command=constants.OPEN, arg0=1, arg1=0, data=b'sync:\x00')
        send2 = AdbMessage(
            command=constants.WRTE, arg0=1, arg1=1,
            data=FileSyncMessage(command=constants.RECV, data=b'/data').pack() + b'/data'
        )
        send3 = AdbMessage(command=constants.OKAY, arg0=1, arg1=1)
        send4 = AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b'')
        expected_bulk_write = b''.join([send1.pack(), send1.data,
                                        send2.pack(), send2.data,
                                        send3.pack(), send3.data,
                                        send4.pack(), send4.data])

        self.assertEqual(filedata, self.device.pull('/data'))
        self.assertEqual(expected_bulk_write, self.device._handle._bulk_write)

    def test_stat(self):
        # Provide the `bulk_read` return values
        read1 = AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00')
        read2 = AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00')
        read3 = AdbMessage(
            command=constants.WRTE, arg0=1, arg1=1,
            data=b''.join([
                FileSyncStatMessage(constants.STAT, 1, 2, 3).pack(),
                FileSyncStatMessage(constants.DONE, 0, 0, 0).pack(),
            ])
        )
        read4 = AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b'')
        self.device._handle._bulk_read = b''.join([read1.pack(), read1.data,
                                                   read2.pack(), read2.data,
                                                   read3.pack(), read3.data,
                                                   read4.pack(), read4.data])

        # Expected `bulk_write` values
        send1 = AdbMessage(command=constants.OPEN, arg0=1, arg1=0, data=b'sync:\x00')
        send2 = AdbMessage(
            command=constants.WRTE, arg0=1, arg1=1,
            data=FileSyncMessage(command=constants.STAT, data=b'/data').pack() + b'/data'
        )
        send3 = AdbMessage(command=constants.OKAY, arg0=1, arg1=1)
        send4 = AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b'')
        expected_bulk_write = b''.join([send1.pack(), send1.data,
                                        send2.pack(), send2.data,
                                        send3.pack(), send3.data,
                                        send4.pack(), send4.data])

        self.assertEqual((1, 2, 3), self.device.stat('/data'))
        self.assertEqual(expected_bulk_write, self.device._handle._bulk_write)


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
