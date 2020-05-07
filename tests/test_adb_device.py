import asyncio
import logging
from io import BytesIO
import sys
import unittest
from unittest.mock import mock_open, patch

from aio_adb_shell import constants, exceptions
from aio_adb_shell.adb_device import AdbDevice, AdbDeviceTcp, DeviceFile
from aio_adb_shell.adb_message import AdbMessage
from aio_adb_shell.auth.keygen import keygen
from aio_adb_shell.auth.sign_pythonrsa import PythonRSASigner

from . import patchers
from .async_wrapper import awaiter
from .filesync_helpers import FileSyncMessage, FileSyncListMessage, FileSyncStatMessage
from .keygen_stub import open_priv_pub


# https://stackoverflow.com/a/7483862
_LOGGER = logging.getLogger('aio_adb_shell.adb_device')
_LOGGER.setLevel(logging.DEBUG)
_LOGGER.addHandler(logging.StreamHandler(sys.stdout))


def to_int(cmd):
    return sum(c << (i * 8) for i, c in enumerate(bytearray(cmd)))

def join_messages(*messages):
    return b''.join([message.pack() + message.data for message in messages])


class AdbMessageForTesting(AdbMessage):
    def __init__(self, command, arg0=None, arg1=None, data=b''):
        self.command = to_int(command)
        self.magic = self.command ^ 0xFFFFFFFF
        self.arg0 = arg0
        self.arg1 = arg1
        self.data = data


class TestAdbDevice(unittest.TestCase):
    def setUp(self):
        self.device = AdbDevice(handle=patchers.FakeTcpHandle('host', 5555))
        self.device._handle._bulk_read = b''.join(patchers.BULK_READ_LIST)

    def tearDown(self):
        self.assertFalse(self.device._handle._bulk_read)

    @awaiter
    async def test_adb_connection_error(self):
        with self.assertRaises(exceptions.AdbConnectionError):
            await self.device.shell('FAIL')

        with self.assertRaises(exceptions.AdbConnectionError):
            async_generator = self.device.streaming_shell('FAIL')
            await async_generator.__anext__()

        with self.assertRaises(exceptions.AdbConnectionError):
            await self.device.list('FAIL')

        with self.assertRaises(exceptions.AdbConnectionError):
            await self.device.push('FAIL', 'FAIL')

        with self.assertRaises(exceptions.AdbConnectionError):
            await self.device.pull('FAIL', 'FAIL')

        with self.assertRaises(exceptions.AdbConnectionError):
            await self.device.stat('FAIL')

        self.device._handle._bulk_read = b''

    @awaiter
    async def test_init_tcp(self):
        with patchers.PATCH_TCP_HANDLE:
            tcp_device = AdbDeviceTcp('host')
            tcp_device._handle._bulk_read = self.device._handle._bulk_read

        # Make sure that the `connect()` method works
        self.assertTrue(await tcp_device.connect())
        self.assertTrue(tcp_device.available)

        # Clear the `_bulk_read` buffer so that `self.tearDown()` passes
        self.device._handle._bulk_read = b''
        

    @awaiter
    async def test_init_banner(self):
        device_with_banner = AdbDevice(handle=patchers.FakeTcpHandle('host', 5555), banner='banner')
        self.assertEqual(device_with_banner._banner, b'banner')

        device_with_banner2 = AdbDevice(handle=patchers.FakeTcpHandle('host', 5555), banner=bytearray('banner2', 'utf-8'))
        self.assertEqual(device_with_banner2._banner, b'banner2')

        device_with_banner3 = AdbDevice(handle=patchers.FakeTcpHandle('host', 5555), banner=u'banner3')
        self.assertEqual(device_with_banner3._banner, b'banner3')

        with patch('socket.gethostname', side_effect=Exception):
            device_banner_unknown = AdbDevice(handle=patchers.FakeTcpHandle('host', 5555))
            self.assertEqual(device_banner_unknown._banner, b'unknown')

        # Clear the `_bulk_read` buffer so that `self.tearDown()` passes
        self.device._handle._bulk_read = b''

    @awaiter
    async def test_init_invalid_handle(self):
        with self.assertRaises(exceptions.InvalidHandleError):
            device = AdbDevice(handle=123)

        # Clear the `_bulk_read` buffer so that `self.tearDown()` passes
        self.device._handle._bulk_read = b''

    @awaiter
    async def test_available(self):
        self.assertFalse(self.device.available)

        # Clear the `_bulk_read` buffer so that `self.tearDown()` passes
        self.device._handle._bulk_read = b''

    @awaiter
    async def test_close(self):
        self.assertFalse(await self.device.close())
        self.assertFalse(self.device.available)

        # Clear the `_bulk_read` buffer so that `self.tearDown()` passes
        self.device._handle._bulk_read = b''

    # ======================================================================= #
    #                                                                         #
    #                             `connect` tests                             #
    #                                                                         #
    # ======================================================================= #
    @awaiter
    async def test_connect(self):
        self.assertTrue(await self.device.connect())
        self.assertTrue(self.device.available)

    @awaiter
    async def test_connect_no_keys(self):
        self.device._handle._bulk_read = b''.join(patchers.BULK_READ_LIST_WITH_AUTH[:2])
        with self.assertRaises(exceptions.DeviceAuthError):
            await self.device.connect()

        self.assertFalse(self.device.available)

    @awaiter
    async def test_connect_with_key_invalid_response(self):
        with patch('aio_adb_shell.auth.sign_pythonrsa.open', open_priv_pub), patch('aio_adb_shell.auth.keygen.open', open_priv_pub):
            keygen('tests/adbkey')
            signer = PythonRSASigner.FromRSAKeyPath('tests/adbkey')

        self.device._handle._bulk_read = b''.join(patchers.BULK_READ_LIST_WITH_AUTH_INVALID)

        with self.assertRaises(exceptions.InvalidResponseError):
            await self.device.connect([signer])

        self.assertFalse(self.device.available)

    @awaiter
    async def test_connect_with_key(self):
        with patch('aio_adb_shell.auth.sign_pythonrsa.open', open_priv_pub), patch('aio_adb_shell.auth.keygen.open', open_priv_pub):
            keygen('tests/adbkey')
            signer = PythonRSASigner.FromRSAKeyPath('tests/adbkey')

        self.device._handle._bulk_read = b''.join(patchers.BULK_READ_LIST_WITH_AUTH)

        self.assertTrue(await self.device.connect([signer]))

    @awaiter
    async def test_connect_with_new_key(self):
        with patch('aio_adb_shell.auth.sign_pythonrsa.open', open_priv_pub), patch('aio_adb_shell.auth.keygen.open', open_priv_pub):
            keygen('tests/adbkey')
            signer = PythonRSASigner.FromRSAKeyPath('tests/adbkey')
            signer.pub_key = u''

        self.device._handle._bulk_read = b''.join(patchers.BULK_READ_LIST_WITH_AUTH_NEW_KEY)

        self.assertTrue(await self.device.connect([signer]))

    @awaiter
    async def test_connect_with_new_key_and_callback(self):
        with patch('aio_adb_shell.auth.sign_pythonrsa.open', open_priv_pub), patch('aio_adb_shell.auth.keygen.open', open_priv_pub):
            keygen('tests/adbkey')
            signer = PythonRSASigner.FromRSAKeyPath('tests/adbkey')
            signer.pub_key = u''

        self._callback_invoked = False
        def auth_callback(device):
            self._callback_invoked = True

        self.device._handle._bulk_read = b''.join(patchers.BULK_READ_LIST_WITH_AUTH_NEW_KEY)

        self.assertTrue(await self.device.connect([signer], auth_callback=auth_callback))
        self.assertTrue(self._callback_invoked)


    # ======================================================================= #
    #                                                                         #
    #                              `shell` tests                              #
    #                                                                         #
    # ======================================================================= #
    @awaiter
    async def test_shell_no_return(self):
        self.assertTrue(await self.device.connect())

        # Provide the `bulk_read` return values
        self.device._handle._bulk_read = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                       AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b''))

        self.assertEqual(await self.device.shell('TEST'), '')

    @awaiter
    async def test_shell_return_pass(self):
        self.assertTrue(await self.device.connect())

        # Provide the `bulk_read` return values
        self.device._handle._bulk_read = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                       AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'PA'),
                                                       AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'SS'),
                                                       AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b''))

        self.assertEqual(await self.device.shell('TEST'), 'PASS')

    @awaiter
    async def test_shell_dont_decode(self):
        self.assertTrue(await self.device.connect())
        
        # Provide the `bulk_read` return values
        self.device._handle._bulk_read = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                       AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'PA'),
                                                       AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'SS'),
                                                       AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b''))

        self.assertEqual(await self.device.shell('TEST', decode=False), b'PASS')

    @awaiter
    async def test_shell_data_length_exceeds_max(self):
        self.assertTrue(await self.device.connect())

        # Provide the `bulk_read` return values
        self.device._handle._bulk_read = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                       AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'0'*(constants.MAX_ADB_DATA+1)),
                                                       AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b''))

        await self.device.shell('TEST')
        self.assertTrue(True)

    @awaiter
    async def test_shell_multibytes_sequence_exceeds_max(self):
        self.assertTrue(await self.device.connect())

        # Provide the `bulk_read` return values
        self.device._handle._bulk_read = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                       AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'0'*(constants.MAX_ADB_DATA-1) + b'\xe3\x81\x82'),
                                                       AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b''))

        self.assertEqual(await self.device.shell('TEST'), u'0'*(constants.MAX_ADB_DATA-1) + u'\u3042')

    @awaiter
    async def test_shell_with_multibytes_sequence_over_two_messages(self):
        self.assertTrue(await self.device.connect())

        # Provide the `bulk_read` return values
        self.device._handle._bulk_read = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                       AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'\xe3'),
                                                       AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'\x81\x82'),
                                                       AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b''))

        self.assertEqual(await self.device.shell('TEST'), u'\u3042')

    @awaiter
    async def test_shell_multiple_clse(self):
        # https://github.com/JeffLIrion/aio_adb_shell/issues/15#issuecomment-536795938
        self.assertTrue(await self.device.connect())

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

        await self.device.shell("dumpsys power | grep 'Display Power' | grep -q 'state=ON' && echo -e '1\\c' && dumpsys power | grep mWakefulness | grep -q Awake && echo -e '1\\c' && dumpsys audio | grep paused | grep -qv 'Buffer Queue' && echo -e '1\\c' || (dumpsys audio | grep started | grep -qv 'Buffer Queue' && echo '2\\c' || echo '0\\c') && dumpsys power | grep Locks | grep 'size=' && CURRENT_APP=$(dumpsys window windows | grep mCurrentFocus) && CURRENT_APP=${CURRENT_APP#*{* * } && CURRENT_APP=${CURRENT_APP%%/*} && echo $CURRENT_APP && (dumpsys media_session | grep -A 100 'Sessions Stack' | grep -A 100 $CURRENT_APP | grep -m 1 'state=PlaybackState {' || echo) && dumpsys audio | grep '\\- STREAM_MUSIC:' -A 12")
        self.assertEqual(await self.device.shell('TEST'), 'PASS')

    # ======================================================================= #
    #                                                                         #
    #                           `shell` error tests                           #
    #                                                                         #
    # ======================================================================= #
    @awaiter
    async def test_shell_error_local_id(self):
        self.assertTrue(await self.device.connect())

        # Provide the `bulk_read` return values
        self.device._handle._bulk_read = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1234, data=b'\x00'))

        with self.assertRaises(exceptions.InvalidResponseError):
            await self.device.shell('TEST')

    @awaiter
    async def test_shell_error_unknown_command(self):
        self.assertTrue(await self.device.connect())

        # Provide the `bulk_read` return values
        self.device._handle._bulk_read = join_messages(AdbMessageForTesting(command=constants.FAIL, arg0=1, arg1=1, data=b''))

        with self.assertRaises(exceptions.InvalidCommandError):
            self.assertEqual(await self.device.shell('TEST'), '')

    @awaiter
    async def test_shell_error_timeout(self):
        self.assertTrue(await self.device.connect())

        # Provide the `bulk_read` return values
        self.device._handle._bulk_read = join_messages(AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b''))

        with self.assertRaises(exceptions.InvalidCommandError):
            await self.device.shell('TEST', total_timeout_s=-1)

    @awaiter
    async def test_shell_error_timeout_multiple_clse(self):
        self.assertTrue(await self.device.connect())

        # Provide the `bulk_read` return values
        self.device._handle._bulk_read = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b''),
                                                       AdbMessage(command=constants.CLSE, arg0=2, arg1=1, data=b''))

        with self.assertRaises(exceptions.InvalidCommandError):
            await self.device.shell('TEST', total_timeout_s=-1)

    @awaiter
    async def test_shell_error_checksum(self):
        self.assertTrue(await self.device.connect())

        # Provide the `bulk_read` return values
        msg1 = AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00')
        msg2 = AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'PASS')
        self.device._handle._bulk_read = b''.join([msg1.pack(), msg1.data, msg2.pack(), msg2.data[:-1] + b'0'])

        with self.assertRaises(exceptions.InvalidChecksumError):
            await self.device.shell('TEST')

    @awaiter
    async def test_shell_error_local_id2(self):
        self.assertTrue(await self.device.connect())

        # Provide the `bulk_read` return values
        self.device._handle._bulk_read = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                       AdbMessage(command=constants.WRTE, arg0=1, arg1=2, data=b'PASS'))

        with self.assertRaises(exceptions.InterleavedDataError):
            await self.device.shell('TEST')
            await self.device.shell('TEST')

    @awaiter
    async def test_shell_error_remote_id2(self):
        self.assertTrue(await self.device.connect())

        # Provide the `bulk_read` return values
        self.device._handle._bulk_read = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                       AdbMessage(command=constants.WRTE, arg0=2, arg1=1, data=b'PASS'))

        with self.assertRaises(exceptions.InvalidResponseError):
            await self.device.shell('TEST')

    @awaiter
    async def test_issue29(self):
        # https://github.com/JeffLIrion/aio_adb_shell/issues/29
        with patch('aio_adb_shell.auth.sign_pythonrsa.open', open_priv_pub), patch('aio_adb_shell.auth.keygen.open', open_priv_pub):
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

        self.assertTrue(await self.device.connect([signer]))

        await self.device.shell('Android TV update command')
        
        self.assertTrue(await self.device.connect([signer]))
        await self.device.shell('Android TV update command')
        await self.device.shell('Android TV update command')
        self.assertTrue(await self.device.connect([signer]))
        await self.device.shell('Android TV update command')
        await self.device.shell('Android TV update command')
        self.assertTrue(await self.device.connect([signer]))
        await self.device.shell('Android TV update command')
        await self.device.shell('Android TV update command')

    # ======================================================================= #
    #                                                                         #
    #                      `streaming_shell` tests                            #
    #                                                                         #
    # ======================================================================= #
    @awaiter
    async def test_streaming_shell_decode(self):
        self.assertTrue(await self.device.connect())

        # Provide the `bulk_read` return values
        self.device._handle._bulk_read = join_messages(
            AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
            AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'ABC'),
            AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'123'),
        )

        async_generator = self.device.streaming_shell('TEST', decode=True)
        self.assertEqual(await async_generator.__anext__(), 'ABC')
        self.assertEqual(await async_generator.__anext__(), '123')

    @awaiter
    async def test_streaming_shell_dont_decode(self):
        self.assertTrue(await self.device.connect())

        # Provide the `bulk_read` return values
        self.device._handle._bulk_read = join_messages(
            AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
            AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'ABC'),
            AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'123'),
        )

        async_generator = self.device.streaming_shell('TEST', decode=False)
        self.assertEqual(await async_generator.__anext__(), b'ABC')
        self.assertEqual(await async_generator.__anext__(), b'123')


    # ======================================================================= #
    #                                                                         #
    #                         `filesync` tests                                #
    #                                                                         #
    # ======================================================================= #
    @awaiter
    async def test_list(self):
        self.assertTrue(await self.device.connect())
        self.device._handle._bulk_write = b''

        # Provide the `bulk_read` return values
        self.device._handle._bulk_read = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                       AdbMessage(command=constants.OKAY, arg0=1, arg1=1),
                                                       AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=join_messages(FileSyncListMessage(constants.DENT, 1, 2, 3, data=b'file1'),
                                                                                                                             FileSyncListMessage(constants.DENT, 4, 5, 6, data=b'file2'),
                                                                                                                             FileSyncListMessage(constants.DONE, 0, 0, 0))),
                                                       AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b''))

        # Expected `bulk_write` values
        expected_bulk_write = join_messages(AdbMessage(command=constants.OPEN, arg0=1, arg1=0, data=b'sync:\x00'),
                                            AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=join_messages(FileSyncMessage(command=constants.LIST, data=b'/dir'))),
                                            AdbMessage(command=constants.OKAY, arg0=1, arg1=1),
                                            AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b''))

        expected_result = [DeviceFile(filename=bytearray(b'file1'), mode=1, size=2, mtime=3),
                           DeviceFile(filename=bytearray(b'file2'), mode=4, size=5, mtime=6)]

        self.assertEqual(await self.device.list('/dir'), expected_result)
        self.assertEqual(self.device._handle._bulk_write, expected_bulk_write)

    async def _test_push(self, mtime):
        self.assertTrue(await self.device.connect())
        self.device._handle._bulk_write = b''

        filedata = b'Ohayou sekai.\nGood morning world!'

        # Provide the `bulk_read` return values
        self.device._handle._bulk_read = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                       AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b''),
                                                       AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=join_messages(FileSyncMessage(constants.OKAY, data=b''))),
                                                       AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b''))

        # Expected `bulk_write` values
        expected_bulk_write = join_messages(AdbMessage(command=constants.OPEN, arg0=1, arg1=0, data=b'sync:\x00'),
                                            AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=join_messages(FileSyncMessage(command=constants.SEND, data=b'/data,33272'),
                                                                                                                  FileSyncMessage(command=constants.DATA, data=filedata),
                                                                                                                  FileSyncMessage(command=constants.DONE, arg0=mtime))),
                                            AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b''),
                                            AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b''))

        with patch('time.time', return_value=mtime):
            await self.device.push(BytesIO(filedata), '/data', mtime=mtime)
            self.assertEqual(self.device._handle._bulk_write, expected_bulk_write)

        return True

    @awaiter
    async def test_push(self):
        self.assertTrue(await self._test_push(100))

    @awaiter
    async def test_push_mtime0(self):
        self.assertTrue(await self._test_push(0))

    @awaiter
    async def test_push_file(self):
        self.assertTrue(await self.device.connect())
        self.device._handle._bulk_write = b''

        mtime = 100
        filedata = b'Ohayou sekai.\nGood morning world!'

        # Provide the `bulk_read` return values
        self.device._handle._bulk_read = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                       AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b''),
                                                       AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=FileSyncMessage(constants.OKAY).pack()),
                                                       AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b''))

        # Expected `bulk_write` values
        expected_bulk_write = join_messages(AdbMessage(command=constants.OPEN, arg0=1, arg1=0, data=b'sync:\x00'),
                                            AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=join_messages(FileSyncMessage(command=constants.SEND, data=b'/data,33272'),
                                                                                                                  FileSyncMessage(command=constants.DATA, data=filedata),
                                                                                                                  FileSyncMessage(command=constants.DONE, arg0=mtime, data=b''))),
                                            AdbMessage(command=constants.OKAY, arg0=1, arg1=1),
                                            AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b''))

        with patch('aio_adb_shell.adb_device.open', mock_open(read_data=filedata)):
            await self.device.push('TEST_FILE', '/data', mtime=mtime)
            self.assertEqual(self.device._handle._bulk_write, expected_bulk_write)

    @awaiter
    async def test_push_fail(self):
        self.assertTrue(await self.device.connect())
        self.device._handle._bulk_write = b''

        mtime = 100
        filedata = b'Ohayou sekai.\nGood morning world!'

        # Provide the `bulk_read` return values
        self.device._handle._bulk_read = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                       AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b''),
                                                       AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=join_messages(FileSyncMessage(constants.FAIL, data=b''))))

        with self.assertRaises(exceptions.PushFailedError), patch('aio_adb_shell.adb_device.open', mock_open(read_data=filedata)):
            await self.device.push('TEST_FILE', '/data', mtime=mtime)

    @awaiter
    async def test_push_big_file(self):
        self.assertTrue(await self.device.connect())
        self.device._handle._bulk_write = b''

        mtime = 100
        filedata = b'0' * int(3.5 * constants.MAX_PUSH_DATA)

        # Provide the `bulk_read` return values
        self.device._handle._bulk_read = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                       AdbMessage(command=constants.OKAY, arg0=1, arg1=1),
                                                       AdbMessage(command=constants.OKAY, arg0=1, arg1=1),
                                                       AdbMessage(command=constants.OKAY, arg0=1, arg1=1),
                                                       AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=join_messages(FileSyncMessage(constants.OKAY))),
                                                       AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b''))

        # Expected `bulk_write` values
        mpd0, mpd1, mpd2, mpd3 = 0, constants.MAX_PUSH_DATA, 2*constants.MAX_PUSH_DATA, 3*constants.MAX_PUSH_DATA
        expected_bulk_write = join_messages(AdbMessage(command=constants.OPEN, arg0=1, arg1=0, data=b'sync:\x00'),
                                            AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=join_messages(FileSyncMessage(command=constants.SEND, data=b'/data,33272'),
                                                                                                                  FileSyncMessage(command=constants.DATA, data=filedata[mpd0:mpd1]))),
                                            AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=join_messages(FileSyncMessage(command=constants.DATA, data=filedata[mpd1:mpd2]))),
                                            AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=join_messages(FileSyncMessage(command=constants.DATA, data=filedata[mpd2:mpd3]),
                                                                                                                  FileSyncMessage(command=constants.DATA, data=filedata[mpd3:]),
                                                                                                                  FileSyncMessage(command=constants.DONE, arg0=mtime))),
                                            AdbMessage(command=constants.OKAY, arg0=1, arg1=1),
                                            AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b''))

        await self.device.push(BytesIO(filedata), '/data', mtime=mtime)
        self.assertEqual(self.device._handle._bulk_write, expected_bulk_write)

    @awaiter
    async def test_push_dir(self):
        self.assertTrue(await self.device.connect())

        mtime = 100
        filedata = b'Ohayou sekai.\nGood morning world!'

        # Provide the `bulk_read` return values
        self.device._handle._bulk_read = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                       AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b''),
                                                       AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                       AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                       AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=join_messages(FileSyncMessage(constants.OKAY))),
                                                       AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b''),
                                                       AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                       AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                       AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=join_messages(FileSyncMessage(constants.OKAY))),
                                                       AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b''))

        # Expected `bulk_write` values
        #TODO

        with patch('aio_adb_shell.adb_device.open', mock_open(read_data=filedata)), patch('os.path.isdir', lambda x: x == 'TEST_DIR/'), patch('os.listdir', return_value=['TEST_FILE1', 'TEST_FILE2']):
            await self.device.push('TEST_DIR/', '/data', mtime=mtime)

    @awaiter
    async def test_pull(self):
        self.assertTrue(await self.device.connect())
        self.device._handle._bulk_write = b''

        filedata = b'Ohayou sekai.\nGood morning world!'

        # Provide the `bulk_read` return values
        self.device._handle._bulk_read = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                       AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                       AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=join_messages(FileSyncMessage(command=constants.DATA, data=filedata),
                                                                                                                             FileSyncMessage(command=constants.DONE))),
                                                       AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b''))

        # Expected `bulk_write` values
        expected_bulk_write = join_messages(AdbMessage(command=constants.OPEN, arg0=1, arg1=0, data=b'sync:\x00'),
                                            AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=join_messages(FileSyncMessage(command=constants.RECV, data=b'/data'))),
                                            AdbMessage(command=constants.OKAY, arg0=1, arg1=1),
                                            AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b''))

        self.assertEqual(await self.device.pull('/data'), filedata)
        self.assertEqual(self.device._handle._bulk_write, expected_bulk_write)

    @awaiter
    async def test_pull_file(self):
        self.assertTrue(await self.device.connect())
        self.device._handle._bulk_write = b''

        filedata = b'Ohayou sekai.\nGood morning world!'

        # Provide the `bulk_read` return values
        self.device._handle._bulk_read = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                       AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                       AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=join_messages(FileSyncMessage(command=constants.DATA, data=filedata),
                                                                                                                             FileSyncMessage(command=constants.DONE))),
                                                       AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b''))

        # Expected `bulk_write` values
        expected_bulk_write = join_messages(AdbMessage(command=constants.OPEN, arg0=1, arg1=0, data=b'sync:\x00'),
                                            AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=join_messages(FileSyncMessage(command=constants.RECV, data=b'/data'))),
                                            AdbMessage(command=constants.OKAY, arg0=1, arg1=1),
                                            AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b''))

        with patch('aio_adb_shell.adb_device.open', mock_open()), patch('os.path.exists', return_value=True):
            self.assertTrue(await self.device.pull('/data', 'TEST_FILE'))
            self.assertEqual(self.device._handle._bulk_write, expected_bulk_write)

    @awaiter
    async def test_pull_file_return_true(self):
        self.assertTrue(await self.device.connect())
        self.device._handle._bulk_write = b''

        filedata = b'Ohayou sekai.\nGood morning world!'

        # Provide the `bulk_read` return values
        self.device._handle._bulk_read = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                       AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                       AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=join_messages(FileSyncMessage(command=constants.DATA, data=filedata),
                                                                                                                             FileSyncMessage(command=constants.DONE))),
                                                       AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b''))

        # Expected `bulk_write` values
        expected_bulk_write = join_messages(AdbMessage(command=constants.OPEN, arg0=1, arg1=0, data=b'sync:\x00'),
                                            AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=join_messages(FileSyncMessage(command=constants.RECV, data=b'/data'))),
                                            AdbMessage(command=constants.OKAY, arg0=1, arg1=1),
                                            AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b''))

        with patch('aio_adb_shell.adb_device.open', mock_open()), patch('aio_adb_shell.adb_device.hasattr', return_value=False):
            self.assertTrue(await self.device.pull('/data', 'TEST_FILE'))
            self.assertEqual(self.device._handle._bulk_write, expected_bulk_write)

    @awaiter
    async def test_pull_big_file(self):
        self.assertTrue(await self.device.connect())
        self.device._handle._bulk_write = b''

        filedata = b'0' * int(1.5 * constants.MAX_ADB_DATA)

        # Provide the `bulk_read` return values

        self.device._handle._bulk_read = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                       AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                       AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=join_messages(FileSyncMessage(command=constants.DATA, data=filedata),
                                                                                                                             FileSyncMessage(command=constants.DONE))),
                                                       AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b''))

        # Expected `bulk_write` values
        expected_bulk_write = join_messages(AdbMessage(command=constants.OPEN, arg0=1, arg1=0, data=b'sync:\x00'),
                                            AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=join_messages(FileSyncMessage(command=constants.RECV, data=b'/data'))),
                                            AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b''),
                                            AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b''))

        with patch('aio_adb_shell.adb_device.open', mock_open()), patch('os.path.exists', return_value=True):
            self.assertTrue(await self.device.pull('/data', 'TEST_FILE'))
            self.assertEqual(self.device._handle._bulk_write, expected_bulk_write)

    @awaiter
    async def test_stat(self):
        self.assertTrue(await self.device.connect())
        self.device._handle._bulk_write = b''

        # Provide the `bulk_read` return values

        self.device._handle._bulk_read = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                       AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                       AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=join_messages(FileSyncStatMessage(constants.STAT, 1, 2, 3),
                                                                                                                             FileSyncStatMessage(constants.DONE, 0, 0, 0))),
                                                        AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b''))

        # Expected `bulk_write` values
        expected_bulk_write = join_messages(AdbMessage(command=constants.OPEN, arg0=1, arg1=0, data=b'sync:\x00'),
                                            AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=join_messages(FileSyncMessage(command=constants.STAT, data=b'/data'))),
                                            AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b''),
                                            AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b''))

        self.assertEqual(await self.device.stat('/data'), (1, 2, 3))
        self.assertEqual(self.device._handle._bulk_write, expected_bulk_write)

    # ======================================================================= #
    #                                                                         #
    #                  `filesync` hidden methods tests                        #
    #                                                                         #
    # ======================================================================= #
    @awaiter
    async def test_filesync_read_adb_command_failure_exceptions(self):
        self.assertTrue(await self.device.connect())
        self.device._handle._bulk_write = b''

        # Provide the `bulk_read` return values
        self.device._handle._bulk_read = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                       AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                       AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=join_messages(FileSyncStatMessage(constants.FAIL, 1, 2, 3),
                                                                                                                             FileSyncStatMessage(constants.DONE, 0, 0, 0))))

        with self.assertRaises(exceptions.AdbCommandFailureException):
            await self.device.stat('/data')

    @awaiter
    async def test_filesync_read_invalid_response_error(self):
        self.assertTrue(await self.device.connect())
        self.device._handle._bulk_write = b''

        # Provide the `bulk_read` return values
        self.device._handle._bulk_read = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                       AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                       AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=join_messages(FileSyncStatMessage(constants.DENT, 1, 2, 3),
                                                                                                                             FileSyncStatMessage(constants.DONE, 0, 0, 0))))

        with self.assertRaises(exceptions.InvalidResponseError):
            await self.device.stat('/data')

    # ======================================================================= #
    #                                                                         #
    #                      `filesync` error tests                             #
    #                                                                         #
    # ======================================================================= #
    @awaiter
    async def test_pull_value_error(self):
        self.assertTrue(await self.device.connect())
        self.device._handle._bulk_write = b''

        with self.assertRaises(ValueError):
            await self.device.pull('device_filename', 123)
