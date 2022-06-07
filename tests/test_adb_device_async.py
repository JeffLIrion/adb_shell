import asyncio
import inspect
import logging
from io import BytesIO
import sys
import unittest
from unittest.mock import mock_open, patch

from adb_shell import adb_device_async, constants, exceptions
from adb_shell.adb_device_async import AdbDeviceAsync, AdbDeviceTcpAsync, DeviceFile
from adb_shell.adb_message import AdbMessage
from adb_shell.auth.keygen import keygen
from adb_shell.auth.sign_pythonrsa import PythonRSASigner

from . import patchers
from .async_patchers import PATCH_TCP_TRANSPORT_ASYNC, FakeTcpTransportAsync, async_patch, async_mock_open
from .async_wrapper import awaiter
from .filesync_helpers import FileSyncMessage, FileSyncListMessage, FileSyncStatMessage
from .keygen_stub import open_priv_pub


# https://stackoverflow.com/a/7483862
_LOGGER = logging.getLogger('adb_shell.adb_device_async')
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


@patchers.ASYNC_SKIPPER
class TestAdbDeviceAsync(unittest.TestCase):
    def setUp(self):
        self.transport = FakeTcpTransportAsync('host', 5555)
        self.device = AdbDeviceAsync(self.transport)
        self.transport.bulk_read_data = b''.join(patchers.BULK_READ_LIST)
        self.progress_callback_count = 0

        async def _progress_callback(device_path, current, total_bytes):
            print("device_path = {}, current = {}, total_bytes = {}".format(device_path, current, total_bytes))
            self.progress_callback_count += 1

        self.progress_callback = _progress_callback

    def tearDown(self):
        self.assertFalse(self.transport.bulk_read_data)
        self.assertEqual(len(self.device._io_manager._packet_store._dict), 0)

    @staticmethod
    async def fake_stat(*args, **kwargs):
        return 1, 2, 3

    def test_no_sync_references(self):
        """Make sure there are no references to sync code."""
        adb_device_async_source = inspect.getsource(adb_device_async)
        self.assertTrue("base_transport." not in adb_device_async_source)
        self.assertTrue("BaseTransport." not in adb_device_async_source)
        self.assertTrue("adb_device." not in adb_device_async_source)
        self.assertTrue("AdbDevice." not in adb_device_async_source)
        self.transport.bulk_read_data = b''

    @awaiter
    async def test_adb_connection_error(self):
        with self.assertRaises(exceptions.AdbConnectionError):
            await self.device.exec_out('FAIL')

        with self.assertRaises(exceptions.AdbConnectionError):
            await self.device.root()

        with self.assertRaises(exceptions.AdbConnectionError):
            await self.device.shell('FAIL')

        with self.assertRaises(exceptions.AdbConnectionError):
            async_generator = self.device.streaming_shell('FAIL')
            await async_generator.__anext__()

        with self.assertRaises(exceptions.AdbConnectionError):
            await self.device.reboot()

        with self.assertRaises(exceptions.AdbConnectionError):
            await self.device.root()

        with self.assertRaises(exceptions.AdbConnectionError):
            await self.device.list('FAIL')

        with self.assertRaises(exceptions.AdbConnectionError):
            await self.device.push('FAIL', 'FAIL')

        with self.assertRaises(exceptions.AdbConnectionError):
            await self.device.pull('FAIL', 'FAIL')

        with self.assertRaises(exceptions.AdbConnectionError):
            await self.device.stat('FAIL')

        self.transport.bulk_read_data = b''

    @awaiter
    async def test_init_tcp(self):
        with PATCH_TCP_TRANSPORT_ASYNC:
            tcp_device = AdbDeviceTcpAsync('host')
            tcp_device._io_manager._transport.bulk_read_data = self.transport.bulk_read_data

        # Make sure that the `connect()` method works
        self.assertTrue(await tcp_device.connect())
        self.assertTrue(tcp_device.available)

        # Clear the `_bulk_read` buffer so that `self.tearDown()` passes
        self.transport.bulk_read_data = b''


    @awaiter
    async def test_init_banner(self):
        device_with_banner = AdbDeviceAsync(transport=FakeTcpTransportAsync('host', 5555), banner='banner')
        self.assertEqual(device_with_banner._banner, b'banner')

        device_with_banner2 = AdbDeviceAsync(transport=FakeTcpTransportAsync('host', 5555), banner=bytearray('banner2', 'utf-8'))
        self.assertEqual(device_with_banner2._banner, b'banner2')

        device_with_banner3 = AdbDeviceAsync(transport=FakeTcpTransportAsync('host', 5555), banner=u'banner3')
        self.assertEqual(device_with_banner3._banner, b'banner3')

        with patch('socket.gethostname', side_effect=Exception):
            device_banner_unknown = AdbDeviceAsync(self.transport)
            self.assertTrue(await device_banner_unknown.connect())
            self.assertEqual(device_banner_unknown._banner, b'unknown')

    @awaiter
    async def test_init_invalid_transport(self):
        with self.assertRaises(exceptions.InvalidTransportError):
            device = AdbDeviceAsync(transport=123)

        # Clear the `_bulk_read` buffer so that `self.tearDown()` passes
        self.transport.bulk_read_data = b''

    @awaiter
    async def test_available(self):
        self.assertFalse(self.device.available)

        # Clear the `_bulk_read` buffer so that `self.tearDown()` passes
        self.transport.bulk_read_data = b''

    @awaiter
    async def test_close(self):
        self.assertFalse(await self.device.close())
        self.assertFalse(self.device.available)

        # Clear the `_bulk_read` buffer so that `self.tearDown()` passes
        self.transport.bulk_read_data = b''

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
        self.transport.bulk_read_data = b''.join(patchers.BULK_READ_LIST_WITH_AUTH[:2])
        with self.assertRaises(exceptions.DeviceAuthError):
            await self.device.connect()

        self.assertFalse(self.device.available)

    @awaiter
    async def test_connect_with_key_invalid_response(self):
        with patch('adb_shell.auth.sign_pythonrsa.open', open_priv_pub), patch('adb_shell.auth.keygen.open', open_priv_pub):
            keygen('tests/adbkey')
            signer = PythonRSASigner.FromRSAKeyPath('tests/adbkey')

        self.transport.bulk_read_data = b''.join(patchers.BULK_READ_LIST_WITH_AUTH_INVALID)

        with self.assertRaises(exceptions.InvalidResponseError):
            await self.device.connect([signer])

        self.assertFalse(self.device.available)

    @awaiter
    async def test_connect_with_key(self):
        with patch('adb_shell.auth.sign_pythonrsa.open', open_priv_pub), patch('adb_shell.auth.keygen.open', open_priv_pub):
            keygen('tests/adbkey')
            signer = PythonRSASigner.FromRSAKeyPath('tests/adbkey')

        self.transport.bulk_read_data = b''.join(patchers.BULK_READ_LIST_WITH_AUTH)

        self.assertTrue(await self.device.connect([signer]))

    @awaiter
    async def test_connect_with_new_key(self):
        with patch('adb_shell.auth.sign_pythonrsa.open', open_priv_pub), patch('adb_shell.auth.keygen.open', open_priv_pub):
            keygen('tests/adbkey')
            signer = PythonRSASigner.FromRSAKeyPath('tests/adbkey')
            signer.pub_key = u''

        self.transport.bulk_read_data = b''.join(patchers.BULK_READ_LIST_WITH_AUTH_NEW_KEY)

        self.assertTrue(await self.device.connect([signer]))

    @awaiter
    async def test_connect_with_new_key_and_callback(self):
        with patch('adb_shell.auth.sign_pythonrsa.open', open_priv_pub), patch('adb_shell.auth.keygen.open', open_priv_pub):
            keygen('tests/adbkey')
            signer = PythonRSASigner.FromRSAKeyPath('tests/adbkey')
            signer.pub_key = u''

        self._callback_invoked = False
        def auth_callback(device):
            self._callback_invoked = True

        self.transport.bulk_read_data = b''.join(patchers.BULK_READ_LIST_WITH_AUTH_NEW_KEY)

        self.assertTrue(await self.device.connect([signer], auth_callback=auth_callback))
        self.assertTrue(self._callback_invoked)

    @awaiter
    async def test_connect_timeout(self):
        self.transport.bulk_read_data = AdbMessage(command=constants.CLSE, arg0=1, arg1=1).pack()

        with self.assertRaises(exceptions.AdbTimeoutError):
            # Use a negative timeout to ensure that only one packet gets read
            await self.device.connect([], read_timeout_s=-1)

    # ======================================================================= #
    #                                                                         #
    #                              `shell` tests                              #
    #                                                                         #
    # ======================================================================= #
    @awaiter
    async def test_shell_no_return(self):
        self.assertTrue(await self.device.connect())

        # Provide the `bulk_read` return values
        self.transport.bulk_read_data = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                      AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b''))

        self.assertEqual(await self.device.shell('TEST'), '')

    @awaiter
    async def test_shell_return_pass(self):
        self.assertTrue(await self.device.connect())

        # Provide the `bulk_read` return values
        self.transport.bulk_read_data = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                      AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'PA'),
                                                      AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'SS'),
                                                      AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b''))

        self.assertEqual(await self.device.shell('TEST'), 'PASS')

    @awaiter
    async def test_shell_local_id_wraparound(self):
        self.assertTrue(await self.device.connect())

        # Provide the `bulk_read` return values
        self.transport.bulk_read_data = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=2**32 - 1, data=b'\x00'),
                                                      AdbMessage(command=constants.WRTE, arg0=1, arg1=2**32 - 1, data=b'PASS1'),
                                                      AdbMessage(command=constants.CLSE, arg0=1, arg1=2**32 - 1, data=b''),
                                                      AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                      AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'PASS2'),
                                                      AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b''))

        self.device._local_id = 2**32 - 2
        self.assertEqual(await self.device.shell('TEST'), 'PASS1')
        self.assertEqual(await self.device.shell('TEST'), 'PASS2')

    @awaiter
    async def test_shell_return_pass_with_unexpected_packet(self):
        self.assertTrue(await self.device.connect())

        # Provide the `bulk_read` return values
        self.transport.bulk_read_data = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                      AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'PA'),
                                                      AdbMessage(command=constants.AUTH, arg0=1, arg1=1, data=b'UNEXPECTED'),
                                                      AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'SS'),
                                                      AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b''))

        self.assertEqual(await self.device.shell('TEST'), 'PASS')

    @awaiter
    async def test_shell_dont_decode(self):
        self.assertTrue(await self.device.connect())

        # Provide the `bulk_read` return values
        self.transport.bulk_read_data = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                      AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'PA'),
                                                      AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'SS'),
                                                      AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b''))

        self.assertEqual(await self.device.shell('TEST', decode=False), b'PASS')

    @awaiter
    async def test_shell_avoid_decode_error(self):
        self.assertTrue(await self.device.connect())

        # Provide the `bulk_read` return values
        self.transport.bulk_read_data = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                      AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'\x80abc'),
                                                      AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b''))

        self.assertEqual(await self.device.shell('TEST'), '\\x80abc')

    @awaiter
    async def test_shell_data_length_exceeds_max(self):
        self.assertTrue(await self.device.connect())

        # Provide the `bulk_read` return values
        self.transport.bulk_read_data = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                      AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'0'*(self.device.max_chunk_size+1)),
                                                      AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b''))

        await self.device.shell('TEST')
        self.assertTrue(True)

    @awaiter
    async def test_shell_multibytes_sequence_exceeds_max(self):
        self.assertTrue(await self.device.connect())

        # Provide the `bulk_read` return values
        self.transport.bulk_read_data = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                      AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'0'*(self.device.max_chunk_size-1) + b'\xe3\x81\x82'),
                                                      AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b''))

        self.assertEqual(await self.device.shell('TEST'), u'0'*(self.device.max_chunk_size-1) + u'\u3042')

    @awaiter
    async def test_shell_with_multibytes_sequence_over_two_messages(self):
        self.assertTrue(await self.device.connect())

        # Provide the `bulk_read` return values
        self.transport.bulk_read_data = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                      AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'\xe3'),
                                                      AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'\x81\x82'),
                                                      AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b''))

        self.assertEqual(await self.device.shell('TEST'), u'\u3042')

    @awaiter
    async def test_shell_multiple_clse(self):
        # https://github.com/JeffLIrion/adb_shell/issues/15#issuecomment-536795938
        self.assertTrue(await self.device.connect())

        # Provide the `bulk_read` return values
        msg1 = AdbMessage(command=constants.OKAY, arg0=2, arg1=2, data=b'')
        msg2 = AdbMessage(command=constants.WRTE, arg0=2, arg1=2, data=b'PASS')
        msg3 = AdbMessage(command=constants.CLSE, arg0=2, arg1=2, data=b'')
        self.transport.bulk_read_data = b''.join([b'OKAY\xd9R\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xb0\xb4\xbe\xa6',
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

    @awaiter
    async def test_shell_multiple_streams(self):
        self.assertTrue(await self.device.connect())

        # Provide the `bulk_read` return values
        self.transport.bulk_read_data = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=2, data=b'\x00'),
                                                      AdbMessage(command=constants.OKAY, arg0=1, arg1=2, data=b'\x00'),
                                                      AdbMessage(command=constants.OKAY, arg0=1, arg1=2, data=b'\x00'),
                                                      AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                      AdbMessage(command=constants.WRTE, arg0=1, arg1=2, data=b'PASS2'),
                                                      AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'PASS1'),
                                                      AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b''),
                                                      AdbMessage(command=constants.CLSE, arg0=1, arg1=2, data=b''))

        self.assertEqual(await self.device.shell('TEST1'), 'PASS1')
        self.assertEqual(await self.device.shell('TEST2'), 'PASS2')

    @awaiter
    async def test_shell_multiple_streams2(self):
        self.assertTrue(await self.device.connect())

        async def fake_read_packet_from_device(*args, **kwargs):
            # Mimic the scenario that this stream's packets get read by another stream after the first attempt to read the packet from the device
            self.device._io_manager._packet_store.put(arg0=1, arg1=1, cmd=constants.WRTE, data=b'\x00')
            self.device._io_manager._packet_store.put(arg0=1, arg1=1, cmd=constants.OKAY, data=b'\x00')
            self.device._io_manager._packet_store.put(arg0=2, arg1=2, cmd=constants.OKAY, data=b'\x00')
            self.device._io_manager._packet_store.put(arg0=1, arg1=1, cmd=constants.OKAY, data=b'\x00')
            self.device._io_manager._packet_store.put(arg0=2, arg1=2, cmd=constants.WRTE, data=b'PASS2')
            self.device._io_manager._packet_store.put(arg0=1, arg1=1, cmd=constants.WRTE, data=b"PASS1")
            self.device._io_manager._packet_store.put(arg0=1, arg1=1, cmd=constants.CLSE, data=b"")
            self.device._io_manager._packet_store.put(arg0=2, arg1=2, cmd=constants.CLSE, data=b"")

            return constants.OKAY, 2, 2, b"\x00"

        with patch.object(self.device._io_manager, "_read_packet_from_device", fake_read_packet_from_device):
            # The patch function will only be called once, all subsequent packets will be retrieved from the store
            self.assertEqual(await self.device.shell('TEST1'), 'PASS1')
            self.assertEqual(await self.device.shell('TEST2'), 'PASS2')

    @awaiter
    async def test_shell_local_id2(self):
        self.assertTrue(await self.device.connect())

        # Provide the `bulk_read` return values
        self.transport.bulk_read_data = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                      AdbMessage(command=constants.OKAY, arg0=1, arg1=2, data=b'\x00'),
                                                      AdbMessage(command=constants.WRTE, arg0=1, arg1=2, data=b'PASS2'),
                                                      AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'PASS1'),
                                                      AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b''),
                                                      AdbMessage(command=constants.CLSE, arg0=1, arg1=2, data=b''))

        self.assertEqual(await self.device.shell('TEST1'), 'PASS1')
        self.assertEqual(await self.device.shell('TEST2'), 'PASS2')

    @awaiter
    async def test_shell_remote_id2(self):
        self.assertTrue(await self.device.connect())

        # Provide the `bulk_read` return values
        self.transport.bulk_read_data = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                      AdbMessage(command=constants.OKAY, arg0=2, arg1=2, data=b'\x00'),
                                                      AdbMessage(command=constants.WRTE, arg0=2, arg1=2, data=b'PASS2'),
                                                      AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'PASS1'),
                                                      AdbMessage(command=constants.CLSE, arg0=2, arg1=2, data=b''),
                                                      AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b''))

        self.assertEqual(await self.device.shell('TEST1'), 'PASS1')
        self.assertEqual(await self.device.shell('TEST2'), 'PASS2')


    # ======================================================================= #
    #                                                                         #
    #                           `shell` error tests                           #
    #                                                                         #
    # ======================================================================= #
    @awaiter
    async def test_shell_error_local_id_timeout(self):
        self.assertTrue(await self.device.connect())

        # Provide the `bulk_read` return values
        self.transport.bulk_read_data = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1234, data=b'\x00'),
                                                      AdbMessage(command=constants.OKAY, arg0=1, arg1=1234, data=b'\x00'))

        with self.assertRaises(exceptions.AdbTimeoutError):
            await self.device.shell('TEST', read_timeout_s=1)

        # Close the connection so that the packet store gets cleared
        await self.device.close()

    @awaiter
    async def test_shell_error_unknown_command(self):
        self.assertTrue(await self.device.connect())

        # Provide the `bulk_read` return values
        self.transport.bulk_read_data = join_messages(AdbMessageForTesting(command=constants.FAIL, arg0=1, arg1=1, data=b''))

        with self.assertRaises(exceptions.InvalidCommandError):
            self.assertEqual(await self.device.shell('TEST'), '')

    @awaiter
    async def test_shell_error_transport_timeout(self):
        self.assertTrue(await self.device.connect())

        # Provide the `bulk_read` return values
        self.transport.bulk_read_data = join_messages(AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b''))

        with self.assertRaises(exceptions.AdbTimeoutError):
            await self.device.shell('TEST', read_timeout_s=-1)

    @awaiter
    async def test_shell_error_read_timeout_multiple_clse(self):
        self.assertTrue(await self.device.connect())

        # Provide the `bulk_read` return values
        self.transport.bulk_read_data = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b''),
                                                      AdbMessage(command=constants.CLSE, arg0=2, arg1=1, data=b''))

        with self.assertRaises(exceptions.AdbTimeoutError):
            await self.device.shell('TEST', read_timeout_s=-1)

    @awaiter
    async def test_shell_error_timeout(self):
        self.assertTrue(await self.device.connect())

        # Provide the `bulk_read` return values
        self.transport.bulk_read_data = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                      AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'PA'),
                                                      AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'SS'),
                                                      AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b''))

        async def fake_read_until(*args, **kwargs):
            await asyncio.sleep(0.2)
            return b'WRTE', b'PA'

        with patch('adb_shell.adb_device_async.AdbDeviceAsync._read_until', fake_read_until):
            with self.assertRaises(exceptions.AdbTimeoutError):
                await self.device.shell('TEST', timeout_s=0.5)

        # Clear the `_bulk_read` buffer so that `self.tearDown()` passes
        self.transport.bulk_read_data = b''

    @awaiter
    async def test_shell_error_checksum(self):
        self.assertTrue(await self.device.connect())

        # Provide the `bulk_read` return values
        msg1 = AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00')
        msg2 = AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'PASS')
        self.transport.bulk_read_data = b''.join([msg1.pack(), msg1.data, msg2.pack(), msg2.data[:-1] + b'0'])

        with self.assertRaises(exceptions.InvalidChecksumError):
            await self.device.shell('TEST')

    @awaiter
    async def test_issue29(self):
        # https://github.com/JeffLIrion/adb_shell/issues/29
        with patch('adb_shell.auth.sign_pythonrsa.open', open_priv_pub), patch('adb_shell.auth.keygen.open', open_priv_pub):
            keygen('tests/adbkey')
            signer = PythonRSASigner.FromRSAKeyPath('tests/adbkey')

        okay3 = AdbMessage(command=constants.OKAY, arg0=1, arg1=3, data=b'\x00')
        clse3 = AdbMessage(command=constants.CLSE, arg0=1, arg1=3, data=b'')
        okay5 = AdbMessage(command=constants.OKAY, arg0=1, arg1=5, data=b'\x00')
        clse5 = AdbMessage(command=constants.CLSE, arg0=1, arg1=5, data=b'')
        okay7 = AdbMessage(command=constants.OKAY, arg0=1, arg1=7, data=b'\x00')
        clse7 = AdbMessage(command=constants.CLSE, arg0=1, arg1=7, data=b'')

        self.transport.bulk_read_data = b''.join([b'AUTH\x01\x00\x00\x00\x00\x00\x00\x00\x14\x00\x00\x00\xc5\n\x00\x00\xbe\xaa\xab\xb7',  # Line 22
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
                                                  b'OKAY\xa5\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xb0\xb4\xbe\xa6',  # Line 305
                                                  b'CLSE\xa5\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xbc\xb3\xac\xba',  # Line 306
                                                  okay3.pack(),
                                                  okay3.data,
                                                  clse3.pack(),
                                                  b'AUTH\x01\x00\x00\x00\x00\x00\x00\x00\x14\x00\x00\x00e\x0c\x00\x00\xbe\xaa\xab\xb7',  # Line 315
                                                  b'\xd3\xef\x7f_\xa6\xc0`b\x19\\z\xe4\xf3\xe2\xed\x8d\xe1W\xfbH',  # Line 316
                                                  b"CNXN\x00\x00\x00\x01\x00\x10\x00\x00i\x00\x00\x00.'\x00\x00\xbc\xb1\xa7\xb1",  # Line 319
                                                  b'device::ro.product.name=once;ro.product.model=MIBOX3;ro.product.device=once;features=stat_v2,cmd,shell_v2',  # Line 320
                                                  b'OKAY\xa7\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xb0\xb4\xbe\xa6',  # Line 323
                                                  b'CLSE\xa7\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xbc\xb3\xac\xba',  # Line 324
                                                  okay5.pack(),
                                                  okay5.data,
                                                  clse5.pack(),
                                                  b'AUTH\x01\x00\x00\x00\x00\x00\x00\x00\x14\x00\x00\x00\x93\x08\x00\x00\xbe\xaa\xab\xb7',  # Line 333
                                                  b's\xd4_e\xa4s\x02\x95\x0f\x1e\xec\n\x95Y9[`\x8e\xe1f',  # Line 334
                                                  b"CNXN\x00\x00\x00\x01\x00\x10\x00\x00i\x00\x00\x00.'\x00\x00\xbc\xb1\xa7\xb1",  # Line 337
                                                  b'device::ro.product.name=once;ro.product.model=MIBOX3;ro.product.device=once;features=stat_v2,cmd,shell_v2',  # Line 338
                                                  b'OKAY\xa9\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xb0\xb4\xbe\xa6',  # Line 341
                                                  b'CLSE\xa9\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xbc\xb3\xac\xba',  # Line 342
                                                  okay7.pack(),
                                                  okay7.data,
                                                  clse7.pack()])

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
        self.transport.bulk_read_data = join_messages(
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
        self.transport.bulk_read_data = join_messages(
            AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
            AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'ABC'),
            AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'123'),
        )

        async_generator = self.device.streaming_shell('TEST', decode=False)
        self.assertEqual(await async_generator.__anext__(), b'ABC')
        self.assertEqual(await async_generator.__anext__(), b'123')


    # ======================================================================= #
    #                                                                         #
    #                              `reboot` test                              #
    #                                                                         #
    # ======================================================================= #
    @awaiter
    async def test_reboot(self):
        self.assertTrue(await self.device.connect())

        with async_patch('adb_shell.adb_device_async.AdbDeviceAsync._open') as patch_open:
            await self.device.reboot()
            patch_open.assert_called_once()


    # ======================================================================= #
    #                                                                         #
    #                               `root` test                               #
    #                                                                         #
    # ======================================================================= #
    @awaiter
    async def test_root(self):
        self.assertTrue(await self.device.connect())

        with async_patch('adb_shell.adb_device_async.AdbDeviceAsync._service') as patch_service:
            await self.device.root()
            patch_service.assert_called_once()


    # ======================================================================= #
    #                                                                         #
    #                         `exec_out` test                                 #
    #                                                                         #
    # ======================================================================= #
    @awaiter
    async def test_exec_out(self):
        self.assertTrue(await self.device.connect())

        # Provide the `bulk_read` return values
        self.transport.bulk_read_data = b''.join([b'OKAY\x14\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xb0\xb4\xbe\xa6',
                                                  b'WRTE\x14\x00\x00\x00\x01\x00\x00\x00\x05\x00\x00\x00J\x01\x00\x00\xa8\xad\xab\xba',
                                                  b'TEST\n',
                                                  b'',
                                                  b'CLSE\x14\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xbc\xb3\xac\xba'])

        self.assertEqual(await self.device.exec_out("echo 'TEST'"), "TEST\n")


    # ======================================================================= #
    #                                                                         #
    #                         `filesync` tests                                #
    #                                                                         #
    # ======================================================================= #
    @awaiter
    async def test_list(self):
        self.assertTrue(await self.device.connect())
        self.transport.bulk_write_data = b''

        # Provide the `bulk_read` return values
        self.transport.bulk_read_data = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
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
        self.assertEqual(self.transport.bulk_write_data, expected_bulk_write)

    @awaiter
    async def test_list_empty_path(self):
        with self.assertRaises(exceptions.DevicePathInvalidError):
            await self.device.list("")
        with self.assertRaises(exceptions.DevicePathInvalidError):
            await self.device.list(b"")
        with self.assertRaises(exceptions.DevicePathInvalidError):
            await self.device.list(u"")
        with self.assertRaises(exceptions.DevicePathInvalidError):
            await self.device.list(None)
        # Clear the `_bulk_read` buffer so that `self.tearDown()` passes
        self.transport.bulk_read_data = b''

    @patchers.ASYNC_SKIPPER
    @awaiter
    async def test_push_fail(self):
        self.assertTrue(await self.device.connect())
        self.transport.bulk_write_data = b''

        mtime = 100
        filedata = b'Ohayou sekai.\nGood morning world!'

        # Provide the `bulk_read` return values
        self.transport.bulk_read_data = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                      AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b''),
                                                      AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=join_messages(FileSyncMessage(constants.FAIL, data=b''))))

        with self.assertRaises(exceptions.PushFailedError), patch('aiofiles.open', async_mock_open(read_data=filedata)):
            await self.device.push('TEST_FILE', '/data', mtime=mtime)

    @patchers.ASYNC_SKIPPER
    @awaiter
    async def test_push_file(self):
        self.assertTrue(await self.device.connect())
        self.transport.bulk_write_data = b''

        mtime = 100
        filedata = b'Ohayou sekai.\nGood morning world!'

        # Provide the `bulk_read` return values
        self.transport.bulk_read_data = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
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

        with patch('aiofiles.open', async_mock_open(read_data=filedata)):
            self.assertEqual(self.progress_callback_count, 0)
            with patch("adb_shell.adb_device_async.os.fstat", return_value=patchers.StSize(12345)):
                await self.device.push('TEST_FILE', '/data', mtime=mtime, progress_callback=self.progress_callback)
            self.assertEqual(self.progress_callback_count, 1)
            self.assertEqual(self.transport.bulk_write_data, expected_bulk_write)

    @patchers.ASYNC_SKIPPER
    @awaiter
    async def test_push_bytesio(self):
        self.assertTrue(await self.device.connect())
        self.transport.bulk_write_data = b''

        mtime = 100
        filedata = b'Ohayou sekai.\nGood morning world!'

        # Provide the `bulk_read` return values
        self.transport.bulk_read_data = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
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

        stream = BytesIO(filedata)
        await self.device.push(stream, '/data', mtime=mtime)
        self.assertEqual(self.transport.bulk_write_data, expected_bulk_write)

    @patchers.ASYNC_SKIPPER
    @awaiter
    async def test_push_file_exception(self):
        self.assertTrue(await self.device.connect())
        self.transport.bulk_write_data = b''

        mtime = 100
        filedata = b'Ohayou sekai.\nGood morning world!'

        # Provide the `bulk_read` return values
        self.transport.bulk_read_data = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
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

        with patch('aiofiles.open', async_mock_open(read_data=filedata)):
            # Set self.progress_callback_count to None so that an exception occurs when self.progress_callback tries to increment it
            self.progress_callback_count = None
            with patch("adb_shell.adb_device_async.os.fstat", return_value=patchers.StSize(12345)):
                await self.device.push('TEST_FILE', '/data', mtime=mtime, progress_callback=self.progress_callback)

            self.assertIsNone(self.progress_callback_count)
            self.assertEqual(self.transport.bulk_write_data, expected_bulk_write)

    @patchers.ASYNC_SKIPPER
    @awaiter
    async def test_push_file_mtime0(self):
        self.assertTrue(await self.device.connect())
        self.transport.bulk_write_data = b''

        mtime = 0
        filedata = b'Ohayou sekai.\nGood morning world!'

        # Provide the `bulk_read` return values
        self.transport.bulk_read_data = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
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

        with patch('aiofiles.open', async_mock_open(read_data=filedata)), patch('time.time', return_value=mtime):
            await self.device.push('TEST_FILE', '/data', mtime=mtime)
            self.assertEqual(self.transport.bulk_write_data, expected_bulk_write)

    @patchers.ASYNC_SKIPPER
    @awaiter
    async def test_push_big_file(self):
        self.assertTrue(await self.device.connect())
        self.transport.bulk_write_data = b''

        mtime = 100
        filedata = b'0' * int(3.5 * self.device.max_chunk_size)

        # Provide the `bulk_read` return values
        self.transport.bulk_read_data = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                      AdbMessage(command=constants.OKAY, arg0=1, arg1=1),
                                                      AdbMessage(command=constants.OKAY, arg0=1, arg1=1),
                                                      AdbMessage(command=constants.OKAY, arg0=1, arg1=1),
                                                      AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=join_messages(FileSyncMessage(constants.OKAY))),
                                                      AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b''))

        # Expected `bulk_write` values
        mcs0, mcs1, mcs2, mcs3 = 0, self.device.max_chunk_size, 2*self.device.max_chunk_size, 3*self.device.max_chunk_size
        expected_bulk_write = join_messages(AdbMessage(command=constants.OPEN, arg0=1, arg1=0, data=b'sync:\x00'),
                                            AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=join_messages(
                                                FileSyncMessage(command=constants.SEND, data=b'/data,33272'),
                                                FileSyncMessage(command=constants.DATA, data=filedata[mcs0:mcs1]))),
                                            AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=join_messages(
                                                FileSyncMessage(command=constants.DATA, data=filedata[mcs1:mcs2]))),
                                            AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=join_messages(
                                                FileSyncMessage(command=constants.DATA, data=filedata[mcs2:mcs3]),
                                                FileSyncMessage(command=constants.DATA, data=filedata[mcs3:]),
                                                FileSyncMessage(command=constants.DONE, arg0=mtime))),
                                            AdbMessage(command=constants.OKAY, arg0=1, arg1=1),
                                            AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b''))

        with patch('aiofiles.open', async_mock_open(read_data=filedata)):
            self.assertEqual(self.progress_callback_count, 0)
            with patch("adb_shell.adb_device_async.os.fstat", return_value=patchers.StSize(12345)):
                await self.device.push('TEST_FILE', '/data', mtime=mtime, progress_callback=self.progress_callback)
            self.assertEqual(self.progress_callback_count, 4)
            self.assertEqual(self.transport.bulk_write_data, expected_bulk_write)

    @patchers.ASYNC_SKIPPER
    @awaiter
    async def test_push_dir(self):
        self.assertTrue(await self.device.connect())

        mtime = 100
        filedata = b'Ohayou sekai.\nGood morning world!'

        # Provide the `bulk_read` return values
        self.transport.bulk_read_data = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                      AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b''),
                                                      AdbMessage(command=constants.OKAY, arg0=2, arg1=2, data=b'\x00'),
                                                      AdbMessage(command=constants.OKAY, arg0=2, arg1=2, data=b'\x00'),
                                                      AdbMessage(command=constants.WRTE, arg0=2, arg1=2, data=join_messages(FileSyncMessage(constants.OKAY))),
                                                      AdbMessage(command=constants.CLSE, arg0=2, arg1=2, data=b''),
                                                      AdbMessage(command=constants.OKAY, arg0=3, arg1=3, data=b'\x00'),
                                                      AdbMessage(command=constants.OKAY, arg0=3, arg1=3, data=b'\x00'),
                                                      AdbMessage(command=constants.WRTE, arg0=3, arg1=3, data=join_messages(FileSyncMessage(constants.OKAY))),
                                                      AdbMessage(command=constants.CLSE, arg0=3, arg1=3, data=b''))

        # Expected `bulk_write` values
        #TODO

        with patch('aiofiles.open', async_mock_open(read_data=filedata)), patch('os.path.isdir', lambda x: x == 'TEST_DIR/'), patch('os.listdir', return_value=['TEST_FILE1', 'TEST_FILE2']):
            await self.device.push('TEST_DIR/', '/data', mtime=mtime)

    @awaiter
    async def test_push_empty_path(self):
        with self.assertRaises(exceptions.DevicePathInvalidError):
            await self.device.push("NOTHING", "")
        with self.assertRaises(exceptions.DevicePathInvalidError):
            await self.device.push("NOTHING", b"")
        with self.assertRaises(exceptions.DevicePathInvalidError):
            await self.device.push("NOTHING", u"")
        with self.assertRaises(exceptions.DevicePathInvalidError):
            await self.device.push("NOTHING", None)
        # Clear the `_bulk_read` buffer so that `self.tearDown()` passes
        self.transport.bulk_read_data = b''

    @patchers.ASYNC_SKIPPER
    @awaiter
    async def test_pull_file(self):
        self.assertTrue(await self.device.connect())
        self.transport.bulk_write_data = b''

        filedata = b'Ohayou sekai.\nGood morning world!'

        # Provide the `bulk_read` return values
        self.transport.bulk_read_data = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                      AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                      AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=join_messages(FileSyncMessage(command=constants.DATA, data=filedata),
                                                                                                                            FileSyncMessage(command=constants.DONE))),
                                                      AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b''))

        # Expected `bulk_write` values
        expected_bulk_write = join_messages(AdbMessage(command=constants.OPEN, arg0=1, arg1=0, data=b'sync:\x00'),
                                            AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=join_messages(FileSyncMessage(command=constants.RECV, data=b'/data'))),
                                            AdbMessage(command=constants.OKAY, arg0=1, arg1=1),
                                            AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b''))

        with patch('aiofiles.open', async_mock_open()) as m:
            self.assertEqual(self.progress_callback_count, 0)
            with patch('adb_shell.adb_device_async.AdbDeviceAsync.stat', self.fake_stat):
                await self.device.pull('/data', 'TEST_FILE', progress_callback=self.progress_callback)

            self.assertEqual(self.progress_callback_count, 1)
            self.assertEqual(m.written, filedata)
            self.assertEqual(self.transport.bulk_write_data, expected_bulk_write)

    @patchers.ASYNC_SKIPPER
    @awaiter
    async def test_pull_bytesio(self):
        self.assertTrue(await self.device.connect())
        self.transport.bulk_write_data = b''

        filedata = b'Ohayou sekai.\nGood morning world!'

        # Provide the `bulk_read` return values
        self.transport.bulk_read_data = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                      AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                      AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=join_messages(FileSyncMessage(command=constants.DATA, data=filedata),
                                                                                                                            FileSyncMessage(command=constants.DONE))),
                                                      AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b''))

        # Expected `bulk_write` values
        expected_bulk_write = join_messages(AdbMessage(command=constants.OPEN, arg0=1, arg1=0, data=b'sync:\x00'),
                                            AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=join_messages(FileSyncMessage(command=constants.RECV, data=b'/data'))),
                                            AdbMessage(command=constants.OKAY, arg0=1, arg1=1),
                                            AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b''))

        stream = BytesIO()
        await self.device.pull('/data', stream)

        self.assertEqual(self.transport.bulk_write_data, expected_bulk_write)
        self.assertEqual(stream.getvalue(), filedata)    

    @patchers.ASYNC_SKIPPER
    @awaiter
    async def test_pull_file_exception(self):
        self.assertTrue(await self.device.connect())
        self.transport.bulk_write_data = b''

        filedata = b'Ohayou sekai.\nGood morning world!'

        # Provide the `bulk_read` return values
        self.transport.bulk_read_data = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                      AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                      AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=join_messages(FileSyncMessage(command=constants.DATA, data=filedata),
                                                                                                                            FileSyncMessage(command=constants.DONE))),
                                                      AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b''))

        # Expected `bulk_write` values
        expected_bulk_write = join_messages(AdbMessage(command=constants.OPEN, arg0=1, arg1=0, data=b'sync:\x00'),
                                            AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=join_messages(FileSyncMessage(command=constants.RECV, data=b'/data'))),
                                            AdbMessage(command=constants.OKAY, arg0=1, arg1=1),
                                            AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b''))

        with patch('aiofiles.open', async_mock_open()) as m:
            # Set self.progress_callback_count to None so that an exception occurs when self.progress_callback tries to increment it
            self.progress_callback_count = None
            with patch('adb_shell.adb_device_async.AdbDeviceAsync.stat', self.fake_stat):
                await self.device.pull('/data', 'TEST_FILE', progress_callback=self.progress_callback)

            self.assertIsNone(self.progress_callback_count)
            self.assertEqual(m.written, filedata)
            self.assertEqual(self.transport.bulk_write_data, expected_bulk_write)

    @patchers.ASYNC_SKIPPER
    @awaiter
    async def test_pull_big_file(self):
        self.assertTrue(await self.device.connect())
        self.transport.bulk_write_data = b''

        filedata = b'0' * int(1.5 * constants.MAX_ADB_DATA)

        # Provide the `bulk_read` return values
        self.transport.bulk_read_data = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                      AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                      AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=join_messages(FileSyncMessage(command=constants.DATA, data=filedata),
                                                                                                                            FileSyncMessage(command=constants.DONE))),
                                                      AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b''))

        # Expected `bulk_write` values
        expected_bulk_write = join_messages(AdbMessage(command=constants.OPEN, arg0=1, arg1=0, data=b'sync:\x00'),
                                            AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=join_messages(FileSyncMessage(command=constants.RECV, data=b'/data'))),
                                            AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b''),
                                            AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b''))

        with patch('aiofiles.open', async_mock_open()) as m:
            self.assertEqual(self.progress_callback_count, 0)
            with patch('adb_shell.adb_device_async.AdbDeviceAsync.stat', self.fake_stat):
                await self.device.pull('/data', 'TEST_FILE', progress_callback=self.progress_callback)

            self.assertEqual(self.progress_callback_count, 1)
            self.assertEqual(m.written, filedata)
            self.assertEqual(self.transport.bulk_write_data, expected_bulk_write)

    @awaiter
    async def test_pull_empty_path(self):
        with self.assertRaises(exceptions.DevicePathInvalidError):
            await self.device.pull("", "NOWHERE")
        with self.assertRaises(exceptions.DevicePathInvalidError):
            await self.device.pull(b"", "NOWHERE")
        with self.assertRaises(exceptions.DevicePathInvalidError):
            await self.device.pull(u"", "NOWHERE")
        with self.assertRaises(exceptions.DevicePathInvalidError):
            await self.device.pull(None, "NOWHERE")
        # Clear the `_bulk_read` buffer so that `self.tearDown()` passes
        self.transport.bulk_read_data = b''

    @awaiter
    async def test_pull_non_existant_path(self):
        self.assertTrue(await self.device.connect())
        self.transport.bulk_write_data = b''

        # Provide the `bulk_read` return values
        self.transport.bulk_read_data = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b''),
                                                      AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b''),
                                                      AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'FAIL&\x00\x00\x00'),
                                                      AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'open failed: No such file or directory'),
                                                      AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b''))

        # Expected `bulk_write` values
        expected_bulk_write = join_messages(AdbMessage(command=constants.OPEN, arg0=1, arg1=0, data=b'sync:\x00'),
                                            AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=join_messages(FileSyncMessage(command=constants.RECV, data=b'/does/not/exist'))),
                                            AdbMessage(command=constants.OKAY, arg0=1, arg1=1),
                                            AdbMessage(command=constants.OKAY, arg0=1, arg1=1),
                                            AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b''))
        with self.assertRaises(exceptions.AdbCommandFailureException):
            await self.device.pull("/does/not/exist", "NOWHERE")
        self.assertEqual(expected_bulk_write, self.transport.bulk_write_data)

    @awaiter
    async def test_pull_non_existant_path_2(self):
        self.assertTrue(await self.device.connect())
        self.transport.bulk_write_data = b''

        # Provide the `bulk_read` return values
        self.transport.bulk_read_data = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b''),
                                                      AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b''),
                                                      AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'FAIL&\x00\x00\x00open failed: No such file or directory'),
                                                      AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b''))

        # Expected `bulk_write` values
        expected_bulk_write = join_messages(AdbMessage(command=constants.OPEN, arg0=1, arg1=0, data=b'sync:\x00'),
                                            AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=join_messages(FileSyncMessage(command=constants.RECV, data=b'/does/not/exist'))),
                                            AdbMessage(command=constants.OKAY, arg0=1, arg1=1),
                                            AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b''))
        with self.assertRaises(exceptions.AdbCommandFailureException):
            await self.device.pull("/does/not/exist", "NOWHERE")
        self.assertEqual(expected_bulk_write, self.transport.bulk_write_data)

    @awaiter
    async def test_stat(self):
        self.assertTrue(await self.device.connect())
        self.transport.bulk_write_data = b''

        # Provide the `bulk_read` return values
        self.transport.bulk_read_data = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
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
        self.assertEqual(self.transport.bulk_write_data, expected_bulk_write)

    @awaiter
    async def test_stat_empty_path(self):
        with self.assertRaises(exceptions.DevicePathInvalidError):
            await self.device.stat("")
        with self.assertRaises(exceptions.DevicePathInvalidError):
            await self.device.stat(b"")
        with self.assertRaises(exceptions.DevicePathInvalidError):
            await self.device.stat(u"")
        with self.assertRaises(exceptions.DevicePathInvalidError):
            await self.device.stat(None)
        # Clear the `_bulk_read` buffer so that `self.tearDown()` passes
        self.transport.bulk_read_data = b''

    @awaiter
    async def test_stat_issue155(self):
        self.assertTrue(await self.device.connect())

        # Provide the `bulk_read` return values
        self.transport.bulk_read_data = b"".join([b'CLSE\n\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xbc\xb3\xac\xba',
                                                  b'OKAY\x0b\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xb0\xb4\xbe\xa6',
                                                  b'OKAY\x0b\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xb0\xb4\xbe\xa6',
                                                  b'WRTE\x0b\x00\x00\x00\x01\x00\x00\x00\x10\x00\x00\x00\x96\x04\x00\x00\xa8\xad\xab\xba',
                                                  b'STAT\xedA\x00\x00\x00\x10\x00\x00\xf0\x88[I',
                                                  b'CLSE\x0b\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xbc\xb3\xac\xba'])

        # This is where the expected values come from
        mode = 16877
        size = 4096
        mtime = 1230735600
        self.assertEqual(FileSyncStatMessage(constants.STAT, mode, size, mtime).pack(), b'STAT\xedA\x00\x00\x00\x10\x00\x00\xf0\x88[I')

        self.assertEqual((mode, size, mtime), await self.device.stat('/'))

    # ======================================================================= #
    #                                                                         #
    #                  `filesync` hidden methods tests                        #
    #                                                                         #
    # ======================================================================= #
    @awaiter
    async def test_filesync_read_adb_command_failure_exceptions(self):
        self.assertTrue(await self.device.connect())
        self.transport.bulk_write_data = b''

        # Provide the `bulk_read` return values
        self.transport.bulk_read_data = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                      AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                      AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=join_messages(FileSyncStatMessage(constants.FAIL, 1, 2, 3),
                                                                                                                            FileSyncStatMessage(constants.DONE, 0, 0, 0))))

        with self.assertRaises(exceptions.AdbCommandFailureException):
            await self.device.stat('/data')

    @awaiter
    async def test_filesync_read_invalid_response_error(self):
        self.assertTrue(await self.device.connect())
        self.transport.bulk_write_data = b''

        # Provide the `bulk_read` return values
        self.transport.bulk_read_data = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                      AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                      AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=join_messages(FileSyncStatMessage(constants.DENT, 1, 2, 3),
                                                                                                                            FileSyncStatMessage(constants.DONE, 0, 0, 0))))

        with self.assertRaises(exceptions.InvalidResponseError):
            await self.device.stat('/data')
