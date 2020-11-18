import logging
from io import BytesIO
import sys
import time
import unittest

from mock import patch

from adb_shell import constants, exceptions
from adb_shell.adb_device import AdbDevice, AdbDeviceTcp, DeviceFile
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

_LOGGER2 = logging.getLogger(__name__)
_LOGGER2.setLevel(logging.DEBUG)
_LOGGER2.addHandler(logging.StreamHandler(sys.stdout))


class AdbDeviceTest2(AdbDevice):
    def __init__(self, transport, banner=None):
        AdbDevice.__init__(self, transport, banner)

    def _filesync_flush(self, adb_info, filesync_info):
        _LOGGER2.info("AdbDevice._filesync_flush({}, {})".format(adb_info, filesync_info))
        return AdbDevice._filesync_flush(self, adb_info, filesync_info)

    def _filesync_read(self, expected_ids, adb_info, filesync_info, read_data=True):
        _LOGGER2.info("AdbDevice._filesync_read({}, {}, {}, {})".format(expected_ids, adb_info, filesync_info, read_data))
        return AdbDevice._filesync_read(self, expected_ids, adb_info, filesync_info, read_data)

    def _filesync_read_buffered(self, size, adb_info, filesync_info):
        _LOGGER2.info("AdbDevice._filesync_read_buffered({}, {}, {})".format(size, adb_info, filesync_info))
        return AdbDevice._filesync_read_buffered(self, size, adb_info, filesync_info)

    def _filesync_read_until(self, expected_ids, finish_ids, adb_info, filesync_info):
        _LOGGER2.info("AdbDevice._filesynce_read_until({}, {}, {}, {})".format(expected_ids, finish_ids, adb_info, filesync_info))
        return AdbDevice._filesynce_read_until(self, expected_ids, finish_ids, adb_info, filesync_info)

    def _filesync_send(self, command_id, adb_info, filesync_info, data=b'', size=None):
        _LOGGER2.info("AdbDevice._filesync_send({}, {}, {}, {}, {})".format(command_id, adb_info, filesync_info, data, size))
        return AdbDevice._filesync_send(command_id, adb_info, filesync_info, data, size)

    def _open(self, destination, adb_info):
        _LOGGER2.info("AdbDevice._open({}, {})".format(destination, adb_info))
        return AdbDevice._open(self, destination, adb_info)

    def _push(self, stream, device_path, st_mode, mtime, progress_callback, adb_info, filesync_info):
        _LOGGER2.info("AdbDevice._push({}, '{}', {}, {}, {}, {}, {})".format(stream, device_path, st_mode, mtime, progress_callback, adb_info, filesync_info))
        return AdbDevice._push(self, stream, device_path, st_mode, mtime, progress_callback, adb_info, filesync_info)

    def push(self, local_path, device_path, st_mode=constants.DEFAULT_PUSH_MODE, mtime=0, progress_callback=None, transport_timeout_s=None, read_timeout_s=constants.DEFAULT_READ_TIMEOUT_S):
        _LOGGER2.info("AdbDevice.push('{}', '{}', {}, {}, {}, {}, {})".format(local_path, device_path, st_mode, mtime, progress_callback, transport_timeout_s, read_timeout_s))
        return AdbDevice.push(self, local_path, device_path, st_mode, mtime, progress_callback, transport_timeout_s, read_timeout_s)

    def _send(self, msg, adb_info):
        _LOGGER2.info("AdbDevice._send({}, {})".format(msg, adb_info))
        return AdbDevice._send(self, msg, adb_info)


def parse_module(infile):
    with open(infile) as f:
         for line in f.readlines():
             if line.strip().startswith("def "):
                 parse_function(line)
                 print()

def parse_function(line):
     name = line.split("(")[0].split()[-1]
     args = line.split("(")[1].split(")")[0]
     args_list = args.split(",")
     arg_names = [arg.split("=")[0].strip() for arg in args_list]
     args_format = ", ".join(["{}" for _ in arg_names[1:]])
     args_str = ", ".join(arg_names[1:])
     print("    {}".format(line.strip()))
     print("        _LOGGER2.info(\"AdbDevice.{}({})\".format({}))".format(name, args_format, args_str))
     print("        return AdbDevice.{}(self, {})".format(name, args_str))


class AdbDeviceTest(AdbDevice):
    def __init__(self, transport, banner=None):
        _LOGGER2.info("AdbDevice.__init__({}, {})".format(transport, banner))
        return AdbDevice.__init__(self, transport, banner)

    def close(self):
        _LOGGER2.info("AdbDevice.close()".format())
        return AdbDevice.close(self)

    def connect(self, rsa_keys=None, transport_timeout_s=None, auth_timeout_s=constants.DEFAULT_AUTH_TIMEOUT_S, read_timeout_s=constants.DEFAULT_READ_TIMEOUT_S, auth_callback=None):
        _LOGGER2.info("AdbDevice.connect({}, {}, {}, {}, {})".format(rsa_keys, transport_timeout_s, auth_timeout_s, read_timeout_s, auth_callback))
        return AdbDevice.connect(self, rsa_keys, transport_timeout_s, auth_timeout_s, read_timeout_s, auth_callback)

    def _service(self, service, command, transport_timeout_s=None, read_timeout_s=constants.DEFAULT_READ_TIMEOUT_S, timeout_s=None, decode=True):
        _LOGGER2.info("AdbDevice._service({}, {}, {}, {}, {}, {})".format(service, command, transport_timeout_s, read_timeout_s, timeout_s, decode))
        return AdbDevice._service(self, service, command, transport_timeout_s, read_timeout_s, timeout_s, decode)

    def _streaming_service(self, service, command, transport_timeout_s=None, read_timeout_s=constants.DEFAULT_READ_TIMEOUT_S, decode=True):
        _LOGGER2.info("AdbDevice._streaming_service({}, {}, {}, {}, {})".format(service, command, transport_timeout_s, read_timeout_s, decode))
        return AdbDevice._streaming_service(self, service, command, transport_timeout_s, read_timeout_s, decode)

    def root(self, transport_timeout_s=None, read_timeout_s=constants.DEFAULT_READ_TIMEOUT_S, timeout_s=None):
        _LOGGER2.info("AdbDevice.root({}, {}, {})".format(transport_timeout_s, read_timeout_s, timeout_s))
        return AdbDevice.root(self, transport_timeout_s, read_timeout_s, timeout_s)

    def shell(self, command, transport_timeout_s=None, read_timeout_s=constants.DEFAULT_READ_TIMEOUT_S, timeout_s=None, decode=True):
        _LOGGER2.info("AdbDevice.shell({}, {}, {}, {}, {})".format(command, transport_timeout_s, read_timeout_s, timeout_s, decode))
        return AdbDevice.shell(self, command, transport_timeout_s, read_timeout_s, timeout_s, decode)

    def streaming_shell(self, command, transport_timeout_s=None, read_timeout_s=constants.DEFAULT_READ_TIMEOUT_S, decode=True):
        _LOGGER2.info("AdbDevice.streaming_shell({}, {}, {}, {})".format(command, transport_timeout_s, read_timeout_s, decode))
        return AdbDevice.streaming_shell(self, command, transport_timeout_s, read_timeout_s, decode)

    def list(self, device_path, transport_timeout_s=None, read_timeout_s=constants.DEFAULT_READ_TIMEOUT_S):
        _LOGGER2.info("AdbDevice.list('{}', {}, {})".format(device_path, transport_timeout_s, read_timeout_s))
        return AdbDevice.list(self, device_path, transport_timeout_s, read_timeout_s)

    def pull(self, device_path, local_path, progress_callback=None, transport_timeout_s=None, read_timeout_s=constants.DEFAULT_READ_TIMEOUT_S):
        _LOGGER2.info("AdbDevice.pull('{}', '{}', {}, {}, {})".format(device_path, local_path, progress_callback, transport_timeout_s, read_timeout_s))
        return AdbDevice.pull(self, device_path, local_path, progress_callback, transport_timeout_s, read_timeout_s)

    def _pull(self, device_path, stream, progress_callback, adb_info, filesync_info):
        _LOGGER2.info("AdbDevice._pull('{}', {}, {}, {}, {})".format(device_path, stream, progress_callback, adb_info, filesync_info))
        return AdbDevice._pull(self, device_path, stream, progress_callback, adb_info, filesync_info)

    def push(self, local_path, device_path, st_mode=constants.DEFAULT_PUSH_MODE, mtime=0, progress_callback=None, transport_timeout_s=None, read_timeout_s=constants.DEFAULT_READ_TIMEOUT_S):
        _LOGGER2.info("AdbDevice.push('{}', '{}', {}, {}, {}, {}, {})".format(local_path, device_path, st_mode, mtime, progress_callback, transport_timeout_s, read_timeout_s))
        return AdbDevice.push(self, local_path, device_path, st_mode, mtime, progress_callback, transport_timeout_s, read_timeout_s)

    def _push(self, stream, device_path, st_mode, mtime, progress_callback, adb_info, filesync_info):
        _LOGGER2.info("AdbDevice._push({}, '{}', {}, {}, {}, {}, {})".format(stream, device_path, st_mode, mtime, progress_callback, adb_info, filesync_info))
        return AdbDevice._push(self, stream, device_path, st_mode, mtime, progress_callback, adb_info, filesync_info)

    def stat(self, device_path, transport_timeout_s=None, read_timeout_s=constants.DEFAULT_READ_TIMEOUT_S):
        _LOGGER2.info("AdbDevice.stat('{}', {}, {})".format(device_path, transport_timeout_s, read_timeout_s))
        return AdbDevice.stat(self, device_path, transport_timeout_s, read_timeout_s)

    def _close(self, adb_info):
        _LOGGER2.info("AdbDevice._close({})".format(adb_info))
        return AdbDevice._close(self, adb_info)

    def _okay(self, adb_info):
        _LOGGER2.info("AdbDevice._okay({})".format(adb_info))
        return AdbDevice._okay(self, adb_info)

    def _open(self, destination, adb_info):
        _LOGGER2.info("AdbDevice._open({}, {})".format(destination, adb_info))
        return AdbDevice._open(self, destination, adb_info)

    def _read(self, expected_cmds, adb_info):
        _LOGGER2.info("AdbDevice._read({}, {})".format(expected_cmds, adb_info))
        return AdbDevice._read(self, expected_cmds, adb_info)

    def _read_until(self, expected_cmds, adb_info):
        _LOGGER2.info("AdbDevice._read_until({}, {})".format(expected_cmds, adb_info))
        return AdbDevice._read_until(self, expected_cmds, adb_info)

    def _read_until_close(self, adb_info):
        _LOGGER2.info("AdbDevice._read_until_close({})".format(adb_info))
        return AdbDevice._read_until_close(self, adb_info)

    def _send(self, msg, adb_info):
        _LOGGER2.info("AdbDevice._send({}, {})".format(msg, adb_info))
        return AdbDevice._send(self, msg, adb_info)

    def _streaming_command(self, service, command, adb_info):
        _LOGGER2.info("AdbDevice._streaming_command({}, {}, {})".format(service, command, adb_info))
        return AdbDevice._streaming_command(self, service, command, adb_info)

    def _write(self, data, adb_info):
        _LOGGER2.info("AdbDevice._write({}, {})".format(data, adb_info))
        return AdbDevice._write(self, data, adb_info)

    def _filesync_flush(self, adb_info, filesync_info):
        _LOGGER2.info("AdbDevice._filesync_flush({}, {})".format(adb_info, filesync_info))
        return AdbDevice._filesync_flush(self, adb_info, filesync_info)

    def _filesync_read(self, expected_ids, adb_info, filesync_info, read_data=True):
        _LOGGER2.info("AdbDevice._filesync_read({}, {}, {}, {})".format(expected_ids, adb_info, filesync_info, read_data))
        return AdbDevice._filesync_read(self, expected_ids, adb_info, filesync_info, read_data)

    def _filesync_read_buffered(self, size, adb_info, filesync_info):
        _LOGGER2.info("AdbDevice._filesync_read_buffered({}, {}, {})".format(size, adb_info, filesync_info))
        return AdbDevice._filesync_read_buffered(self, size, adb_info, filesync_info)

    def _filesync_read_until(self, expected_ids, finish_ids, adb_info, filesync_info):
        _LOGGER2.info("AdbDevice._filesync_read_until({}, {}, {}, {})".format(expected_ids, finish_ids, adb_info, filesync_info))
        return AdbDevice._filesync_read_until(self, expected_ids, finish_ids, adb_info, filesync_info)

    def _filesync_send(self, command_id, adb_info, filesync_info, data=b'', size=None):
        _LOGGER2.info("AdbDevice._filesync_send({}, {}, {}, {}, {})".format(command_id, adb_info, filesync_info, data, size))
        return AdbDevice._filesync_send(self, command_id, adb_info, filesync_info, data, size)


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
        self.device = AdbDevice(transport=patchers.FakeTcpTransport('host', 5555))
        self.device._transport._bulk_read = b''.join(patchers.BULK_READ_LIST)

    def tearDown(self):
        self.assertFalse(self.device._transport._bulk_read)

    def test_adb_connection_error(self):
        with self.assertRaises(exceptions.AdbConnectionError):
            self.device.shell('FAIL')

        with self.assertRaises(exceptions.AdbConnectionError):
            ''.join(self.device.streaming_shell('FAIL'))

        with self.assertRaises(exceptions.AdbConnectionError):
            self.device.root()

        with self.assertRaises(exceptions.AdbConnectionError):
            self.device.list('FAIL')

        with self.assertRaises(exceptions.AdbConnectionError):
            self.device.push('FAIL', 'FAIL')

        with self.assertRaises(exceptions.AdbConnectionError):
            self.device.pull('FAIL', 'FAIL')

        with self.assertRaises(exceptions.AdbConnectionError):
            self.device.stat('FAIL')

        self.device._transport._bulk_read = b''

    def test_init_tcp(self):
        with patchers.PATCH_TCP_TRANSPORT:
            tcp_device = AdbDeviceTcp('host')
            tcp_device._transport._bulk_read = self.device._transport._bulk_read

        # Make sure that the `connect()` method works
        self.assertTrue(tcp_device.connect())
        self.assertTrue(tcp_device.available)

        # Clear the `_bulk_read` buffer so that `self.tearDown()` passes
        self.device._transport._bulk_read = b''
        

    def test_init_banner(self):
        device_with_banner = AdbDevice(transport=patchers.FakeTcpTransport('host', 5555), banner='banner')
        self.assertEqual(device_with_banner._banner, b'banner')

        device_with_banner2 = AdbDevice(transport=patchers.FakeTcpTransport('host', 5555), banner=bytearray('banner2', 'utf-8'))
        self.assertEqual(device_with_banner2._banner, b'banner2')

        device_with_banner3 = AdbDevice(transport=patchers.FakeTcpTransport('host', 5555), banner=u'banner3')
        self.assertEqual(device_with_banner3._banner, b'banner3')

        with patch('socket.gethostname', side_effect=Exception):
            device_banner_unknown = AdbDevice(transport=patchers.FakeTcpTransport('host', 5555))
            device_banner_unknown._transport._bulk_read = self.device._transport._bulk_read
            self.assertTrue(device_banner_unknown.connect())
            self.assertEqual(device_banner_unknown._banner, b'unknown')

        # Clear the `_bulk_read` buffer so that `self.tearDown()` passes
        self.device._transport._bulk_read = b''

    def test_init_invalid_transport(self):
        with self.assertRaises(exceptions.InvalidTransportError):
            device = AdbDevice(transport=123)

        # Clear the `_bulk_read` buffer so that `self.tearDown()` passes
        self.device._transport._bulk_read = b''

    def test_available(self):
        self.assertFalse(self.device.available)

        # Clear the `_bulk_read` buffer so that `self.tearDown()` passes
        self.device._transport._bulk_read = b''

    def test_close(self):
        self.assertFalse(self.device.close())
        self.assertFalse(self.device.available)

        # Clear the `_bulk_read` buffer so that `self.tearDown()` passes
        self.device._transport._bulk_read = b''

    # ======================================================================= #
    #                                                                         #
    #                             `connect` tests                             #
    #                                                                         #
    # ======================================================================= #
    def test_connect(self):
        self.assertTrue(self.device.connect())
        self.assertTrue(self.device.available)

    def test_connect_no_keys(self):
        self.device._transport._bulk_read = b''.join(patchers.BULK_READ_LIST_WITH_AUTH[:2])
        with self.assertRaises(exceptions.DeviceAuthError):
            self.device.connect()

        self.assertFalse(self.device.available)

    def test_connect_with_key_invalid_response(self):
        with patch('adb_shell.auth.sign_pythonrsa.open', open_priv_pub), patch('adb_shell.auth.keygen.open', open_priv_pub):
            keygen('tests/adbkey')
            signer = PythonRSASigner.FromRSAKeyPath('tests/adbkey')

        self.device._transport._bulk_read = b''.join(patchers.BULK_READ_LIST_WITH_AUTH_INVALID)

        with self.assertRaises(exceptions.InvalidResponseError):
            self.device.connect([signer])

        self.assertFalse(self.device.available)

    def test_connect_with_key(self):
        with patch('adb_shell.auth.sign_pythonrsa.open', open_priv_pub), patch('adb_shell.auth.keygen.open', open_priv_pub):
            keygen('tests/adbkey')
            signer = PythonRSASigner.FromRSAKeyPath('tests/adbkey')

        self.device._transport._bulk_read = b''.join(patchers.BULK_READ_LIST_WITH_AUTH)

        self.assertTrue(self.device.connect([signer]))

    def test_connect_with_new_key(self):
        with patch('adb_shell.auth.sign_pythonrsa.open', open_priv_pub), patch('adb_shell.auth.keygen.open', open_priv_pub):
            keygen('tests/adbkey')
            signer = PythonRSASigner.FromRSAKeyPath('tests/adbkey')
            signer.pub_key = u''

        self.device._transport._bulk_read = b''.join(patchers.BULK_READ_LIST_WITH_AUTH_NEW_KEY)

        self.assertTrue(self.device.connect([signer]))

    def test_connect_with_new_key_and_callback(self):
        with patch('adb_shell.auth.sign_pythonrsa.open', open_priv_pub), patch('adb_shell.auth.keygen.open', open_priv_pub):
            keygen('tests/adbkey')
            signer = PythonRSASigner.FromRSAKeyPath('tests/adbkey')
            signer.pub_key = u''

        self._callback_invoked = False
        def auth_callback(device):
            self._callback_invoked = True

        self.device._transport._bulk_read = b''.join(patchers.BULK_READ_LIST_WITH_AUTH_NEW_KEY)

        self.assertTrue(self.device.connect([signer], auth_callback=auth_callback))
        self.assertTrue(self._callback_invoked)


    # ======================================================================= #
    #                                                                         #
    #                              `shell` tests                              #
    #                                                                         #
    # ======================================================================= #
    def test_shell_no_return(self):
        self.assertTrue(self.device.connect())

        # Provide the `bulk_read` return values
        self.device._transport._bulk_read = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                          AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b''))

        self.assertEqual(self.device.shell('TEST'), '')

    def test_shell_return_pass(self):
        self.assertTrue(self.device.connect())

        # Provide the `bulk_read` return values
        self.device._transport._bulk_read = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                          AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'PA'),
                                                          AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'SS'),
                                                          AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b''))

        self.assertEqual(self.device.shell('TEST'), 'PASS')

    def test_shell_dont_decode(self):
        self.assertTrue(self.device.connect())
        
        # Provide the `bulk_read` return values
        self.device._transport._bulk_read = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                          AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'PA'),
                                                          AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'SS'),
                                                          AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b''))

        self.assertEqual(self.device.shell('TEST', decode=False), b'PASS')

    def test_shell_data_length_exceeds_max(self):
        self.assertTrue(self.device.connect())

        # Provide the `bulk_read` return values
        self.device._transport._bulk_read = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                          AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'0'*(constants.MAX_ADB_DATA+1)),
                                                          AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b''))

        self.device.shell('TEST')
        self.assertTrue(True)

    def test_shell_multibytes_sequence_exceeds_max(self):
        self.assertTrue(self.device.connect())

        # Provide the `bulk_read` return values
        self.device._transport._bulk_read = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                          AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'0'*(constants.MAX_ADB_DATA-1) + b'\xe3\x81\x82'),
                                                          AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b''))

        self.assertEqual(u'0'*(constants.MAX_ADB_DATA-1) + u'\u3042', self.device.shell('TEST'))

    def test_shell_with_multibytes_sequence_over_two_messages(self):
        self.assertTrue(self.device.connect())

        # Provide the `bulk_read` return values
        self.device._transport._bulk_read = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                          AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'\xe3'),
                                                          AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'\x81\x82'),
                                                          AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b''))

        self.assertEqual(u'\u3042', self.device.shell('TEST'))

    def test_shell_multiple_clse(self):
        # https://github.com/JeffLIrion/adb_shell/issues/15#issuecomment-536795938
        self.assertTrue(self.device.connect())

        # Provide the `bulk_read` return values
        msg1 = AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'')
        msg2 = AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'PASS')
        msg3 = AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b'')
        self.device._transport._bulk_read = b''.join([b'OKAY\xd9R\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xb0\xb4\xbe\xa6',
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
        self.device._transport._bulk_read = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1234, data=b'\x00'))

        with self.assertRaises(exceptions.InvalidResponseError):
            self.device.shell('TEST')

    def test_shell_error_unknown_command(self):
        self.assertTrue(self.device.connect())

        # Provide the `bulk_read` return values
        self.device._transport._bulk_read = join_messages(AdbMessageForTesting(command=constants.FAIL, arg0=1, arg1=1, data=b''))

        with self.assertRaises(exceptions.InvalidCommandError):
            self.assertEqual(self.device.shell('TEST'), '')

    def test_shell_error_transport_timeout(self):
        self.assertTrue(self.device.connect())

        # Provide the `bulk_read` return values
        self.device._transport._bulk_read = join_messages(AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b''))

        with self.assertRaises(exceptions.InvalidCommandError):
            self.device.shell('TEST', read_timeout_s=-1)

    def test_shell_error_read_timeout_multiple_clse(self):
        self.assertTrue(self.device.connect())

        # Provide the `bulk_read` return values
        self.device._transport._bulk_read = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b''),
                                                          AdbMessage(command=constants.CLSE, arg0=2, arg1=1, data=b''))

        with self.assertRaises(exceptions.InvalidCommandError):
            self.device.shell('TEST', read_timeout_s=-1)

    def test_shell_error_timeout(self):
        self.assertTrue(self.device.connect())

        # Provide the `bulk_read` return values
        self.device._transport._bulk_read = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                          AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'PA'),
                                                          AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'SS'),
                                                          AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b''))

        def fake_read_until(*args, **kwargs):
            time.sleep(0.2)
            return b'WRTE', b'PA'

        with patch('adb_shell.adb_device.AdbDevice._read_until', fake_read_until):
            with self.assertRaises(exceptions.AdbTimeoutError):
                self.device.shell('TEST', timeout_s=0.5)

        # Clear the `_bulk_read` buffer so that `self.tearDown()` passes
        self.device._transport._bulk_read = b''

    def test_shell_error_checksum(self):
        self.assertTrue(self.device.connect())

        # Provide the `bulk_read` return values
        msg1 = AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00')
        msg2 = AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'PASS')
        self.device._transport._bulk_read = b''.join([msg1.pack(), msg1.data, msg2.pack(), msg2.data[:-1] + b'0'])

        with self.assertRaises(exceptions.InvalidChecksumError):
            self.device.shell('TEST')

    def test_shell_error_local_id2(self):
        self.assertTrue(self.device.connect())

        # Provide the `bulk_read` return values
        self.device._transport._bulk_read = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                          AdbMessage(command=constants.WRTE, arg0=1, arg1=2, data=b'PASS'))

        with self.assertRaises(exceptions.InterleavedDataError):
            self.device.shell('TEST')
            self.device.shell('TEST')

    def test_shell_error_remote_id2(self):
        self.assertTrue(self.device.connect())

        # Provide the `bulk_read` return values
        self.device._transport._bulk_read = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                          AdbMessage(command=constants.WRTE, arg0=2, arg1=1, data=b'PASS'))

        with self.assertRaises(exceptions.InvalidResponseError):
            self.device.shell('TEST')

    def test_issue29(self):
        # https://github.com/JeffLIrion/adb_shell/issues/29
        with patch('adb_shell.auth.sign_pythonrsa.open', open_priv_pub), patch('adb_shell.auth.keygen.open', open_priv_pub):
            keygen('tests/adbkey')
            signer = PythonRSASigner.FromRSAKeyPath('tests/adbkey')

        msg1 = AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00')
        msg2 = AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b'')

        self.device._transport._bulk_read = b''.join([b'AUTH\x01\x00\x00\x00\x00\x00\x00\x00\x14\x00\x00\x00\xc5\n\x00\x00\xbe\xaa\xab\xb7',  # Line 22
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
    #                      `streaming_shell` tests                            #
    #                                                                         #
    # ======================================================================= #
    def test_streaming_shell_decode(self):
        self.assertTrue(self.device.connect())

        # Provide the `bulk_read` return values
        self.device._transport._bulk_read = join_messages(
            AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
            AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'ABC'),
            AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'123'),
        )

        generator = self.device.streaming_shell('TEST', decode=True)
        self.assertEqual('ABC', next(generator))
        self.assertEqual('123', next(generator))

    def test_streaming_shell_dont_decode(self):
        self.assertTrue(self.device.connect())

        # Provide the `bulk_read` return values
        self.device._transport._bulk_read = join_messages(
            AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
            AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'ABC'),
            AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=b'123'),
        )

        generator = self.device.streaming_shell('TEST', decode=False)
        self.assertEqual(b'ABC', next(generator))
        self.assertEqual(b'123', next(generator))


    # ======================================================================= #
    #                                                                         #
    #                               `root` test                               #
    #                                                                         #
    # ======================================================================= #
    def test_root(self):
        self.assertTrue(self.device.connect())

        with patch('adb_shell.adb_device.AdbDevice._service') as patch_service:
            self.device.root()
            patch_service.assert_called_once()

    # ======================================================================= #
    #                                                                         #
    #                         `filesync` tests                                #
    #                                                                         #
    # ======================================================================= #
    def test_list(self):
        self.assertTrue(self.device.connect())
        self.device._transport._bulk_write = b''

        # Provide the `bulk_read` return values
        self.device._transport._bulk_read = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
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

        self.assertEqual(expected_result, self.device.list('/dir'))
        self.assertEqual(expected_bulk_write, self.device._transport._bulk_write)

    def test_list_empty_path(self):
        with self.assertRaises(exceptions.DevicePathInvalidError):
            self.device.list("")
        with self.assertRaises(exceptions.DevicePathInvalidError):
            self.device.list(b"")
        with self.assertRaises(exceptions.DevicePathInvalidError):
            self.device.list(u"")
        with self.assertRaises(exceptions.DevicePathInvalidError):
            self.device.list(None)
        # Clear the `_bulk_read` buffer so that `self.tearDown()` passes
        self.device._transport._bulk_read = b''

    def test_push_fail(self):
        self.assertTrue(self.device.connect())
        self.device._transport._bulk_write = b''

        mtime = 100
        filedata = b'Ohayou sekai.\nGood morning world!'

        # Provide the `bulk_read` return values
        self.device._transport._bulk_read = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                          AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b''),
                                                          AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=join_messages(FileSyncMessage(constants.FAIL, data=b''))))

        with self.assertRaises(exceptions.PushFailedError), patch('adb_shell.adb_device.open', patchers.mock_open(read_data=filedata)):
            self.device.push('TEST_FILE', '/data', mtime=mtime)

    def test_push_file(self):
        self.assertTrue(self.device.connect())
        self.device._transport._bulk_write = b''

        mtime = 100
        filedata = b'Ohayou sekai.\nGood morning world!'

        # Provide the `bulk_read` return values
        self.device._transport._bulk_read = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
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

        with patch('adb_shell.adb_device.open', patchers.mock_open(read_data=filedata)):
            self.device.push('TEST_FILE', '/data', mtime=mtime)
            self.assertEqual(expected_bulk_write, self.device._transport._bulk_write)

    def test_push_issue113(self):
        # pytest tests/test_adb_device.py::TestAdbDevice::test_push_issue113 --log-cli-level=INFO
        def push_progress_callback(device_path, bytes_written, total_bytes):
            _LOGGER2.warning(f"ADB Push-Progress: {device_path} bytes_written:{bytes_written} total_bytes:{total_bytes}")

        self.device = AdbDeviceTest(transport=patchers.FakeTcpTransport('host', 5555))
        self.device._transport._bulk_read = b''.join(patchers.BULK_READ_LIST)
        self.device._transport._bulk_read = b''.join([b'CNXN\x01\x00\x00\x01\x00\x00\x10\x00\x10\x01\x00\x00\xa1f\x00\x00\xbc\xb1\xa7\xb1',
                                                      b'device::ro.product.name=sdk_gphone_x86_64_arm64;ro.product.model=sdk_gphone_x86_64_arm64;ro.product.device=generic_x86_64_arm64;features=sendrecv_v2_brotli,remount_shell,sendrecv_v2,abb_exec,fixed_push_mkdir,fixed_push_symlink_timestamp,abb,shell_v2,cmd,ls_v2,apex,stat_v2',
                                                      b'OKAYj\x06\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xb0\xb4\xbe\xa6',
                                                      b'WRTEj\x06\x00\x00\x01\x00\x00\x00 \x00\x00\x00\x8c\x0b\x00\x00\xa8\xad\xab\xba',
                                                      b'adbd is already running as root\n',
                                                      b'CLSEj\x06\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xbc\xb3\xac\xba'])

        self.assertTrue(self.device.connect())
        self.device.root()
        self.assertEqual(self.device._transport._bulk_read, b'')

        self.device._transport._bulk_write = b''

        mtime = 100
        filedata = b'Ohayou sekai.\nGood morning world!'

        # Provide the `bulk_read` return values
        self.device._transport._bulk_read = b''.join([b'CLSEj\x06\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xbc\xb3\xac\xba',
                                                      b'OKAYk\x06\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xb0\xb4\xbe\xa6'])
        #self.device._transport._bulk_read = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
        #                                                  AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b''),
        #                                                  AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=FileSyncMessage(constants.OKAY).pack()),
        #                                                  AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b''))

        # Expected `bulk_write` values
        expected_bulk_write = join_messages(AdbMessage(command=constants.OPEN, arg0=1, arg1=0, data=b'sync:\x00'),
                                            AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=join_messages(FileSyncMessage(command=constants.SEND, data=b'/data,33272'),
                                                                                                                  FileSyncMessage(command=constants.DATA, data=filedata),
                                                                                                                  FileSyncMessage(command=constants.DONE, arg0=mtime, data=b''))),
                                            AdbMessage(command=constants.OKAY, arg0=1, arg1=1),
                                            AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b''))

        class StSize:
            def __init__(self):
                self.st_size = -1

        with patch('adb_shell.adb_device.open', patchers.mock_open(read_data=filedata)), patch('os.fstat', return_value=StSize()):
            self.device.push('TEST_FILE', '/data', mtime=mtime, progress_callback=push_progress_callback)
            self.assertEqual(expected_bulk_write, self.device._transport._bulk_write)

    def test_push_file_mtime0(self):
        self.assertTrue(self.device.connect())
        self.device._transport._bulk_write = b''

        mtime = 0
        filedata = b'Ohayou sekai.\nGood morning world!'

        # Provide the `bulk_read` return values
        self.device._transport._bulk_read = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
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

        with patch('adb_shell.adb_device.open', patchers.mock_open(read_data=filedata)), patch('time.time', return_value=mtime):
            self.device.push('TEST_FILE', '/data', mtime=mtime)
            self.assertEqual(expected_bulk_write, self.device._transport._bulk_write)

    def test_push_big_file(self):
        self.assertTrue(self.device.connect())
        self.device._transport._bulk_write = b''

        mtime = 100
        filedata = b'0' * int(3.5 * self.device.max_chunk_size)

        # Provide the `bulk_read` return values
        self.device._transport._bulk_read = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
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

        with patch('adb_shell.adb_device.open', patchers.mock_open(read_data=filedata)):
            self.device.push('TEST_FILE', '/data', mtime=mtime)
            self.assertEqual(expected_bulk_write, self.device._transport._bulk_write)

    def test_push_dir(self):
        self.assertTrue(self.device.connect())

        mtime = 100
        filedata = b'Ohayou sekai.\nGood morning world!'

        # Provide the `bulk_read` return values
        self.device._transport._bulk_read = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
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

        with patch('adb_shell.adb_device.open', patchers.mock_open(read_data=filedata)), patch('os.path.isdir', lambda x: x == 'TEST_DIR/'), patch('os.listdir', return_value=['TEST_FILE1', 'TEST_FILE2']):
            self.device.push('TEST_DIR/', '/data', mtime=mtime)

    def test_push_empty_path(self):
        with self.assertRaises(exceptions.DevicePathInvalidError):
            self.device.push("NOTHING", "")
        with self.assertRaises(exceptions.DevicePathInvalidError):
            self.device.push("NOTHING", b"")
        with self.assertRaises(exceptions.DevicePathInvalidError):
            self.device.push("NOTHING", u"")
        with self.assertRaises(exceptions.DevicePathInvalidError):
            self.device.push("NOTHING", None)
        # Clear the `_bulk_read` buffer so that `self.tearDown()` passes
        self.device._transport._bulk_read = b''

    def test_pull_file(self):
        self.assertTrue(self.device.connect())
        self.device._transport._bulk_write = b''

        filedata = b'Ohayou sekai.\nGood morning world!'

        # Provide the `bulk_read` return values
        self.device._transport._bulk_read = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                          AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                          AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=join_messages(FileSyncMessage(command=constants.DATA, data=filedata),
                                                                                                                                FileSyncMessage(command=constants.DONE))),
                                                          AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b''))

        # Expected `bulk_write` values
        expected_bulk_write = join_messages(AdbMessage(command=constants.OPEN, arg0=1, arg1=0, data=b'sync:\x00'),
                                            AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=join_messages(FileSyncMessage(command=constants.RECV, data=b'/data'))),
                                            AdbMessage(command=constants.OKAY, arg0=1, arg1=1),
                                            AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b''))

        with patch('adb_shell.adb_device.open', patchers.mock_open()) as m:
            self.device.pull('/data', 'TEST_FILE')
            self.assertEqual(m.written, filedata)
            self.assertEqual(expected_bulk_write, self.device._transport._bulk_write)

    def test_pull_big_file(self):
        self.assertTrue(self.device.connect())
        self.device._transport._bulk_write = b''

        filedata = b'0' * int(1.5 * constants.MAX_ADB_DATA)

        # Provide the `bulk_read` return values
        self.device._transport._bulk_read = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                          AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                          AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=join_messages(FileSyncMessage(command=constants.DATA, data=filedata),
                                                                                                                                FileSyncMessage(command=constants.DONE))),
                                                          AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b''))

        # Expected `bulk_write` values
        expected_bulk_write = join_messages(AdbMessage(command=constants.OPEN, arg0=1, arg1=0, data=b'sync:\x00'),
                                            AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=join_messages(FileSyncMessage(command=constants.RECV, data=b'/data'))),
                                            AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b''),
                                            AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b''))

        with patch('adb_shell.adb_device.open', patchers.mock_open()) as m:
            self.device.pull('/data', 'TEST_FILE')
            self.assertEqual(m.written, filedata)
            self.assertEqual(expected_bulk_write, self.device._transport._bulk_write)

    def test_pull_empty_path(self):
        with self.assertRaises(exceptions.DevicePathInvalidError):
            self.device.pull("", "NOWHERE")
        with self.assertRaises(exceptions.DevicePathInvalidError):
            self.device.pull(b"", "NOWHERE")
        with self.assertRaises(exceptions.DevicePathInvalidError):
            self.device.pull(u"", "NOWHERE")
        with self.assertRaises(exceptions.DevicePathInvalidError):
            self.device.pull(None, "NOWHERE")
        # Clear the `_bulk_read` buffer so that `self.tearDown()` passes
        self.device._transport._bulk_read = b''

    def test_stat(self):
        self.assertTrue(self.device.connect())
        self.device._transport._bulk_write = b''

        # Provide the `bulk_read` return values
        self.device._transport._bulk_read = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                          AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                          AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=join_messages(FileSyncStatMessage(constants.STAT, 1, 2, 3),
                                                                                                                                FileSyncStatMessage(constants.DONE, 0, 0, 0))),
                                                          AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b''))

        # Expected `bulk_write` values
        expected_bulk_write = join_messages(AdbMessage(command=constants.OPEN, arg0=1, arg1=0, data=b'sync:\x00'),
                                            AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=join_messages(FileSyncMessage(command=constants.STAT, data=b'/data'))),
                                            AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b''),
                                            AdbMessage(command=constants.CLSE, arg0=1, arg1=1, data=b''))

        self.assertEqual((1, 2, 3), self.device.stat('/data'))
        self.assertEqual(expected_bulk_write, self.device._transport._bulk_write)

    def test_stat_empty_path(self):
        with self.assertRaises(exceptions.DevicePathInvalidError):
            self.device.stat("")
        with self.assertRaises(exceptions.DevicePathInvalidError):
            self.device.stat(b"")
        with self.assertRaises(exceptions.DevicePathInvalidError):
            self.device.stat(u"")
        with self.assertRaises(exceptions.DevicePathInvalidError):
            self.device.stat(None)
        # Clear the `_bulk_read` buffer so that `self.tearDown()` passes
        self.device._transport._bulk_read = b''

    # ======================================================================= #
    #                                                                         #
    #                  `filesync` hidden methods tests                        #
    #                                                                         #
    # ======================================================================= #
    def test_filesync_read_adb_command_failure_exceptions(self):
        self.assertTrue(self.device.connect())
        self.device._transport._bulk_write = b''

        # Provide the `bulk_read` return values
        self.device._transport._bulk_read = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                          AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                          AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=join_messages(FileSyncStatMessage(constants.FAIL, 1, 2, 3),
                                                                                                                                FileSyncStatMessage(constants.DONE, 0, 0, 0))))

        with self.assertRaises(exceptions.AdbCommandFailureException):
            self.device.stat('/data')

    def test_filesync_read_invalid_response_error(self):
        self.assertTrue(self.device.connect())
        self.device._transport._bulk_write = b''

        # Provide the `bulk_read` return values
        self.device._transport._bulk_read = join_messages(AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                          AdbMessage(command=constants.OKAY, arg0=1, arg1=1, data=b'\x00'),
                                                          AdbMessage(command=constants.WRTE, arg0=1, arg1=1, data=join_messages(FileSyncStatMessage(constants.DENT, 1, 2, 3),
                                                                                                                                FileSyncStatMessage(constants.DONE, 0, 0, 0))))

        with self.assertRaises(exceptions.InvalidResponseError):
            self.device.stat('/data')
