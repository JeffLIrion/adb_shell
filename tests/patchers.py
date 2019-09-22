from mock import patch

from adb_shell import constants
from adb_shell.adb_message import AdbMessage, unpack
from adb_shell.tcp_handle import TcpHandle


MSG_CONNECT = AdbMessage(command=constants.CNXN, arg0=constants.VERSION, arg1=constants.MAX_ADB_DATA, data=b'host::unknown\0')

# BULK_READ_LIST0 = [b'CNXN\x00\x00\x00\x00\x00\x00\x00\x00\t\x00\x00\x00\xe4\x02\x00\x00\xbc\xb1\xa7\xb1', bytearray(b'device::\x00')]


class FakeSocket(object):
    def __init__(self):
        self.recv_list = [b'']

    def close(self):
        pass

    def recv(self, bufsize):
        return self.recv_list.pop(0)

    def send(self, data):
        pass

    def setblocking(self, *args, **kwargs):
        pass

    def shutdown(self, how):
        pass


class FakeTcpHandle(TcpHandle):
    def close(self):
        self._connection = None

    def connect(self, auth_timeout_s=None):
        self._connection = True
        self.bulk_read_list = [MSG_CONNECT.pack(), MSG_CONNECT.data]

    def bulk_read(self, numbytes, timeout_s=None):
        return self.bulk_read_list.pop(0)

    def bulk_write(self, data, timeout_s=None):
        return len(data)


# `socket` patches
patch_create_connection = patch('socket.create_connection', return_value=FakeSocket())


# `select` patches
patch_select_success = patch('select.select', return_value=(True, True, True))

patch_select_fail = patch('select.select', return_value=(False, False, False))


# `TcpHandle` patches
patch_tcp_handle = patch('adb_shell.adb_device.TcpHandle', FakeTcpHandle)
