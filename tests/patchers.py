from mock import patch

from adb_shell import constants
from adb_shell.adb_message import AdbMessage
from adb_shell.handle.tcp_handle import TcpHandle


MSG_CONNECT = AdbMessage(command=constants.CNXN, arg0=0, arg1=0, data=b'host::unknown\0')
MSG_CONNECT_WITH_AUTH_INVALID = AdbMessage(command=constants.AUTH, arg0=0, arg1=0, data=b'host::unknown\0')
MSG_CONNECT_WITH_AUTH1 = AdbMessage(command=constants.AUTH, arg0=constants.AUTH_TOKEN, arg1=0, data=b'host::unknown\0')
MSG_CONNECT_WITH_AUTH2 = AdbMessage(command=constants.CNXN, arg0=0, arg1=0, data=b'host::unknown\0')
MSG_CONNECT_WITH_AUTH_NEW_KEY2 = AdbMessage(command=constants.AUTH, arg0=0, arg1=0, data=b'host::unknown\0')
MSG_CONNECT_WITH_AUTH_NEW_KEY3 = AdbMessage(command=constants.CNXN, arg0=0, arg1=0, data=b'host::unknown\0')

BULK_READ_LIST = [MSG_CONNECT.pack(), MSG_CONNECT.data]
BULK_READ_LIST_WITH_AUTH_INVALID = [MSG_CONNECT_WITH_AUTH_INVALID.pack(), MSG_CONNECT_WITH_AUTH_INVALID.data]
BULK_READ_LIST_WITH_AUTH = [MSG_CONNECT_WITH_AUTH1.pack(), MSG_CONNECT_WITH_AUTH1.data, MSG_CONNECT_WITH_AUTH2.pack(), MSG_CONNECT_WITH_AUTH2.data]
BULK_READ_LIST_WITH_AUTH_NEW_KEY = [MSG_CONNECT_WITH_AUTH1.pack(), MSG_CONNECT_WITH_AUTH1.data, MSG_CONNECT_WITH_AUTH_NEW_KEY2.pack(), MSG_CONNECT_WITH_AUTH_NEW_KEY2.data, MSG_CONNECT_WITH_AUTH_NEW_KEY3.pack(), MSG_CONNECT_WITH_AUTH_NEW_KEY3.data]


class FakeSocket(object):
    def __init__(self):
        self._recv = b''

    def close(self):
        pass

    def recv(self, bufsize):
        ret = self._recv[:bufsize]
        self._recv = self._recv[bufsize:]
        return ret

    def send(self, data):
        pass

    def setblocking(self, *args, **kwargs):
        pass

    def shutdown(self, how):
        pass


class FakeTcpHandle(TcpHandle):
    def __init__(self, *args, **kwargs):
        TcpHandle.__init__(self, *args, **kwargs)
        self._bulk_read = b''
        self._bulk_write = b''

    def close(self):
        self._connection = None

    def connect(self, timeout_s=None):
        self._connection = True

    def bulk_read(self, numbytes, timeout_s=None):
        num = min(numbytes, constants.MAX_ADB_DATA)
        ret = self._bulk_read[:num]
        self._bulk_read = self._bulk_read[num:]
        return ret

    def bulk_write(self, data, timeout_s=None):
        self._bulk_write += data
        return len(data)


# `socket` patches
PATCH_CREATE_CONNECTION = patch('socket.create_connection', return_value=FakeSocket())


# `select` patches
PATCH_SELECT_SUCCESS = patch('select.select', return_value=(True, True, True))

PATCH_SELECT_FAIL = patch('select.select', return_value=(False, False, False))


# `TcpHandle` patches
PATCH_TCP_HANDLE = patch('adb_shell.adb_device.TcpHandle', FakeTcpHandle)
