from unittest.mock import patch

from adb_shell import constants
from adb_shell.adb_message import AdbMessage, unpack
from adb_shell.handle.tcp_handle_async import TcpHandleAsync


class FakeStreamWriter:
    def close(self):
        pass

    async def wait_closed(self):
        pass

    def write(self, data):
        pass

    async def drain(self):
        pass


class FakeStreamReader:
    async def read(self, numbytes):
        return b'TEST'


class FakeTcpHandleAsync(TcpHandleAsync):
    def __init__(self, *args, **kwargs):
        TcpHandleAsync.__init__(self, *args, **kwargs)
        self._bulk_read = b''
        self._bulk_write = b''

    async def close(self):
        self._reader = None
        self._writer = None

    async def connect(self, auth_timeout_s=None):
        self._reader = True
        self._writer = True

    async def bulk_read(self, numbytes, timeout_s=None):
        num = min(numbytes, constants.MAX_ADB_DATA)
        ret = self._bulk_read[:num]
        self._bulk_read = self._bulk_read[num:]
        return ret

    async def bulk_write(self, data, timeout_s=None):
        self._bulk_write += data
        return len(data)


# `TcpHandle` patches
PATCH_TCP_HANDLE_ASYNC = patch('adb_shell.adb_device_async.TcpHandleAsync', FakeTcpHandleAsync)
