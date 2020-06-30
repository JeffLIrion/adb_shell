try:
    from contextlib import asynccontextmanager
except ImportError:
    asynccontextmanager = lambda func: func

from unittest.mock import patch

from adb_shell import constants
from adb_shell.adb_message import AdbMessage, unpack
from adb_shell.transport.tcp_transport_async import TcpTransportAsync

try:
    from unittest.mock import AsyncMock
except ImportError:
    from unittest.mock import MagicMock

    class AsyncMock(MagicMock):
        async def __call__(self, *args, **kwargs):
            return super(AsyncMock, self).__call__(*args, **kwargs)


def async_mock_open(read_data=""):
    class AsyncMockFile:
        def __init__(self, read_data):
            self.read_data = read_data
            _async_mock_open.written = read_data[:0]

        async def read(self, size=-1):
            if size == -1:
                ret = self.read_data
                self.read_data = self.read_data[:0]
                return ret

            n = min(size, len(self.read_data))
            ret = self.read_data[:n]
            self.read_data = self.read_data[n:]
            return ret

        async def write(self, b):
            if _async_mock_open.written:
                _async_mock_open.written += b
            else:
                _async_mock_open.written = b

    @asynccontextmanager
    async def _async_mock_open(*args, **kwargs):
        try:
            yield AsyncMockFile(read_data)
        finally:
            pass

    return _async_mock_open


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


class FakeTcpTransportAsync(TcpTransportAsync):
    def __init__(self, *args, **kwargs):
        TcpTransportAsync.__init__(self, *args, **kwargs)
        self._bulk_read = b''
        self._bulk_write = b''

    async def close(self):
        self._reader = None
        self._writer = None

    async def connect(self, transport_timeout_s=None):
        self._reader = True
        self._writer = True

    async def bulk_read(self, numbytes, transport_timeout_s=None):
        num = min(numbytes, constants.MAX_ADB_DATA)
        ret = self._bulk_read[:num]
        self._bulk_read = self._bulk_read[num:]
        return ret

    async def bulk_write(self, data, transport_timeout_s=None):
        self._bulk_write += data
        return len(data)


# `TcpTransport` patches
PATCH_TCP_TRANSPORT_ASYNC = patch('adb_shell.adb_device_async.TcpTransportAsync', FakeTcpTransportAsync)


def async_patch(*args, **kwargs):
    return patch(*args, new_callable=AsyncMock, **kwargs)
