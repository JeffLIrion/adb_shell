import asyncio
import unittest
from unittest.mock import patch

from aio_adb_shell.exceptions import TcpTimeoutException
from aio_adb_shell.handle.tcp_handle import TcpHandle

from . import patchers
from .async_wrapper import awaiter

try:
    from unittest.mock import AsyncMock
except ImportError:
    from unittest.mock import MagicMock

    class AsyncMock(MagicMock):
        async def __call__(self, *args, **kwargs):
            return super(AsyncMock, self).__call__(*args, **kwargs)


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


class TestTcpHandle(unittest.TestCase):
    def setUp(self):
        """Create a ``TcpHandle`` and connect to a TCP service.

        """
        self.handle = TcpHandle('host', 5555)
        #with patchers.PATCH_CREATE_CONNECTION:
        #    self.handle.connect()

    '''def tearDown(self):
        """Close the socket connection."""
        self.handle.close()'''

    @awaiter
    async def test_close(self):
        await self.handle.close()

    @awaiter
    async def test_close2(self):
        await self.handle.close()

    @awaiter
    async def test_connect(self):
        with patch('asyncio.open_connection', return_value=(True, True), new_callable=AsyncMock):
            await self.handle.connect()

    @awaiter
    async def test_connect_close(self):
        with patch('asyncio.open_connection', return_value=(FakeStreamReader(), FakeStreamWriter()), new_callable=AsyncMock):
            await self.handle.connect()
            self.assertIsNotNone(self.handle._writer)

        await self.handle.close()
        self.assertIsNone(self.handle._reader)
        self.assertIsNone(self.handle._writer)

    @awaiter
    async def test_connect_close_catch_oserror(self):
        with patch('asyncio.open_connection', return_value=(FakeStreamReader(), FakeStreamWriter()), new_callable=AsyncMock):
            await self.handle.connect()
            self.assertIsNotNone(self.handle._writer)

        with patch('{}.FakeStreamWriter.close'.format(__name__), side_effect=OSError):
            await self.handle.close()
            self.assertIsNone(self.handle._reader)
            self.assertIsNone(self.handle._writer)

    @awaiter
    async def test_connect_with_timeout(self):
        with self.assertRaises(TcpTimeoutException):
            with patch('asyncio.open_connection', side_effect=asyncio.TimeoutError, new_callable=AsyncMock):
                await self.handle.connect()

    @awaiter
    async def test_bulk_read(self):
        with patch('asyncio.open_connection', return_value=(FakeStreamReader(), FakeStreamWriter()), new_callable=AsyncMock):
            await self.handle.connect()

        self.assertEqual(await self.handle.bulk_read(4), b'TEST')

        with self.assertRaises(TcpTimeoutException):
            with patch('{}.FakeStreamReader.read'.format(__name__), side_effect=asyncio.TimeoutError):
                await self.handle.bulk_read(4)

    @awaiter
    async def test_bulk_write(self):
        with patch('asyncio.open_connection', return_value=(FakeStreamReader(), FakeStreamWriter()), new_callable=AsyncMock):
            await self.handle.connect()

        self.assertEqual(await self.handle.bulk_write(b'TEST'), 4)

        with self.assertRaises(TcpTimeoutException):
            with patch('{}.FakeStreamWriter.write'.format(__name__), side_effect=asyncio.TimeoutError):
                await self.handle.bulk_write(b'TEST')
