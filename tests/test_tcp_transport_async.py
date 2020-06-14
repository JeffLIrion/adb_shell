import asyncio
import unittest
from unittest.mock import patch

from adb_shell.exceptions import TcpTimeoutException
from adb_shell.transport.tcp_transport_async import TcpHandleAsync

from .async_patchers import AsyncMock, FakeStreamReader, FakeStreamWriter
from .async_wrapper import awaiter
from . import patchers


@patchers.ASYNC_SKIPPER
class TestTcpHandleAsync(unittest.TestCase):
    def setUp(self):
        """Create a ``TcpHandleAsync`` and connect to a TCP service.

        """
        self.transport = TcpHandleAsync('host', 5555)

    @awaiter
    async def test_close(self):
        await self.transport.close()

    @awaiter
    async def test_close2(self):
        await self.transport.close()

    @awaiter
    async def test_connect(self):
        with patch('asyncio.open_connection', return_value=(True, True), new_callable=AsyncMock):
            await self.transport.connect()

    @awaiter
    async def test_connect_close(self):
        with patch('asyncio.open_connection', return_value=(FakeStreamReader(), FakeStreamWriter()), new_callable=AsyncMock):
            await self.transport.connect()
            self.assertIsNotNone(self.transport._writer)

        await self.transport.close()
        self.assertIsNone(self.transport._reader)
        self.assertIsNone(self.transport._writer)

    @awaiter
    async def test_connect_close_catch_oserror(self):
        with patch('asyncio.open_connection', return_value=(FakeStreamReader(), FakeStreamWriter()), new_callable=AsyncMock):
            await self.transport.connect()
            self.assertIsNotNone(self.transport._writer)

        with patch('{}.FakeStreamWriter.close'.format(__name__), side_effect=OSError):
            await self.transport.close()
            self.assertIsNone(self.transport._reader)
            self.assertIsNone(self.transport._writer)

    @awaiter
    async def test_connect_with_timeout(self):
        with self.assertRaises(TcpTimeoutException):
            with patch('asyncio.open_connection', side_effect=asyncio.TimeoutError, new_callable=AsyncMock):
                await self.transport.connect()

    @awaiter
    async def test_bulk_read(self):
        with patch('asyncio.open_connection', return_value=(FakeStreamReader(), FakeStreamWriter()), new_callable=AsyncMock):
            await self.transport.connect()

        self.assertEqual(await self.transport.bulk_read(4), b'TEST')

        with self.assertRaises(TcpTimeoutException):
            with patch('{}.FakeStreamReader.read'.format(__name__), side_effect=asyncio.TimeoutError):
                await self.transport.bulk_read(4)

    @awaiter
    async def test_bulk_write(self):
        with patch('asyncio.open_connection', return_value=(FakeStreamReader(), FakeStreamWriter()), new_callable=AsyncMock):
            await self.transport.connect()

        self.assertEqual(await self.transport.bulk_write(b'TEST'), 4)

        with self.assertRaises(TcpTimeoutException):
            with patch('{}.FakeStreamWriter.write'.format(__name__), side_effect=asyncio.TimeoutError):
                await self.transport.bulk_write(b'TEST')
