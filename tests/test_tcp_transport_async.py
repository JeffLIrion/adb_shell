import asyncio
import unittest
from unittest.mock import patch

from adb_shell.exceptions import TcpTimeoutException
from adb_shell.transport.tcp_transport_async import TcpTransportAsync

from .async_patchers import FakeStreamReader, FakeStreamWriter, async_patch
from .async_wrapper import awaiter
from . import patchers


@patchers.ASYNC_SKIPPER
class TestTcpTransportAsync(unittest.TestCase):
    def setUp(self):
        """Create a ``TcpTransportAsync`` and connect to a TCP service.

        """
        self.transport = TcpTransportAsync('host', 5555)

    @awaiter
    async def test_close(self):
        await self.transport.close()

    @awaiter
    async def test_close2(self):
        await self.transport.close()

    @awaiter
    async def test_connect(self):
        with async_patch('asyncio.open_connection', return_value=(True, True)):
            await self.transport.connect(transport_timeout_s=1)

    @awaiter
    async def test_connect_close(self):
        with async_patch('asyncio.open_connection', return_value=(FakeStreamReader(), FakeStreamWriter())):
            await self.transport.connect(transport_timeout_s=1)
            self.assertIsNotNone(self.transport._writer)

        await self.transport.close()
        self.assertIsNone(self.transport._reader)
        self.assertIsNone(self.transport._writer)

    @awaiter
    async def test_connect_close_catch_oserror(self):
        with async_patch('asyncio.open_connection', return_value=(FakeStreamReader(), FakeStreamWriter())):
            await self.transport.connect(transport_timeout_s=1)
            self.assertIsNotNone(self.transport._writer)

        with patch('{}.FakeStreamWriter.close'.format(__name__), side_effect=OSError):
            await self.transport.close()
            self.assertIsNone(self.transport._reader)
            self.assertIsNone(self.transport._writer)

    @awaiter
    async def test_connect_with_timeout(self):
        with self.assertRaises(TcpTimeoutException):
            with async_patch('asyncio.open_connection', side_effect=asyncio.TimeoutError):
                await self.transport.connect(transport_timeout_s=1)

    @awaiter
    async def test_bulk_read(self):
        with async_patch('asyncio.open_connection', return_value=(FakeStreamReader(), FakeStreamWriter())):
            await self.transport.connect(transport_timeout_s=1)

        self.assertEqual(await self.transport.bulk_read(4, transport_timeout_s=1), b'TEST')

        with self.assertRaises(TcpTimeoutException):
            with patch('{}.FakeStreamReader.read'.format(__name__), side_effect=asyncio.TimeoutError):
                await self.transport.bulk_read(4, transport_timeout_s=1)

    @awaiter
    async def test_bulk_write(self):
        with async_patch('asyncio.open_connection', return_value=(FakeStreamReader(), FakeStreamWriter())):
            await self.transport.connect(transport_timeout_s=1)

        self.assertEqual(await self.transport.bulk_write(b'TEST', transport_timeout_s=1), 4)

        with self.assertRaises(TcpTimeoutException):
            with patch('{}.FakeStreamWriter.write'.format(__name__), side_effect=asyncio.TimeoutError):
                await self.transport.bulk_write(b'TEST', transport_timeout_s=1)
