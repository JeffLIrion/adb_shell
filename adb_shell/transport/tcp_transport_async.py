# Copyright (c) 2021 Jeff Irion and contributors
#
# This file is part of the adb-shell package.

"""A class for creating a socket connection with the device and sending and receiving data.

* :class:`TcpTransportAsync`

    * :meth:`TcpTransportAsync.bulk_read`
    * :meth:`TcpTransportAsync.bulk_write`
    * :meth:`TcpTransportAsync.close`
    * :meth:`TcpTransportAsync.connect`

"""


import asyncio

from .base_transport_async import BaseTransportAsync
from ..exceptions import TcpTimeoutException


class TcpTransportAsync(BaseTransportAsync):
    """TCP connection object.

    Parameters
    ----------
    host : str
        The address of the device; may be an IP address or a host name
    port : int
        The device port to which we are connecting (default is 5555)

    Attributes
    ----------
    _host : str
        The address of the device; may be an IP address or a host name
    _port : int
        The device port to which we are connecting (default is 5555)
    _reader : StreamReader, None
        Object for reading data from the socket
    _writer : StreamWriter, None
        Object for writing data to the socket

    """
    def __init__(self, host, port=5555):
        self._host = host
        self._port = port

        self._reader = None
        self._writer = None

    async def close(self):
        """Close the socket connection.

        """
        if self._writer:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except OSError:
                pass

        self._reader = None
        self._writer = None

    async def connect(self, transport_timeout_s):
        """Create a socket connection to the device.

        Parameters
        ----------
        transport_timeout_s : float, None
            Timeout for connecting to the socket; if it is ``None``, then it will block until the operation completes

        """
        try:
            self._reader, self._writer = await asyncio.wait_for(asyncio.open_connection(self._host, self._port), transport_timeout_s)
        except asyncio.TimeoutError as exc:
            msg = 'Connecting to {}:{} timed out ({} seconds)'.format(self._host, self._port, transport_timeout_s)
            raise TcpTimeoutException(msg) from exc

    async def bulk_read(self, numbytes, transport_timeout_s):
        """Receive data from the socket.

        Parameters
        ----------
        numbytes : int
            The maximum amount of data to be received
        transport_timeout_s : float, None
            Timeout for reading data from the socket; if it is ``None``, then it will block until the read operation completes

        Returns
        -------
        bytes
            The received data

        Raises
        ------
        TcpTimeoutException
            Reading timed out.

        """
        try:
            return await asyncio.wait_for(self._reader.read(numbytes), transport_timeout_s)
        except asyncio.TimeoutError as exc:
            msg = 'Reading from {}:{} timed out ({} seconds)'.format(self._host, self._port, transport_timeout_s)
            raise TcpTimeoutException(msg) from exc

    async def bulk_write(self, data, transport_timeout_s):
        """Send data to the socket.

        Parameters
        ----------
        data : bytes
            The data to be sent
        transport_timeout_s : float, None
            Timeout for writing data to the socket; if it is ``None``, then it will block until the write operation completes

        Returns
        -------
        int
            The number of bytes sent

        Raises
        ------
        TcpTimeoutException
            Sending data timed out.  No data was sent.

        """
        try:
            self._writer.write(data)
            await asyncio.wait_for(self._writer.drain(), transport_timeout_s)
            return len(data)
        except asyncio.TimeoutError as exc:
            msg = 'Sending data to {}:{} timed out after {} seconds. No data was sent.'.format(self._host, self._port, transport_timeout_s)
            raise TcpTimeoutException(msg) from exc
