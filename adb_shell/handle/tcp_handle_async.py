# Copyright (c) 2020 Jeff Irion and contributors
#
# This file is part of the adb-shell package.

"""A class for creating a socket connection with the device and sending and receiving data.

* :class:`TcpHandleAsync`

    * :meth:`TcpHandleAsync.bulk_read`
    * :meth:`TcpHandleAsync.bulk_write`
    * :meth:`TcpHandleAsync.close`
    * :meth:`TcpHandleAsync.connect`

"""


import asyncio

from .base_handle_async import BaseHandleAsync
from ..exceptions import TcpTimeoutException


class TcpHandleAsync(BaseHandleAsync):
    """TCP connection object.

    Parameters
    ----------
    host : str
        The address of the device; may be an IP address or a host name
    port : int
        The device port to which we are connecting (default is 5555)
    default_timeout_s : float, None
        Default timeout in seconds for TCP packets, or ``None``

    Attributes
    ----------
    _default_timeout_s : float, None
        Default timeout in seconds for TCP packets, or ``None``
    _host : str
        The address of the device; may be an IP address or a host name
    _port : int
        The device port to which we are connecting (default is 5555)
    _reader : StreamReader, None
        TODO
    _writer : StreamWriter, None
        TODO

    """
    def __init__(self, host, port=5555, default_timeout_s=None):
        self._host = host
        self._port = port
        self._default_timeout_s = default_timeout_s

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

    async def connect(self, timeout_s=None):
        """Create a socket connection to the device.

        Parameters
        ----------
        timeout_s : float, None
            Set the timeout on the socket instance

        """
        timeout = self._default_timeout_s if timeout_s is None else timeout_s

        try:
            self._reader, self._writer = await asyncio.wait_for(asyncio.open_connection(self._host, self._port), timeout)
        except asyncio.TimeoutError:
            msg = 'Connecting to {}:{} timed out ({} seconds)'.format(self._host, self._port, timeout)
            raise TcpTimeoutException(msg)

    async def bulk_read(self, numbytes, timeout_s=None):
        """Receive data from the socket.

        Parameters
        ----------
        numbytes : int
            The maximum amount of data to be received
        timeout_s : float, None
            When the timeout argument is omitted, ``select.select`` blocks until at least one file descriptor is ready. A time-out value of zero specifies a poll and never blocks.

        Returns
        -------
        bytes
            The received data

        Raises
        ------
        TcpTimeoutException
            Reading timed out.

        """
        timeout = self._default_timeout_s if timeout_s is None else timeout_s

        try:
            return await asyncio.wait_for(self._reader.read(numbytes), timeout)
        except asyncio.TimeoutError:
            msg = 'Reading from {}:{} timed out ({} seconds)'.format(self._host, self._port, timeout)
            raise TcpTimeoutException(msg)

    async def bulk_write(self, data, timeout_s=None):
        """Send data to the socket.

        Parameters
        ----------
        data : bytes
            The data to be sent
        timeout_s : float, None
            When the timeout argument is omitted, ``select.select`` blocks until at least one file descriptor is ready. A time-out value of zero specifies a poll and never blocks.

        Returns
        -------
        int
            The number of bytes sent

        Raises
        ------
        TcpTimeoutException
            Sending data timed out.  No data was sent.

        """
        timeout = self._default_timeout_s if timeout_s is None else timeout_s

        try:
            self._writer.write(data)
            await asyncio.wait_for(self._writer.drain(), timeout)
            return len(data)
        except asyncio.TimeoutError:
            msg = 'Sending data to {}:{} timed out after {} seconds. No data was sent.'.format(self._host, self._port, timeout)
            raise TcpTimeoutException(msg)
