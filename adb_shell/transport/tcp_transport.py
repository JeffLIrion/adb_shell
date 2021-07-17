# Copyright (c) 2021 Jeff Irion and contributors
#
# This file is part of the adb-shell package.  It incorporates work
# covered by the following license notice:
#
#
#   Copyright 2014 Google Inc. All rights reserved.
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

"""A class for creating a socket connection with the device and sending and receiving data.

* :class:`TcpTransport`

    * :meth:`TcpTransport.bulk_read`
    * :meth:`TcpTransport.bulk_write`
    * :meth:`TcpTransport.close`
    * :meth:`TcpTransport.connect`

"""


import select
import socket

from .base_transport import BaseTransport
from ..exceptions import TcpTimeoutException


class TcpTransport(BaseTransport):
    """TCP connection object.

    Parameters
    ----------
    host : str
        The address of the device; may be an IP address or a host name
    port : int
        The device port to which we are connecting (default is 5555)

    Attributes
    ----------
    _connection : socket.socket, None
        A socket connection to the device
    _host : str
        The address of the device; may be an IP address or a host name
    _port : int
        The device port to which we are connecting (default is 5555)

    """
    def __init__(self, host, port=5555):
        self._host = host
        self._port = port

        self._connection = None

    def close(self):
        """Close the socket connection.

        """
        if self._connection:
            try:
                self._connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

            self._connection.close()
            self._connection = None

    def connect(self, transport_timeout_s):
        """Create a socket connection to the device.

        Parameters
        ----------
        transport_timeout_s : float, None
            Set the timeout on the socket instance

        """
        self._connection = socket.create_connection((self._host, self._port), timeout=transport_timeout_s)
        if transport_timeout_s:
            # Put the socket in non-blocking mode
            # https://docs.python.org/3/library/socket.html#socket.socket.settimeout
            self._connection.setblocking(False)

    def bulk_read(self, numbytes, transport_timeout_s):
        """Receive data from the socket.

        Parameters
        ----------
        numbytes : int
            The maximum amount of data to be received
        transport_timeout_s : float, None
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
        readable, _, _ = select.select([self._connection], [], [], transport_timeout_s)
        if readable:
            return self._connection.recv(numbytes)

        msg = 'Reading from {}:{} timed out ({} seconds)'.format(self._host, self._port, transport_timeout_s)
        raise TcpTimeoutException(msg)

    def bulk_write(self, data, transport_timeout_s):
        """Send data to the socket.

        Parameters
        ----------
        data : bytes
            The data to be sent
        transport_timeout_s : float, None
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
        _, writeable, _ = select.select([], [self._connection], [], transport_timeout_s)
        if writeable:
            return self._connection.send(data)

        msg = 'Sending data to {}:{} timed out after {} seconds. No data was sent.'.format(self._host, self._port, transport_timeout_s)
        raise TcpTimeoutException(msg)
