"""A class for creating a socket connection with the device and sending and receiving data.

* :class:`TcpHandle`

    * :attr:`TcpHandle.available`
    * :attr:`TcpHandle.bulk_read`
    * :attr:`TcpHandle.bulk_write`
    * :meth:`TcpHandle.close`
    * :meth:`TcpHandle.connect`

"""


import select
import socket

from . import constants
from .exceptions import TcpTimeoutException


class TcpHandle(object):
    """TCP connection object.

    Parameters
    ----------
    serial : str, bytes, bytearray
        Android device serial of the form "host" or "host:port".  (Host may be an IP address or a host name.)
        TODO

    Attributes
    ----------
    _connection : socket.socket, None
        A socket connection to the device
    host : str
        The address of the device
    port : str
        The device port to which we are connecting (default is 5555)
    serial_number : str
        ``<host>:<port>``

    """
    def __init__(self, serial):
        if ':' in serial:
            self.host, port = serial.split(':')
            self.port = int(port)
        else:
            self.host = serial
            self.port = 5555

        self.serial = '{}:{}'.format(self.host, self.port)
        self._connection = None

    @property
    def available(self):
        """Whether the socket connection has been created.

        Returns
        -------
        bool
            Whether the connection has been created

        """
        return bool(self._connection)

    def close(self):
        """Close the socket connection.

        """
        if self._connection:
            self._connection.shutdown(socket.SHUT_RDWR)
            self._connection.close()
            self._connection = None

    def connect(self, auth_timeout_s=None):
        """Create a socket connection to the device.

        Parameters
        ----------
        auth_timeout_s : TODO
            TODO

        """
        timeout = constants.DEFAULT_AUTH_TIMEOUT_S if auth_timeout_s is None else auth_timeout_s
        self._connection = socket.create_connection((self.host, self.port), timeout=timeout)
        if timeout:
            self._connection.setblocking(0)

    def bulk_read(self, numbytes, timeout_s=None):
        """TODO

        Parameters
        ----------
        numbytes : int
            TODO
        timeout_s : int, None
            TODO

        Returns
        -------
        bytes
            The received data

        Raises
        ------
        TcpTimeoutException
            Reading timed out.

        """
        timeout = constants.DEFAULT_TIMEOUT_S if timeout_s is None else timeout_s
        readable, _, _ = select.select([self._connection], [], [], timeout)
        if readable:
            return self._connection.recv(numbytes)

        msg = 'Reading from {} timed out ({} seconds)'.format(self.serial, timeout)
        raise TcpTimeoutException(msg)

    def bulk_write(self, data, timeout_s=None):
        """TODO

        Parameters
        ----------
        data : TODO
            TODO
        timeout_s : TODO, None
            TODO

        Returns
        -------
        int
            The number of bytes sent

        Raises
        ------
        TcpTimeoutException
            Sending data timed out.  No data was sent.

        """
        timeout = constants.DEFAULT_TIMEOUT_S if timeout_s is None else timeout_s
        _, writeable, _ = select.select([], [self._connection], [], timeout)
        if writeable:
            return self._connection.send(data)

        msg = 'Sending data to {} timed out after {} seconds. No data was sent.'.format(self.serial, timeout)
        raise TcpTimeoutException(msg)
