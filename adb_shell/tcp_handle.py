"""TODO

* :class:`TcpHandle`

    * :meth:`TcpHandle._connect`
    * :meth:`TcpHandle.BulkRead`
    * :meth:`TcpHandle.BulkWrite`
    * :meth:`TcpHandle.Close`
    * :meth:`TcpHandle.serial_number`
    * :meth:`TcpHandle.Timeout`
    * :meth:`TcpHandle.TimeoutSeconds`

"""


import logging
import select
import socket

from . import constants
from .exceptions import TcpTimeoutException


_LOGGER = logging.getLogger(__name__)


class TcpHandle(object):
    """TCP connection object.

    Provides same interface as `UsbHandle`.

    Parameters
    ----------
    serial : str, bytes, bytearray
        Android device serial of the form "host" or "host:port". (Host may be an IP address or a host name.)
    timeout_s : TODO, None
        TODO

    Attributes
    ----------
    _connection : TODO, None
        TODO
    host : str
        TODO
    port : str
        TODO
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
        """TODO

        """
        return bool(self._connection)

    def close(self):
        """TODO

        """
        if self._connection:
            self._connection.shutdown(socket.SHUT_RDWR)
            self._connection.close()
            self._connection = None

    def connect(self, auth_timeout_s=None):
        """TODO

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
        timeout_s : TODO, None
            TODO

        Returns
        -------
        TODO
            TODO

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
        TODO
            TODO

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
