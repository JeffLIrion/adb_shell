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


_LOGGER = logging.getLogger(__name__)


class TcpTimeoutException(Exception):
    """TCP connection timed read/write operation exceeded the allowed time.

    Parameters
    ----------
    msg : str
        TODO

    """
    def __init__(self, msg):
        super(TcpTimeoutException, self).__init__(msg)


class TcpHandle(object):
    """TCP connection object.

    Provides same interface as `UsbHandle`.

    .. image:: _static/adb.common.TcpHandle.__init__.CALLER_GRAPH.svg

    Parameters
    ----------
    serial : str, bytes, bytearray
        Android device serial of the form "host" or "host:port". (Host may be an IP address or a host name.)
    timeout_ms : TODO, None
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
            self.host, self.port = serial.split(':')
        else:
            self.host = serial
            self.port = '5555'

        self.serial = '{}:{}'.format(self.host, self.port)
        self._connection = None

    def connect(self, auth_timeout_ms=None):
        """TODO

        """
        timeout = constants.DEFAULT_AUTH_TIMEOUT if auth_timeout_ms is None else auth_timeout_ms / 1000.
        self._connection = socket.create_connection((self.host, self.port), timeout=timeout)
        if timeout:
            self._connection.setblocking(0)

    def bulk_read(self, numbytes, timeout_ms=None):
        """TODO

        Parameters
        ----------
        numbytes : int
            TODO
        timeout_ms : TODO, None
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
        timeout = constants.DEFAULT_TIMEOUT if timeout_ms is None else timeout_ms / 1000.
        readable, _, _ = select.select([self._connection], [], [], timeout)
        if readable:
            return self._connection.recv(numbytes)

        msg = 'Reading from {} timed out ({} seconds)'.format(self.serial, timeout)
        raise TcpTimeoutException(msg)

    def bulk_write(self, data, timeout_ms=None):
        """TODO

        Parameters
        ----------
        data : TODO
            TODO
        timeout : TODO, None
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
        timeout = constants.DEFAULT_TIMEOUT if timeout_ms is None else timeout_ms / 1000.
        _, writeable, _ = select.select([], [self._connection], [], timeout)
        if writeable:
            return self._connection.send(data)

        msg = 'Sending data to {} timed out after {} seconds. No data was sent.'.format(self.serial, timeout)
        raise TcpTimeoutException(msg)

    def close(self):
        """TODO

        """
        self._connection.close()
