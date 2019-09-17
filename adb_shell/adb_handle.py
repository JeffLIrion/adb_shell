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


import socket


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
            self.host, self.port =  serial.split(':')
        else:
            self.host = serial
            self.port = '5555'

        self.serial = '{}:{}'.format(self.host, self.port)

    def connect(self, auth_timeout_ms=None):
        """TODO

        """
        timeout = 10 if auth_timeout_ms is None else auth_timeout_ms / 1000.
        self._connection = socket.create_connection((self.host, self.port), timeout=timeout)
        if timeout:
            self._connection.setblocking(0)

    def bulk_write(self, *args, **kwargs):
        pass

    def bulk_read(self, *args, **kwargs):
        pass
