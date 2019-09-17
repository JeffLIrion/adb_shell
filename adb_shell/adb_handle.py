"""TODO

"""


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
    _serial_number : str
        ``<host>:<port>``
    _timeout_ms : float, None
        TODO
    host : str, TODO
        TODO
    port : str, int, TODO
        TODO

    """
    def __init__(self, *args, **kwargs):
        pass

    def BulkWrite(self, *args, **kwargs):
        pass

    def BulkRead(self, *args, **kwargs):
        pass
