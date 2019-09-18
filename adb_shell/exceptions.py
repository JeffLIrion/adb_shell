"""TODO

"""


from . import constants


class AdbCommandFailureException(Exception):
    """TODO

    """
    def __init__(self, msg):
        super(AdbCommandFailureException, self).__init__(msg)


class InterleavedDataError(Exception):
    """We only support command sent serially.

    .. image:: _static/adb.adb_protocol.InterleavedDataError.CALL_GRAPH.svg

    """


class InvalidChecksumError(Exception):
    """Checksum of data didn't match expected checksum.

    .. image:: _static/adb.adb_protocol.InvalidChecksumError.CALL_GRAPH.svg

    """


class InvalidCommandError(Exception):
    """Got an invalid command over USB.

    .. image:: _static/adb.adb_protocol.InvalidCommandError.CALL_GRAPH.svg

    .. image:: _static/adb.adb_protocol.InvalidCommandError.__init__.CALLER_GRAPH.svg

    """
    def __init__(self, message, response_header, response_data):
        if response_header == constants.FAIL:
            message = 'Command failed, device said so. (%s)' % message
        super(InvalidCommandError, self).__init__(message, response_header, response_data)


class InvalidResponseError(Exception):
    """Got an invalid response to our command.

    .. image:: _static/adb.adb_protocol.InvalidResponseError.CALL_GRAPH.svg

    """


class TcpTimeoutException(Exception):
    """TCP connection timed read/write operation exceeded the allowed time.

    Parameters
    ----------
    msg : str
        TODO

    """
    def __init__(self, msg):
        super(TcpTimeoutException, self).__init__(msg)
