import struct

from aio_adb_shell import constants


class FileSyncMessage(object):  # pylint: disable=too-few-public-methods
    """A helper class for packing FileSync messages.

    Parameters
    ----------
    command : bytes
        TODO
    arg0 : int
        TODO
    data : bytes
        The data that will be sent

    Attributes
    ----------
    arg0 : int
        TODO
    command : int
        The input parameter ``command`` converted to an integer via :const:`aio_adb_shell.constants.FILESYNC_ID_TO_WIRE`
    data : bytes
        The data that will be sent

    """
    def __init__(self, command, arg0=None, data=b''):
        self.command = constants.FILESYNC_ID_TO_WIRE[command]
        self.arg0 = arg0 or len(data)
        self.data = data

    def pack(self):
        """Returns this message in an over-the-wire format.

        Returns
        -------
        bytes
            The message packed into the format required by ADB

        """
        return struct.pack(b'<2I', self.command, self.arg0)


class FileSyncListMessage(object):  # pylint: disable=too-few-public-methods
    """A helper class for packing FileSync messages for the "list" service".

    Parameters
    ----------
    command : bytes
        TODO
    arg0 : int
        TODO
    arg1 : TODO
        TODO
    arg2 : TODO
        TODO
    data : bytes
        The data that will be sent

    Attributes
    ----------
    arg0 : int
        TODO
    arg1 : TODO
        TODO
    arg2 : TODO
        TODO
    arg3 : int
        The size of the data
    command : int
        The input parameter ``command`` converted to an integer via :const:`aio_adb_shell.constants.FILESYNC_ID_TO_WIRE`
    data : bytes
        TODO

    """
    def __init__(self, command, arg0, arg1, arg2, data=b''):
        self.command = constants.FILESYNC_ID_TO_WIRE[command]
        self.arg0 = arg0
        self.arg1 = arg1
        self.arg2 = arg2
        self.arg3 = len(data)
        self.data = data

    def pack(self):
        """Returns this message in an over-the-wire format.

        Returns
        -------
        bytes
            The message packed into the format required by ADB

        """
        return struct.pack(b'<5I', self.command, self.arg0, self.arg1, self.arg2, self.arg3)


class FileSyncStatMessage(object):  # pylint: disable=too-few-public-methods
    """A helper class for packing FileSync messages for the "stat" service".

    Parameters
    ----------
    command : bytes
        TODO
    arg0 : int
        TODO
    arg1 : TODO
        TODO
    arg2 : TODO
        TODO

    Attributes
    ----------
    arg0 : int
        TODO
    arg1 : TODO
        TODO
    arg2 : TODO
        TODO
    command : int
        The input parameter ``command`` converted to an integer via :const:`aio_adb_shell.constants.FILESYNC_ID_TO_WIRE`
    data : bytes
        The data that will be sent (always empty)

    """
    def __init__(self, command, arg0, arg1, arg2):
        self.command = constants.FILESYNC_ID_TO_WIRE[command]
        self.arg0 = arg0
        self.arg1 = arg1
        self.arg2 = arg2
        self.data = b''

    def pack(self):
        """Returns this message in an over-the-wire format.

        Returns
        -------
        bytes
            The message packed into the format required by ADB

        """
        return struct.pack(b'<4I', self.command, self.arg0, self.arg1, self.arg2)
