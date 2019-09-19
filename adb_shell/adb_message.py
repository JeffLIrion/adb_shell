"""TODO

"""


import struct

from . import constants


def checksum(data):
    """TODO

    Parameters
    ----------
    data : TODO
        TODO

    Returns
    -------
    TODO
        TODO

    """
    # The checksum is just a sum of all the bytes. I swear.
    if isinstance(data, bytearray):
        total = sum(data)

    elif isinstance(data, bytes):
        if data and isinstance(data[0], bytes):
            # Python 2 bytes (str) index as single-character strings.
            total = sum(map(ord, data))
        else:
            # Python 3 bytes index as numbers (and PY2 empty strings sum() to 0)
            total = sum(data)

    else:
        # Unicode strings (should never see?)
        total = sum(map(ord, data))

    return total & 0xFFFFFFFF



def unpack(message):
    """TODO

    .. image:: _static/adb.adb_protocol.AdbMessage.Unpack.CALLER_GRAPH.svg

    Parameters
    ----------
    message : TODO
        TODO

    Returns
    -------
    cmd : TODO
        TODO
    arg0 : TODO
        TODO
    arg1 : TODO
        TODO
    data_length : TODO
        TODO
    data_checksum : TODO
        TODO
    unused_magic : TODO
        TODO

    Raises
    ------
    ValueError
        Unable to unpack the ADB command.

    """
    try:
        cmd, arg0, arg1, data_length, data_checksum, unused_magic = struct.unpack(constants.MESSAGE_FORMAT, message)
    except struct.error as e:
        raise ValueError('Unable to unpack ADB command. ({})'.format(len(message)), constants.MESSAGE_FORMAT, message, e)

    return cmd, arg0, arg1, data_length, data_checksum


class AdbMessage(object):
    """TODO

    """
    def __init__(self, command=None, arg0=None, arg1=None, data=b''):
        self.command = constants.ID_TO_WIRE[command]
        self.magic = self.command ^ 0xFFFFFFFF
        self.arg0 = arg0
        self.arg1 = arg1
        self.data = data

    def pack(self):
        """Returns this message in an over-the-wire format.

        Returns
        -------
        bytes
            TODO

        """
        return struct.pack(constants.MESSAGE_FORMAT, self.command, self.arg0, self.arg1, len(self.data), self.checksum, self.magic)

    @property
    def checksum(self):
        """TODO

        Returns
        -------
        TODO
            TODO

        """
        return checksum(self.data)
