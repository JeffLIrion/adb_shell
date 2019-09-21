"""TODO

"""


import struct

from . import constants


def checksum(data):
    """Calculate the checksum of the provided data.

    Parameters
    ----------
    data : bytearray, bytes, str
        The data

    Returns
    -------
    int
        The checksum

    """
    # The checksum is just a sum of all the bytes. I swear.
    if isinstance(data, bytearray):
        total = sum(data)

    elif isinstance(data, bytes):
        if data and isinstance(data[0], bytes):
            # Python 2 bytes (str) index as single-character strings.
            total = sum(map(ord, data))  # pragma: no cover
        else:
            # Python 3 bytes index as numbers (and PY2 empty strings sum() to 0)
            total = sum(data)

    else:
        # Unicode strings (should never see?)
        total = sum(map(ord, data))

    return total & 0xFFFFFFFF


def unpack(message):
    """Unpack a received ADB message.

    Parameters
    ----------
    message : bytes
        The received message

    Returns
    -------
    cmd : int
        The ADB command
    arg0 : int
        TODO
    arg1 : int
        TODO
    data_length : int
        TODO
    data_checksum : int
        TODO
    unused_magic : int
        TODO

    Raises
    ------
    ValueError
        Unable to unpack the ADB command.

    """
    print('\n\ntype(message) = {}\n\n'.format(type(message)))
    try:
        cmd, arg0, arg1, data_length, data_checksum, unused_magic = struct.unpack(constants.MESSAGE_FORMAT, message)
        print('type(cmd) = {}'.format(type(cmd)))
        print('type(arg0) = {}'.format(type(arg0)))
        print('type(arg1) = {}'.format(type(arg1)))
        print('type(data_length) = {}'.format(type(data_length)))
        print('type(data_checksum) = {}'.format(type(data_checksum)))
        print('type(unused_magic) = {}'.format(type(unused_magic)))
    except struct.error as e:
        raise ValueError('Unable to unpack ADB command. ({})'.format(len(message)), constants.MESSAGE_FORMAT, message, e)

    return cmd, arg0, arg1, data_length, data_checksum


class AdbMessage(object):
    """TODO

    Parameters
    ----------
    command : bytes
        TODO
    arg0 : int
        TODO
    arg1 : int
        TODO
    data : bytes
        TODO

    """
    def __init__(self, command, arg0=None, arg1=None, data=b''):
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
        int
            The checksum of ``self.data``

        """
        return checksum(self.data)
