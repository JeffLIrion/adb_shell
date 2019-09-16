"""TODO

"""


import struct

from . import constants


class AdbMessage(object):
    """TODO

    """
    def __init__(self, command=None, arg0=None, arg1=None, data=b''):
        self.command = constants.ID_TO_WIRE[command]
        self.magic = self.command ^ 0xFFFFFFFF
        self.arg0 = arg0
        self.arg1 = arg1
        self.data = data

    def Pack(self):
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
        # The checksum is just a sum of all the bytes. I swear.
        if isinstance(self.data, bytearray):
            total = sum(self.data)

        elif isinstance(self.data, bytes):
            if self.data and isinstance(self.data[0], bytes):
                # Python 2 bytes (str) index as single-character strings.
                total = sum(map(ord, self.data))
            else:
                # Python 3 bytes index as numbers (and PY2 empty strings sum() to 0)
                total = sum(self.data)

        else:
            # Unicode strings (should never see?)
            total = sum(map(ord, self.data))

        return total & 0xFFFFFFFF
