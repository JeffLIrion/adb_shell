# Copyright (c) 2020 Jeff Irion and contributors
#
# This file is part of the adb-shell package.

"""A base class for handles used to communicate with a device.

* :class:`BaseHandleAsync`

    * :meth:`BaseHandleAsync.bulk_read`
    * :meth:`BaseHandleAsync.bulk_write`
    * :meth:`BaseHandleAsync.close`
    * :meth:`BaseHandleAsync.connect`

"""


from abc import ABC, abstractmethod


class BaseHandleAsync(ABC):
    """A base handle class.

    """

    @abstractmethod
    async def close(self):
        """Close the connection.

        """

    @abstractmethod
    async def connect(self, timeout_s=None):
        """Create a connection to the device.

        Parameters
        ----------
        timeout_s : float, None
            A connection timeout

        """

    @abstractmethod
    async def bulk_read(self, numbytes, timeout_s=None):
        """Read data from the device.

        Parameters
        ----------
        numbytes : int
            The maximum amount of data to be received
        timeout_s : float, None
            A timeout for the read operation

        Returns
        -------
        bytes
            The received data

        """

    @abstractmethod
    async def bulk_write(self, data, timeout_s=None):
        """Send data to the device.

        Parameters
        ----------
        data : bytes
            The data to be sent
        timeout_s : float, None
            A timeout for the write operation

        Returns
        -------
        int
            The number of bytes sent

        """
