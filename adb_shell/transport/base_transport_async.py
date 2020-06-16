# Copyright (c) 2020 Jeff Irion and contributors
#
# This file is part of the adb-shell package.

"""A base class for transports used to communicate with a device.

* :class:`BaseTransportAsync`

    * :meth:`BaseTransportAsync.bulk_read`
    * :meth:`BaseTransportAsync.bulk_write`
    * :meth:`BaseTransportAsync.close`
    * :meth:`BaseTransportAsync.connect`

"""


from abc import ABC, abstractmethod


class BaseTransportAsync(ABC):
    """A base transport class.

    """

    @abstractmethod
    async def close(self):
        """Close the connection.

        """

    @abstractmethod
    async def connect(self, transport_timeout_s=None):
        """Create a connection to the device.

        Parameters
        ----------
        transport_timeout_s : float, None
            A connection timeout

        """

    @abstractmethod
    async def bulk_read(self, numbytes, transport_timeout_s=None):
        """Read data from the device.

        Parameters
        ----------
        numbytes : int
            The maximum amount of data to be received
        transport_timeout_s : float, None
            A timeout for the read operation

        Returns
        -------
        bytes
            The received data

        """

    @abstractmethod
    async def bulk_write(self, data, transport_timeout_s=None):
        """Send data to the device.

        Parameters
        ----------
        data : bytes
            The data to be sent
        transport_timeout_s : float, None
            A timeout for the write operation

        Returns
        -------
        int
            The number of bytes sent

        """
