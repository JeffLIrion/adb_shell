# Copyright (c) 2020 Jeff Irion and contributors
#
# This file is part of the adb-shell package.

"""A base class for transports used to communicate with a device.

* :class:`BaseTransport`

    * :meth:`BaseTransport.bulk_read`
    * :meth:`BaseTransport.bulk_write`
    * :meth:`BaseTransport.close`
    * :meth:`BaseTransport.connect`

"""


try:
    from abc import ABC, abstractmethod
except ImportError:  # pragma: no cover
    from abc import ABCMeta, abstractmethod

    class ABC(object):  # pylint: disable=too-few-public-methods
        """A Python2-compatible `ABC` class.

        """
        __metaclass__ = ABCMeta


class BaseTransport(ABC):
    """A base transport class.

    """

    @abstractmethod
    def close(self):
        """Close the connection.

        """

    @abstractmethod
    def connect(self, transport_timeout_s=None):
        """Create a connection to the device.

        Parameters
        ----------
        transport_timeout_s : float, None
            A connection timeout

        """

    @abstractmethod
    def bulk_read(self, numbytes, transport_timeout_s=None):
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
    def bulk_write(self, data, transport_timeout_s=None):
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
