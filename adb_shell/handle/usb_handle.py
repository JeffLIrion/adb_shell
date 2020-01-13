# Copyright (c) 2020 Jeff Irion and contributors
#
# This file is part of the adb-shell package.

"""A class for creating a USB connection with the device and sending and receiving data.

* :func:`get_interface`
* :func:`interface_matcher`
* :class:`UsbHandle`

    * :meth:`UsbHandle._find`
    * :meth:`UsbHandle._find_and_open`
    * :meth:`UsbHandle._find_devices`
    * :meth:`UsbHandle._find_first`
    * :meth:`UsbHandle._flush_buffers`
    * :meth:`UsbHandle._open`
    * :meth:`UsbHandle._port_path_matcher`
    * :meth:`UsbHandle._serial_matcher`
    * :meth:`UsbHandle._timeout`
    * :meth:`UsbHandle.bulk_read`
    * :meth:`UsbHandle.bulk_write`
    * :meth:`UsbHandle.close`
    * :meth:`UsbHandle.connect`
    * :attr:`UsbHandle.port_path`
    * :attr:`UsbHandle.serial_number`
    * :attr:`UsbHandle.usb_info`

"""


import logging
import platform
import re
import threading
import weakref

import libusb1
import usb1

try:
    from libusb1 import LIBUSB_ERROR_NOT_FOUND, LIBUSB_ERROR_TIMEOUT  # pylint: disable=ungrouped-imports
except ImportError:  # pragma: no cover
    LIBUSB_ERROR_NOT_FOUND = 'LIBUSB_ERROR_NOT_FOUND'
    LIBUSB_ERROR_TIMEOUT = 'LIBUSB_ERROR_TIMEOUT'

from .base_handle import BaseHandle

from .. import exceptions


#: Default timeout
DEFAULT_TIMEOUT_S = 10

SYSFS_PORT_SPLIT_RE = re.compile("[,/:.-]")

_LOGGER = logging.getLogger(__name__)


def get_interface(setting):
    """Get the class, subclass, and protocol for the given USB setting.

    Parameters
    ----------
    setting : TODO
        TODO

    Returns
    -------
    TODO
        TODO
    TODO
        TODO
    TODO
        TODO

    """
    return (setting.getClass(), setting.getSubClass(), setting.getProtocol())


def interface_matcher(clazz, subclass, protocol):
    """Returns a matcher that returns the setting with the given interface.

    Parameters
    ----------
    clazz : TODO
        TODO
    subclass : TODO
        TODO
    protocol : TODO
        TODO

    Returns
    -------
    matcher : function
        TODO

    """
    interface = (clazz, subclass, protocol)

    def matcher(device):
        """TODO

        Parameters
        ----------
        device : TODO
            TODO

        Returns
        -------
        TODO, None
            TODO

        """
        for setting in device.iterSettings():
            if get_interface(setting) == interface:
                return setting
        return None

    return matcher


class UsbHandle(BaseHandle):
    """USB communication object. Not thread-safe.

    Handles reading and writing over USB with the proper endpoints, exceptions,
    and interface claiming.

    Parameters
    ----------
    device : TODO
        libusb_device to connect to.
    setting : TODO
        libusb setting with the correct endpoints to communicate with.
    usb_info : TODO, None
        String describing the usb path/serial/device, for debugging.
    timeout_s : TODO, None
        Timeout in seconds for all I/O.

    Attributes
    ----------
    _device : TODO
        libusb_device to connect to.
    _handle : TODO
        TODO
    _interface_number : TODO
        TODO
    _max_read_packet_len : TODO
        TODO
    _read_endpoint : TODO
        TODO
    _setting : TODO
        libusb setting with the correct endpoints to communicate with.
    _timeout_s : TODO, None
        Timeout in seconds for all I/O.
    _usb_info : TODO
        String describing the usb path/serial/device, for debugging.
    _write_endpoint : TODO, None
        TODO

    """
    _HANDLE_CACHE = weakref.WeakValueDictionary()
    _HANDLE_CACHE_LOCK = threading.Lock()

    def __init__(self, device, setting, usb_info=None, timeout_s=None):
        """Initialize USB Handle."""
        self._setting = setting
        self._device = device
        self._handle = None

        self._interface_number = None
        self._read_endpoint = None
        self._write_endpoint = None

        self._usb_info = usb_info or ''
        self._timeout_s = timeout_s if timeout_s else DEFAULT_TIMEOUT_S
        self._max_read_packet_len = 0

    def close(self):
        """Close the USB connection.

        """
        if self._handle is None:
            return
        try:
            self._handle.releaseInterface(self._interface_number)
            self._handle.close()
        except libusb1.USBError:
            _LOGGER.info('USBError while closing handle %s: ', self.usb_info, exc_info=True)
        finally:
            self._handle = None

    def connect(self, timeout_s=None):
        """Create a USB connection to the device.

        Parameters
        ----------
        timeout_s : float, None
            Set the timeout on the socket instance

        """

    def bulk_read(self, numbytes, timeout_s=None):
        """Receive data from the USB device.

        Parameters
        ----------
        numbytes : int
            The maximum amount of data to be received
        timeout_s : float, None
            When the timeout argument is omitted, ``select.select`` blocks until at least one file descriptor is ready. A time-out value of zero specifies a poll and never blocks.

        Returns
        -------
        bytes
            The received data

        Raises
        ------
        adb_shell.exceptions.UsbReadFailedError
            Could not receive data

        """
        if self._handle is None:
            raise exceptions.UsbReadFailedError('This handle has been closed, probably due to another being opened.', None)
        try:
            # python-libusb1 > 1.6 exposes bytearray()s now instead of bytes/str.
            # To support older and newer versions, we ensure everything's bytearray()
            # from here on out.
            return bytearray(self._handle.bulk_read(self._read_endpoint, numbytes, timeout=self._timeout(timeout_s)))
        except libusb1.USBError as e:
            raise exceptions.UsbReadFailedError('Could not receive data from %s (timeout %sms)' % (self.usb_info, self._timeout(timeout_s)), e)

    def bulk_write(self, data, timeout_s=None):
        """Send data to the USB device.

        Parameters
        ----------
        data : bytes
            The data to be sent
        timeout_s : float, None
            When the timeout argument is omitted, ``select.select`` blocks until at least one file descriptor is ready. A time-out value of zero specifies a poll and never blocks.

        Returns
        -------
        int
            The number of bytes sent

        Raises
        ------
        adb_shell.exceptions.UsbWriteFailedError
            This handle has been closed, probably due to another being opened
        adb_shell.exceptions.UsbWriteFailedError
            Could not send data

        """
        if self._handle is None:
            raise exceptions.UsbWriteFailedError('This handle has been closed, probably due to another being opened.', None)

        try:
            return self._handle.bulkWrite(self._write_endpoint, data, timeout=self._timeout(timeout_s))

        except libusb1.USBError as e:
            raise exceptions.UsbWriteFailedError('Could not send data to %s (timeout %sms)' % (self.usb_info, self._timeout(timeout_s)), e)

    def _open(self):
        """Opens the USB device for this setting, and claims the interface.

        """
        # Make sure we close any previous handle open to this usb device.
        port_path = tuple(self.port_path)
        with self._HANDLE_CACHE_LOCK:
            old_handle = self._HANDLE_CACHE.get(port_path)
            if old_handle is not None:
                old_handle.Close()

        self._read_endpoint = None
        self._write_endpoint = None

        for endpoint in self._setting.iterEndpoints():
            address = endpoint.getAddress()
            if address & libusb1.USB_ENDPOINT_DIR_MASK:
                self._read_endpoint = address
                self._max_read_packet_len = endpoint.getMaxPacketSize()
            else:
                self._write_endpoint = address

        assert self._read_endpoint is not None
        assert self._write_endpoint is not None

        handle = self._device.open()
        iface_number = self._setting.getNumber()
        try:
            if (platform.system() != 'Windows' and handle.kernelDriverActive(iface_number)):
                handle.detachKernelDriver(iface_number)
        except libusb1.USBError as e:
            if e.value == LIBUSB_ERROR_NOT_FOUND:
                _LOGGER.warning('Kernel driver not found for interface: %s.', iface_number)
            else:
                raise
        handle.claimInterface(iface_number)
        self._handle = handle
        self._interface_number = iface_number

        with self._HANDLE_CACHE_LOCK:
            self._HANDLE_CACHE[port_path] = self
        # When this object is deleted, make sure it's closed.
        weakref.ref(self, self.Close)

    def _timeout(self, timeout_s):
        """TODO

        Returns
        -------
        TODO
            TODO

        """
        return timeout_s * 1000 if timeout_s is not None else self._timeout_s * 1000

    def _flush_buffers(self):
        """TODO

        Raises
        ------
        adb_shell.exceptions.UsbReadFailedError
            TODO

        """
        while True:
            try:
                self.bulk_read(self._max_read_packet_len, timeout_s=10)
            except exceptions.UsbReadFailedError as e:
                if e.usb_error.value == LIBUSB_ERROR_TIMEOUT:
                    break
                raise

    # ======================================================================= #
    #                                                                         #
    #                               Properties                                #
    #                                                                         #
    # ======================================================================= #
    @property
    def port_path(self):
        """TODO

        Returns
        -------
        TODO
            TODO

        """
        return [self._device.getBusNumber()] + self._device.getPortNumberList()

    @property
    def serial_number(self):
        """TODO

        Returns
        -------
        TODO
            TODO

        """
        return self._device.getSerialNumber()

    @property
    def usb_info(self):
        """TODO

        Returns
        -------
        TODO
            TODO

        """
        try:
            sn = self.serial_number
        except libusb1.USBError:
            sn = ''
        if sn and sn != self._usb_info:
            return '%s %s' % (self._usb_info, sn)
        return self._usb_info

    # ======================================================================= #
    #                                                                         #
    #                                Matchers                                 #
    #                                                                         #
    # ======================================================================= #
    @classmethod
    def _port_path_matcher(cls, port_path):
        """Returns a device matcher for the given port path.

        Parameters
        ----------
        port_path : TODO
            TODO

        Returns
        -------
        function
            TODO

        """
        if isinstance(port_path, str):
            # Convert from sysfs path to port_path.
            port_path = [int(part) for part in SYSFS_PORT_SPLIT_RE.split(port_path)]
        return lambda device: device.port_path == port_path

    @classmethod
    def _serial_matcher(cls, serial):
        """Returns a device matcher for the given serial.

        Parameters
        ----------
        serial : TODO
            TODO

        Returns
        -------
        function
            TODO

        """
        return lambda device: device.serial_number == serial

    # ======================================================================= #
    #                                                                         #
    #                                 Finders                                 #
    #                                                                         #
    # ======================================================================= #
    @classmethod
    def _find(cls, setting_matcher, port_path=None, serial=None, timeout_s=None):
        """Gets the first device that matches according to the keyword args.

        Parameters
        ----------
        setting_matcher : TODO
            TODO
        port_path : TODO, None
            TODO
        serial : TODO, None
            TODO
        timeout_s : TODO, None
            TODO

        Returns
        -------
        TODO
            TODO

        """
        if port_path:
            device_matcher = cls._port_path_matcher(port_path)
            usb_info = port_path
        elif serial:
            device_matcher = cls._serial_matcher(serial)
            usb_info = serial
        else:
            device_matcher = None
            usb_info = 'first'
        return cls._find_first(setting_matcher, device_matcher, usb_info=usb_info, timeout_s=timeout_s)

    @classmethod
    def _find_and_open(cls, setting_matcher, port_path=None, serial=None, timeout_s=None):
        """TODO

        Parameters
        ----------
        setting_matcher : TODO
            TODO
        port_path : TODO, None
            TODO
        serial : TODO, None
            TODO
        timeout_s : TODO, None
            TODO

        Returns
        -------
        dev : TODO
            TODO

        """
        dev = cls._find(setting_matcher, port_path=port_path, serial=serial, timeout_s=timeout_s)
        dev._open()  # pylint: disable=protected-access
        dev._flush_buffers()  # pylint: disable=protected-access
        return dev

    @classmethod
    def _find_devices(cls, setting_matcher, device_matcher=None, usb_info='', timeout_s=None):
        """_find and yield the devices that match.

        Parameters
        ----------
        setting_matcher : TODO
            Function that returns the setting to use given a ``usb1.USBDevice``, or ``None``
            if the device doesn't have a valid setting.
        device_matcher : TODO, None
            Function that returns ``True`` if the given ``UsbHandle`` is
            valid. ``None`` to match any device.
        usb_info : str
            Info string describing device(s).
        timeout_s : TODO, None
            Default timeout of commands in seconds.

        Yields
        ------
        TODO
            UsbHandle instances

        """
        ctx = usb1.USBContext()
        for device in ctx.getDeviceList(skip_on_error=True):
            setting = setting_matcher(device)
            if setting is None:
                continue

            handle = cls(device, setting, usb_info=usb_info, timeout_s=timeout_s)
            if device_matcher is None or device_matcher(handle):
                yield handle

    @classmethod
    def _find_first(cls, setting_matcher, device_matcher=None, **kwargs):
        """Find and return the first matching device.

        Parameters
        ----------
        setting_matcher : TODO
            See :meth:`UsbHandle._find_devices`.
        device_matcher : TODO
            See :meth:`UsbHandle._find_devices`.
        **kwargs : TODO
            See :meth:`UsbHandle._find_devices`.

        Returns
        -------
        TODO
            An instance of `UsbHandle`

        Raises
        ------
        adb_shell.exceptions.DeviceNotFoundError
            Raised if the device is not available.

        """
        try:
            return next(cls._find_devices(setting_matcher, device_matcher=device_matcher, **kwargs))
        except StopIteration:
            raise exceptions.UsbDeviceNotFoundError('No device available, or it is in the wrong configuration.')
