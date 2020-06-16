# Copyright (c) 2020 Jeff Irion and contributors
#
# This file is part of the adb-shell package.  It incorporates work
# covered by the following license notice:
#
#
#   Copyright 2014 Google Inc. All rights reserved.
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

"""A class for creating a USB connection with the device and sending and receiving data.

.. warning::

   USB support is an experimental feature.


* :func:`get_interface`
* :func:`interface_matcher`
* :class:`UsbTransport`

    * :meth:`UsbTransport._find`
    * :meth:`UsbTransport._find_and_open`
    * :meth:`UsbTransport._find_devices`
    * :meth:`UsbTransport._find_first`
    * :meth:`UsbTransport._flush_buffers`
    * :meth:`UsbTransport._open`
    * :meth:`UsbTransport._port_path_matcher`
    * :meth:`UsbTransport._serial_matcher`
    * :meth:`UsbTransport._timeout`
    * :meth:`UsbTransport.bulk_read`
    * :meth:`UsbTransport.bulk_write`
    * :meth:`UsbTransport.close`
    * :meth:`UsbTransport.connect`
    * :attr:`UsbTransport.port_path`
    * :attr:`UsbTransport.serial_number`
    * :attr:`UsbTransport.usb_info`

"""


import logging
import platform
import re
import threading
import warnings
import weakref

import usb1

from .base_transport import BaseTransport

from .. import exceptions


#: Default timeout
DEFAULT_TIMEOUT_S = 10

SYSFS_PORT_SPLIT_RE = re.compile("[,/:.-]")

_LOGGER = logging.getLogger(__name__)

CLASS = usb1.CLASS_VENDOR_SPEC  # pylint: disable=no-member
SUBCLASS = 0x42
PROTOCOL = 0x01


def get_interface(setting):  # pragma: no cover
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


def interface_matcher(clazz, subclass, protocol):   # pragma: no cover
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


class UsbTransport(BaseTransport):   # pragma: no cover
    """USB communication object. Not thread-safe.

    Handles reading and writing over USB with the proper endpoints, exceptions,
    and interface claiming.

    Parameters
    ----------
    device : usb1.USBDevice
        libusb_device to connect to.
    setting : usb1.USBInterfaceSetting
        libusb setting with the correct endpoints to communicate with.
    usb_info : TODO, None
        String describing the usb path/serial/device, for debugging.
    default_transport_timeout_s : TODO, None
        Timeout in seconds for all I/O.

    Attributes
    ----------
    _default_transport_timeout_s : TODO, None
        Timeout in seconds for all I/O.
    _device : TODO
        libusb_device to connect to.
    _transport : TODO
        TODO
    _interface_number : TODO
        TODO
    _max_read_packet_len : TODO
        TODO
    _read_endpoint : TODO
        TODO
    _setting : TODO
        libusb setting with the correct endpoints to communicate with.
    _usb_info : TODO
        String describing the usb path/serial/device, for debugging.
    _write_endpoint : TODO, None
        TODO

    """
    _HANDLE_CACHE = weakref.WeakValueDictionary()
    _HANDLE_CACHE_LOCK = threading.Lock()

    def __init__(self, device, setting, usb_info=None, default_transport_timeout_s=None):
        self._setting = setting
        self._device = device
        self._transport = None

        self._interface_number = None
        self._read_endpoint = None
        self._write_endpoint = None

        self._usb_info = usb_info or ''
        self._default_transport_timeout_s = default_transport_timeout_s if default_transport_timeout_s is not None else DEFAULT_TIMEOUT_S
        self._max_read_packet_len = 0

    def close(self):
        """Close the USB connection.

        """
        if self._transport is None:
            return
        try:
            self._transport.releaseInterface(self._interface_number)
            self._transport.close()
        except usb1.USBError:
            _LOGGER.info('USBError while closing transport %s: ', self.usb_info, exc_info=True)
        finally:
            self._transport = None

    def connect(self, transport_timeout_s=None):
        """Create a USB connection to the device.

        Parameters
        ----------
        transport_timeout_s : float, None
            Set the timeout on the USB instance

        """
        read_endpoint = None
        write_endpoint = None

        for endpoint in self._setting.iterEndpoints():
            address = endpoint.getAddress()
            if address & usb1.ENDPOINT_DIR_MASK:  # pylint: disable=no-member
                read_endpoint = address
                # max_read_packet_len = endpoint.getMaxPacketSize()
            else:
                write_endpoint = address

        assert read_endpoint is not None
        assert write_endpoint is not None

        transport = self._device.open()
        iface_number = self._setting.getNumber()
        try:
            if (platform.system() != 'Windows' and transport.kernelDriverActive(iface_number)):
                transport.detachKernelDriver(iface_number)
        except usb1.USBErrorNotFound:  # pylint: disable=no-member
            warnings.warn('Kernel driver not found for interface: %s.', iface_number)

        # # When this object is deleted, make sure it's closed.
        # weakref.ref(self, self.close)

        self._transport = transport
        self._read_endpoint = read_endpoint
        self._write_endpoint = write_endpoint
        self._interface_number = iface_number

        self._transport.claimInterface(self._interface_number)

    def bulk_read(self, numbytes, transport_timeout_s=None):
        """Receive data from the USB device.

        Parameters
        ----------
        numbytes : int
            The maximum amount of data to be received
        transport_timeout_s : float, None
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
        if self._transport is None:
            raise exceptions.UsbReadFailedError('This transport has been closed, probably due to another being opened.', None)
        try:
            # python-libusb1 > 1.6 exposes bytearray()s now instead of bytes/str.
            # To support older and newer versions, we ensure everything's bytearray()
            # from here on out.
            return bytes(self._transport.bulkRead(self._read_endpoint, numbytes, timeout=self._timeout_ms(transport_timeout_s)))
        except usb1.USBError as e:
            raise exceptions.UsbReadFailedError('Could not receive data from %s (timeout %sms)' % (self.usb_info, self._timeout_ms(transport_timeout_s)), e)

    def bulk_write(self, data, transport_timeout_s=None):
        """Send data to the USB device.

        Parameters
        ----------
        data : bytes
            The data to be sent
        transport_timeout_s : float, None
            When the timeout argument is omitted, ``select.select`` blocks until at least one file descriptor is ready. A time-out value of zero specifies a poll and never blocks.

        Returns
        -------
        int
            The number of bytes sent

        Raises
        ------
        adb_shell.exceptions.UsbWriteFailedError
            This transport has been closed, probably due to another being opened
        adb_shell.exceptions.UsbWriteFailedError
            Could not send data

        """
        if self._transport is None:
            raise exceptions.UsbWriteFailedError('This transport has been closed, probably due to another being opened.', None)

        try:
            return self._transport.bulkWrite(self._write_endpoint, data, timeout=self._timeout_ms(transport_timeout_s))

        except usb1.USBError as e:
            raise exceptions.UsbWriteFailedError('Could not send data to %s (timeout %sms)' % (self.usb_info, self._timeout_ms(transport_timeout_s)), e)

    def _open(self):
        """Opens the USB device for this setting, and claims the interface.

        """
        # Make sure we close any previous transport open to this usb device.
        port_path = tuple(self.port_path)
        with self._HANDLE_CACHE_LOCK:
            old_transport = self._HANDLE_CACHE.get(port_path)
            if old_transport is not None:
                old_transport.Close()

        self._read_endpoint = None
        self._write_endpoint = None

        for endpoint in self._setting.iterEndpoints():
            address = endpoint.getAddress()
            if address & usb1.USB_ENDPOINT_DIR_MASK:  # pylint: disable=no-member
                self._read_endpoint = address
                self._max_read_packet_len = endpoint.getMaxPacketSize()
            else:
                self._write_endpoint = address

        assert self._read_endpoint is not None
        assert self._write_endpoint is not None

        transport = self._device.open()
        iface_number = self._setting.getNumber()
        try:
            if (platform.system() != 'Windows' and transport.kernelDriverActive(iface_number)):
                transport.detachKernelDriver(iface_number)
        except usb1.USBErrorNotFound:  # pylint: disable=no-member
            warnings.warn('Kernel driver not found for interface: %s.', iface_number)
        transport.claimInterface(iface_number)
        self._transport = transport
        self._interface_number = iface_number

        with self._HANDLE_CACHE_LOCK:
            self._HANDLE_CACHE[port_path] = self
        # When this object is deleted, make sure it's closed.
        weakref.ref(self, self.close)

    def _timeout_ms(self, transport_timeout_s):
        """TODO

        Returns
        -------
        TODO
            TODO

        """
        return int(transport_timeout_s * 1000 if transport_timeout_s is not None else self._default_transport_timeout_s * 1000)

    def _flush_buffers(self):
        """TODO

        Raises
        ------
        adb_shell.exceptions.UsbReadFailedError
            TODO

        """
        while True:
            try:
                self.bulk_read(self._max_read_packet_len, transport_timeout_s=10)
            except exceptions.UsbReadFailedError as e:
                if isinstance(e.usb_error, usb1.USBErrorTimeout):  # pylint: disable=no-member
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
        except usb1.USBError:
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
    def _find(cls, setting_matcher, port_path=None, serial=None, default_transport_timeout_s=None):
        """Gets the first device that matches according to the keyword args.

        Parameters
        ----------
        setting_matcher : TODO
            TODO
        port_path : TODO, None
            TODO
        serial : TODO, None
            TODO
        default_transport_timeout_s : TODO, None
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
        return cls._find_first(setting_matcher, device_matcher, usb_info=usb_info, default_transport_timeout_s=default_transport_timeout_s)

    @classmethod
    def _find_and_open(cls, setting_matcher, port_path=None, serial=None, default_transport_timeout_s=None):
        """TODO

        Parameters
        ----------
        setting_matcher : TODO
            TODO
        port_path : TODO, None
            TODO
        serial : TODO, None
            TODO
        default_transport_timeout_s : TODO, None
            TODO

        Returns
        -------
        dev : TODO
            TODO

        """
        dev = cls._find(setting_matcher, port_path=port_path, serial=serial, default_transport_timeout_s=default_transport_timeout_s)
        dev._open()  # pylint: disable=protected-access
        dev._flush_buffers()  # pylint: disable=protected-access
        return dev

    @classmethod
    def _find_devices(cls, setting_matcher, device_matcher=None, usb_info='', default_transport_timeout_s=None):
        """_find and yield the devices that match.

        Parameters
        ----------
        setting_matcher : TODO
            Function that returns the setting to use given a ``usb1.USBDevice``, or ``None``
            if the device doesn't have a valid setting.
        device_matcher : TODO, None
            Function that returns ``True`` if the given ``UsbTransport`` is
            valid. ``None`` to match any device.
        usb_info : str
            Info string describing device(s).
        default_transport_timeout_s : TODO, None
            Default timeout of commands in seconds.

        Yields
        ------
        TODO
            UsbTransport instances

        """
        ctx = usb1.USBContext()
        for device in ctx.getDeviceList(skip_on_error=True):
            setting = setting_matcher(device)
            if setting is None:
                continue

            transport = cls(device, setting, usb_info=usb_info, default_transport_timeout_s=default_transport_timeout_s)
            if device_matcher is None or device_matcher(transport):
                yield transport

    @classmethod
    def _find_first(cls, setting_matcher, device_matcher=None, usb_info='', default_transport_timeout_s=None):
        """Find and return the first matching device.

        Parameters
        ----------
        setting_matcher : TODO
            Function that returns the setting to use given a ``usb1.USBDevice``, or ``None``
            if the device doesn't have a valid setting.
        device_matcher : TODO
            Function that returns ``True`` if the given ``UsbTransport`` is
            valid. ``None`` to match any device.
        usb_info : str
            Info string describing device(s).
        default_transport_timeout_s : TODO, None
            Default timeout of commands in seconds.

        Returns
        -------
        TODO
            An instance of `UsbTransport`

        Raises
        ------
        adb_shell.exceptions.DeviceNotFoundError
            Raised if the device is not available.

        """
        try:
            return next(cls._find_devices(setting_matcher, device_matcher=device_matcher, usb_info=usb_info, default_transport_timeout_s=default_transport_timeout_s))
        except StopIteration:
            raise exceptions.UsbDeviceNotFoundError('No device available, or it is in the wrong configuration.')

    @classmethod
    def find_adb(cls, serial=None, port_path=None, default_transport_timeout_s=None):
        """TODO

        Parameters
        ----------
        serial : TODO
            TODO
        port_path : TODO
            TODO
        default_transport_timeout_s : TODO, None
            Default timeout of commands in seconds.

        Returns
        -------
        UsbTransport
            TODO

        """
        return cls._find(
            interface_matcher(CLASS, SUBCLASS, PROTOCOL),
            serial=serial,
            port_path=port_path,
            default_transport_timeout_s=default_transport_timeout_s
        )
