# Copyright 2014 Google Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Common exceptions for ADB and Fastboot.


.. rubric:: Contents

* :class:`AdbCommandFailureException`
* :class:`AdbOperationException`
* :class:`CommonUsbError`
* :class:`DeviceAuthError`
* :class:`DeviceNotFoundError`
* :class:`FormatMessageWithArgumentsException`
* :class:`LibusbWrappingError`
* :class:`ReadFailedError`
* :class:`TcpTimeoutException`
* :class:`WriteFailedError`

"""


class CommonUsbError(Exception):
    """Base class for usb communication errors.

    .. image:: _static/adb.usb_exceptions.CommonUsbError.CALL_GRAPH.svg

    """


class FormatMessageWithArgumentsException(CommonUsbError):
    """Exception that both looks good and is functional.

    Okay, not that kind of functional, it's still a class.

    This interpolates the message with the given arguments to make it
    human-readable, but keeps the arguments in case other code try-excepts it.

    .. image:: _static/adb.usb_exceptions.FormatMessageWithArgumentsException.CALL_GRAPH.svg

    Parameters
    ----------
    message : str
        The error message
    args : str
        Positional arguments for formatting ``message``

    """
    def __init__(self, message, *args):
        message %= args
        super(FormatMessageWithArgumentsException, self).__init__(message, *args)


class DeviceNotFoundError(FormatMessageWithArgumentsException):
    """Device isn't on USB.

    .. image:: _static/adb.usb_exceptions.DeviceNotFoundError.CALL_GRAPH.svg

    """


class DeviceAuthError(FormatMessageWithArgumentsException):
    """Device authentication failed.

    .. image:: _static/adb.usb_exceptions.DeviceAuthError.CALL_GRAPH.svg

    """


class LibusbWrappingError(CommonUsbError):
    """Wraps ``libusb1`` errors while keeping their original usefulness.

    .. image:: _static/adb.usb_exceptions.LibusbWrappingError.CALL_GRAPH.svg

    Parameters
    ----------
    msg : str
        The error message
    usb_error : libusb1.USBError
        An exception from ``libusb1``

    Attributes
    ----------
    usb_error : libusb1.USBError
        An exception from ``libusb1``

    """
    def __init__(self, msg, usb_error):
        super(LibusbWrappingError, self).__init__(msg)
        self.usb_error = usb_error

    def __str__(self):
        return '%s: %s' % (super(LibusbWrappingError, self).__str__(), str(self.usb_error))


class WriteFailedError(LibusbWrappingError):
    """Raised when the device doesn't accept our command.

    .. image:: _static/adb.usb_exceptions.WriteFailedError.CALL_GRAPH.svg

    """


class ReadFailedError(LibusbWrappingError):
    """Raised when the device doesn't respond to our commands.

    .. image:: _static/adb.usb_exceptions.ReadFailedError.CALL_GRAPH.svg

    """


class AdbCommandFailureException(Exception):
    """ADB Command returned a FAIL.

    .. image:: _static/adb.usb_exceptions.AdbCommandFailureException.CALL_GRAPH.svg

    """


class AdbOperationException(Exception):
    """Failed to communicate over adb with device after multiple retries.

    .. image:: _static/adb.usb_exceptions.AdbOperationException.CALL_GRAPH.svg

    """


class TcpTimeoutException(FormatMessageWithArgumentsException):
    """TCP connection timed out in the time out given.

    .. image:: _static/adb.usb_exceptions.TcpTimeoutException.CALL_GRAPH.svg

    """
