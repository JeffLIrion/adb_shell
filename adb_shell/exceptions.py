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

"""ADB-related exceptions.

"""


from . import constants


class AdbCommandFailureException(Exception):
    """A ``b'FAIL'`` packet was received.

    """


class AdbConnectionError(Exception):
    """ADB command not sent because a connection to the device has not been established.

    """


class AdbTimeoutError(Exception):
    """ADB command did not complete within the specified time.

    """


class DeviceAuthError(Exception):
    """Device authentication failed.

    """
    def __init__(self, message, *args):
        message %= args
        super(DeviceAuthError, self).__init__(message, *args)


class InterleavedDataError(Exception):
    """We only support command sent serially.

    """


class InvalidChecksumError(Exception):
    """Checksum of data didn't match expected checksum.

    """


class InvalidCommandError(Exception):
    """Got an invalid command.

    """
    def __init__(self, message, response_header, response_data):
        if response_header == constants.FAIL:
            message = 'Command failed, device said so. (%s)' % message
        super(InvalidCommandError, self).__init__(message, response_header, response_data)


class InvalidTransportError(Exception):
    """The provided transport does not implement the necessary methods: ``close``, ``connect``, ``bulk_read``, and ``bulk_write``.

    """


class InvalidResponseError(Exception):
    """Got an invalid response to our command.

    """


class PushFailedError(Exception):
    """Pushing a file failed for some reason.

    """


class TcpTimeoutException(Exception):
    """TCP connection timed read/write operation exceeded the allowed time.

    """


class UsbDeviceNotFoundError(Exception):
    """TODO

    """


class UsbReadFailedError(Exception):
    """TODO

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
        super(UsbReadFailedError, self).__init__(msg)
        self.usb_error = usb_error

    def __str__(self):
        return '%s: %s' % (super(UsbReadFailedError, self).__str__(), str(self.usb_error))


class UsbWriteFailedError(Exception):
    """:meth:`adb_shell.transport.usb_transport.UsbTransport.bulk_write` failed.

    """
