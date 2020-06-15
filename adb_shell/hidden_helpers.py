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

"""Implement helpers for the :class:`~adb_shell.adb_device.AdbDevice` and :class:`~adb_shell.adb_device_async.AdbDeviceAsync` classes.

.. rubric:: Contents

* :class:`_AdbTransactionInfo`
* :class:`_FileSyncTransactionInfo`

    * :meth:`_FileSyncTransactionInfo.can_add_to_send_buffer`

* :func:`_open`

"""


from collections import namedtuple
from contextlib import contextmanager
import io
import struct

from . import constants


try:
    FILE_TYPES = (file, io.IOBase)
except NameError:  # pragma: no cover
    FILE_TYPES = (io.IOBase,)

DeviceFile = namedtuple('DeviceFile', ['filename', 'mode', 'size', 'mtime'])


@contextmanager
def _open(name, mode='r'):
    """Handle opening and closing of files and IO streams.

    Parameters
    ----------
    name : str, io.IOBase
        The name of the file *or* an IO stream
    mode : str
        The mode for opening the file

    Yields
    ------
    io.IOBase
        The opened file *or* the IO stream

    """
    try:
        opened = open(name, mode) if isinstance(name, str) else None
        if isinstance(name, str):
            yield opened
        else:
            yield name
    finally:
        if isinstance(name, str):
            opened.close()
        else:
            name.close()


class _AdbTransactionInfo(object):  # pylint: disable=too-few-public-methods
    """A class for storing info and settings used during a single ADB "transaction."

    Note that if ``timeout_s`` is not ``None``, then:

    ::

       self.transport_timeout_s <= self.read_timeout_s <= self.timeout_s

    If ``timeout_s`` is ``None``, the first inequality still applies.


    Parameters
    ----------
    local_id : int
        The ID for the sender (i.e., the device running this code)
    remote_id : int
        The ID for the recipient
    transport_timeout_s : float, None
        Timeout in seconds for sending and receiving packets, or ``None``; see :meth:`BaseTransport.bulk_read() <adb_shell.transport.base_transport.BaseTransport.bulk_read>`,
        :meth:`BaseTransport.bulk_write() <adb_shell.transport.base_transport.BaseTransport.bulk_write>`,
        :meth:`BaseTransportAsync.bulk_read() <adb_shell.transport.base_transport_async.BaseTransportAsync.bulk_read>`, and
        :meth:`BaseTransportAsync.bulk_write() <adb_shell.transport.base_transport_async.BaseTransportAsync.bulk_write>`
    read_timeout_s : float
        The total time in seconds to wait for a command in ``expected_cmds`` in :meth:`AdbDevice._read` and :meth:`AdbDeviceAsync._read`
    timeout_s : float, None
        The total time in seconds to wait for the ADB command to finish

    Attributes
    ----------
    local_id : int
        The ID for the sender (i.e., the device running this code)
    read_timeout_s : float
        The total time in seconds to wait for a command in ``expected_cmds`` in :meth:`AdbDevice._read` and :meth:`AdbDeviceAsync._read`
    remote_id : int
        The ID for the recipient
    timeout_s : float, None
        The total time in seconds to wait for the ADB command to finish
    transport_timeout_s : float, None
        Timeout in seconds for sending and receiving packets, or ``None``; see :meth:`BaseTransport.bulk_read() <adb_shell.transport.base_transport.BaseTransport.bulk_read>`,
        :meth:`BaseTransport.bulk_write() <adb_shell.transport.base_transport.BaseTransport.bulk_write>`,
        :meth:`BaseTransportAsync.bulk_read() <adb_shell.transport.base_transport_async.BaseTransportAsync.bulk_read>`, and
        :meth:`BaseTransportAsync.bulk_write() <adb_shell.transport.base_transport_async.BaseTransportAsync.bulk_write>`

    """
    def __init__(self, local_id, remote_id, transport_timeout_s=None, read_timeout_s=constants.DEFAULT_READ_TIMEOUT_S, timeout_s=None):
        self.local_id = local_id
        self.remote_id = remote_id
        self.timeout_s = timeout_s
        self.read_timeout_s = read_timeout_s if self.timeout_s is None else min(read_timeout_s, self.timeout_s)
        self.transport_timeout_s = self.read_timeout_s if transport_timeout_s is None else min(transport_timeout_s, self.read_timeout_s)


class _FileSyncTransactionInfo(object):  # pylint: disable=too-few-public-methods
    """A class for storing info used during a single FileSync "transaction."

    Parameters
    ----------
    recv_message_format : bytes
        The FileSync message format

    Attributes
    ----------
    recv_buffer : bytearray
        A buffer for storing received data
    recv_message_format : bytes
        The FileSync message format
    recv_message_size : int
        The FileSync message size
    send_buffer : bytearray
        A buffer for storing data to be sent
    send_idx : int
        The index in ``recv_buffer`` that will be the start of the next data packet sent

    """
    def __init__(self, recv_message_format):
        self.send_buffer = bytearray(constants.MAX_ADB_DATA)
        self.send_idx = 0

        self.recv_buffer = bytearray()
        self.recv_message_format = recv_message_format
        self.recv_message_size = struct.calcsize(recv_message_format)

    def can_add_to_send_buffer(self, data_len):
        """Determine whether ``data_len`` bytes of data can be added to the send buffer without exceeding :const:`constants.MAX_ADB_DATA`.

        Parameters
        ----------
        data_len : int
            The length of the data to be potentially added to the send buffer (not including the length of its header)

        Returns
        -------
        bool
            Whether ``data_len`` bytes of data can be added to the send buffer without exceeding :const:`constants.MAX_ADB_DATA`

        """
        added_len = self.recv_message_size + data_len
        return self.send_idx + added_len < constants.MAX_ADB_DATA
