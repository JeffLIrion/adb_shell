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

* :func:`get_banner`
* :func:`get_files_to_push`

"""


from collections import namedtuple
import os
import socket
import struct

try:
    from queue import Queue
except ImportError:  # pragma: no cover
    from Queue import Queue

from . import constants


DeviceFile = namedtuple('DeviceFile', ['filename', 'mode', 'size', 'mtime'])


def get_files_to_push(local_path, device_path):
    """Get a list of the file(s) to push.

    Parameters
    ----------
    local_path : str
        A path to a local file or directory
    device_path : str
        A path to a file or directory on the device

    Returns
    -------
    local_path_is_dir : bool
        Whether or not ``local_path`` is a directory
    local_paths : list[str]
        A list of the file(s) to push
    device_paths : list[str]
        A list of destination paths on the device that corresponds to ``local_paths``

    """
    local_path_is_dir = os.path.isdir(local_path)
    local_paths = [local_path] if not local_path_is_dir else os.listdir(local_path)
    device_paths = [device_path] if not local_path_is_dir else [device_path + '/' + f for f in local_paths]

    return local_path_is_dir, local_paths, device_paths


def get_banner():
    """Get the ``banner`` that will be signed in :meth:`adb_shell.adb_device.AdbDevice.connect` / :meth:`adb_shell.adb_device_async.AdbDeviceAsync.connect`.

    Returns
    -------
    bytearray
        The hostname, or "unknown" if it could not be determined

    """
    try:
        return bytearray(socket.gethostname(), 'utf-8')
    except:  # noqa pylint: disable=bare-except
        return bytearray('unknown', 'utf-8')


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
    maxdata: int
        Maximum amount of data in an ADB packet

    Attributes
    ----------
    _maxdata: int
        Maximum amount of data in an ADB packet
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
    def __init__(self, recv_message_format, maxdata=constants.MAX_ADB_DATA):
        self.send_buffer = bytearray(maxdata)
        self.send_idx = 0

        self.recv_buffer = bytearray()
        self.recv_message_format = recv_message_format
        self.recv_message_size = struct.calcsize(recv_message_format)

        self._maxdata = maxdata

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
        return self.send_idx + added_len < self._maxdata


class _AdbPacketStore(object):
    """A class for storing ADB packets.

    This class is used to support multiple streams.

    Attributes
    ----------
    _dict : dict[int: dict[int: Queue]]
        A dictionary of dictionaries of queues.  The first (outer) dictionary keys are the ``arg1`` return values from
        the :meth:`adb_shell.adb_device.AdbDevice._read` and :meth:`adb_shell.adb_device_async.AdbDeviceAsync._read`
        methods.  The second (inner) dictionary keys are the ``arg0`` return values from those methods.  And the values
        of this inner dictionary are queues of ``(cmd, data)`` tuples.

    """

    def __init__(self):
        self._dict = {}

    def __contains__(self, value):
        """Check if there are any entries in a queue for the specified value.

        Note that ``None`` is used as a wildcard.

        Parameters
        ----------
        value : tuple[int, int]
            An ``(arg0, arg1)`` pair; either or both values can be ``None``

        Returns
        -------
        bool
            Whether the ``(arg0, arg1)`` tuple has any corresponding queue entries

        """
        if not self._dict:
            return False

        if value[1] is None:
            if value[0] is None:
                # `value = (None, None)` -> search for any non-empty queue
                return any(not val0.empty() for val1 in self._dict.values() for val0 in val1.values())

            # Search for a non-empty queue with a key of `arg0 == value[0]`
            return any(key0 == value[0] and not val0.empty() for val1 in self._dict.values() for key0, val0 in val1.items())

        if value[1] not in self._dict:
            return False

        if value[0] is None:
            # Look for a non-empty queue in the `self._dict[value[1]]` dictionary
            return any(not val0.empty() for val0 in self._dict[value[1]].values())

        return value[0] in self._dict[value[1]] and not self._dict[value[1]][value[0]].empty()

    def __len__(self):
        """Get the number of non-empty queues.

        Returns
        -------
        int
            The number of non-empty queues

        """
        return sum(not val0.empty() for val1 in self._dict.values() for val0 in val1.values())

    def clear(self, arg0, arg1):
        """Delete the entry for ``(arg0, arg1)``, if it exists.

        Parameters
        ----------
        arg0 : int
            The ``arg0`` return value from the :meth:`adb_shell.adb_device.AdbDevice._read` and :meth:`adb_shell.adb_device_async.AdbDeviceAsync._read` methods
        arg1 : int
            The ``arg1`` return value from the :meth:`adb_shell.adb_device.AdbDevice._read` and :meth:`adb_shell.adb_device_async.AdbDeviceAsync._read` methods

        """
        if arg1 in self._dict and arg0 in self._dict[arg1]:
            del self._dict[arg1][arg0]

    def clear_all(self):
        """Clear all the entries."""
        self._dict = {}

    def get(self, arg0, arg1):
        """Get the next entry from the queue for ``arg0`` and ``arg1``.

        Parameters
        ----------
        arg0 : int, None
            The ``arg0`` return value from the :meth:`adb_shell.adb_device.AdbDevice._read` and :meth:`adb_shell.adb_device_async.AdbDeviceAsync._read` methods; ``None`` serves as a wildcard
        arg1 : int, None
            The ``arg1`` return value from the :meth:`adb_shell.adb_device.AdbDevice._read` and :meth:`adb_shell.adb_device_async.AdbDeviceAsync._read` methods; ``None`` serves as a wildcard

        Returns
        -------
        arg0 : int
            The ``arg0`` value from the returned packet
        arg1 : int
            The ``arg1`` value from the returned packet
        cmd : bytes
            The ADB packet's command
        data : bytes
            The ADB packet's data

        """
        # NOTE: While dictionaries don't necessarily have an order, this should only be called with `None` when there is only one corresponding key
        if arg1 is None:
            if arg0 is None:
                arg0 = next(key0 for key1, val1 in self._dict.items() for key0, val0 in val1.items() if not val0.empty())

            arg1 = next(key1 for key1, val1 in self._dict.items() if arg0 in val1 and not val1[arg0].empty())

        if arg0 is None:
            arg0 = next(key0 for key0, val0 in self._dict[arg1].items() if not val0.empty())

        # Get the data from the queue
        cmd, data = self._dict[arg1][arg0].get()

        return arg0, arg1, cmd, data

    def put(self, arg0, arg1, cmd, data):
        """Add an entry to the queue for ``arg0`` and ``arg1``.

        Note that a new dictionary entry will not be created if ``cmd == constants.CLSE``.

        Parameters
        ----------
        arg0 : int
            The ``arg0`` return value from the :meth:`adb_shell.adb_device.AdbDevice._read` and :meth:`adb_shell.adb_device_async.AdbDeviceAsync._read` methods
        arg1 : int
            The ``arg1`` return value from the :meth:`adb_shell.adb_device.AdbDevice._read` and :meth:`adb_shell.adb_device_async.AdbDeviceAsync._read` methods
        cmd : bytes
            The ADB packet's command
        data : bytes
            The ADB packet's data

        """
        if arg1 in self._dict:
            if arg0 not in self._dict[arg1]:
                if cmd == constants.CLSE:
                    return

                # Create the `arg0` entry in the `arg1` dict
                self._dict[arg1][arg0] = Queue()
        else:
            if cmd == constants.CLSE:
                return

            # Create the `arg1` entry with a new dict
            self._dict[arg1] = {arg0: Queue()}

        # Put the data into the queue
        self._dict[arg1][arg0].put((cmd, data))
