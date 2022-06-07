# Copyright (c) 2021 Jeff Irion and contributors
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

* :class:`_AdbPacketStore`

    * :meth:`_AdbPacketStore.__contains__`
    * :meth:`_AdbPacketStore.__len__`
    * :meth:`_AdbPacketStore.clear`
    * :meth:`_AdbPacketStore.clear_all`
    * :meth:`_AdbPacketStore.find`
    * :meth:`_AdbPacketStore.find_allow_zeros`
    * :meth:`_AdbPacketStore.get`
    * :meth:`_AdbPacketStore.put`

* :class:`_AdbTransactionInfo`

    * :meth:`_AdbTransactionInfo.args_match`

* :class:`_FileSyncTransactionInfo`

    * :meth:`_FileSyncTransactionInfo.can_add_to_send_buffer`

* :func:`get_banner`
* :func:`get_files_to_push`

"""


from collections import namedtuple
from io import BytesIO
import os
import socket
import struct

try:
    from asyncio import Queue
except ImportError:  # pragma: no cover
    try:
        from queue import Queue
    except ImportError:
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
    local_path_is_dir = not isinstance(local_path, BytesIO) and os.path.isdir(local_path)
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
        Timeout in seconds for sending and receiving data, or ``None``; see :meth:`BaseTransport.bulk_read() <adb_shell.transport.base_transport.BaseTransport.bulk_read>`,
        :meth:`BaseTransport.bulk_write() <adb_shell.transport.base_transport.BaseTransport.bulk_write>`,
        :meth:`BaseTransportAsync.bulk_read() <adb_shell.transport.base_transport_async.BaseTransportAsync.bulk_read>`, and
        :meth:`BaseTransportAsync.bulk_write() <adb_shell.transport.base_transport_async.BaseTransportAsync.bulk_write>`
    read_timeout_s : float
        The total time in seconds to wait for data and packets from the device
    timeout_s : float, None
        The total time in seconds to wait for the ADB command to finish

    Attributes
    ----------
    local_id : int
        The ID for the sender (i.e., the device running this code)
    read_timeout_s : float
        The total time in seconds to wait for data and packets from the device
    remote_id : int
        The ID for the recipient
    timeout_s : float, None
        The total time in seconds to wait for the ADB command to finish
    transport_timeout_s : float, None
        Timeout in seconds for sending and receiving data, or ``None``; see :meth:`BaseTransport.bulk_read() <adb_shell.transport.base_transport.BaseTransport.bulk_read>`,
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

    def args_match(self, arg0, arg1, allow_zeros=False):
        """Check if ``arg0`` and ``arg1`` match this object's ``remote_id`` and ``local_id`` attributes, respectively.

        Parameters
        ----------
        arg0 : int
            The ``arg0`` value from an ADB packet, which will be compared to this object's ``remote_id`` attribute
        arg1 : int
            The ``arg1`` value from an ADB packet, which will be compared to this object's ``local_id`` attribute
        allow_zeros : bool
            Whether to check if ``arg0`` and ``arg1`` match 0, in addition to this object's ``local_id`` and ``remote_id`` attributes

        Returns
        -------
        bool
            Whether ``arg0`` and ``arg1`` match this object's ``local_id`` and ``remote_id`` attributes

        """
        if not allow_zeros:
            return arg1 == self.local_id and (self.remote_id is None or arg0 == self.remote_id)

        # https://github.com/JeffLIrion/adb_shell/blob/17540be9b3b84637aca9b994ae3e0b35d02b1a03/adb_shell/adb_device.py#L923-L929
        return arg1 in (0, self.local_id) and (self.remote_id is None or arg0 in (0, self.remote_id))


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
        the :meth:`adb_shell.adb_device._AdbIOManager._read_packet_from_device` and
        :meth:`adb_shell.adb_device_async._AdbIOManagerAsync._read_packet_from_device` methods.  The second (inner)
        dictionary keys are the ``arg0`` return values from those methods.  And the values of this inner dictionary are
        queues of ``(cmd, data)`` tuples.

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
        return bool(self.find(value[0], value[1]))

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
            The ``arg0`` return value from the :meth:`adb_shell.adb_device._AdbIOManager._read_packet_from_device` and :meth:`adb_shell.adb_device_async._AdbIOManagerAsync._read_packet_from_device` methods
        arg1 : int
            The ``arg1`` return value from the :meth:`adb_shell.adb_device._AdbIOManager._read_packet_from_device` and :meth:`adb_shell.adb_device_async._AdbIOManagerAsync._read_packet_from_device` methods

        """
        if arg1 in self._dict and arg0 in self._dict[arg1]:
            del self._dict[arg1][arg0]

            if not self._dict[arg1]:
                # `self._dict[arg1]` is an empty dictionary now, so delete it
                del self._dict[arg1]

    def clear_all(self):
        """Clear all the entries."""
        self._dict = {}

    def find(self, arg0, arg1):
        """Find the entry corresponding to ``arg0`` and ``arg1``.

        Parameters
        ----------
        arg0 : int, None
            The ``arg0`` value that we are looking for; ``None`` serves as a wildcard
        arg1 : int, None
            The ``arg1`` value that we are looking for; ``None`` serves as a wildcard

        Returns
        -------
        tuple[int, int], None
            The ``(arg0, arg1)`` pair that was found in the dictionary of dictionaries, or ``None`` if no match was found

        """
        if not self._dict:
            return None

        if arg1 is None:
            if arg0 is None:
                # `value = (None, None)` -> search for any non-empty queue
                return next(((key0, key1) for key1, val1 in self._dict.items() for key0, val0 in val1.items() if not val0.empty()), None)

            # Search for a non-empty queue with a key of `arg0 == value[0]`
            return next(((arg0, key1) for key1, val1 in self._dict.items() for key0, val0 in val1.items() if key0 == arg0 and not val0.empty()), None)

        if arg1 not in self._dict:
            return None

        if arg0 is None:
            # Look for a non-empty queue in the `self._dict[value[1]]` dictionary
            return next(((key0, arg1) for key0, val0 in self._dict[arg1].items() if not val0.empty()), None)

        if arg0 in self._dict[arg1] and not self._dict[arg1][arg0].empty():
            return (arg0, arg1)

        return None

    def find_allow_zeros(self, arg0, arg1):
        """Find the entry corresponding to (``arg0`` or 0) and (``arg1`` or 0).

        Parameters
        ----------
        arg0 : int, None
            The ``arg0`` value that we are looking for; ``None`` serves as a wildcard
        arg1 : int, None
            The ``arg1`` value that we are looking for; ``None`` serves as a wildcard

        Returns
        -------
        tuple[int, int], None
            The first matching ``(arg0, arg1)`` pair that was found in the dictionary of dictionaries, or ``None`` if no match was found

        """
        for arg0_, arg1_ in ((arg0, arg1), (arg0, 0), (0, arg1), (0, 0)):
            arg0_arg1 = self.find(arg0_, arg1_)
            if arg0_arg1:
                return arg0_arg1

        return None

    def get(self, arg0, arg1):
        """Get the next entry from the queue for ``arg0`` and ``arg1``.

        This function assumes you have already checked that ``(arg0, arg1) in self``.

        Parameters
        ----------
        arg0 : int, None
            The ``arg0`` return value from the :meth:`adb_shell.adb_device._AdbIOManager._read_packet_from_device` and :meth:`adb_shell.adb_device_async._AdbIOManagerAsync._read_packet_from_device` methods; ``None`` serves as a wildcard
        arg1 : int, None
            The ``arg1`` return value from the :meth:`adb_shell.adb_device._AdbIOManager._read_packet_from_device` and :meth:`adb_shell.adb_device_async._AdbIOManagerAsync._read_packet_from_device` methods; ``None`` serves as a wildcard

        Returns
        -------
        cmd : bytes
            The ADB packet's command
        arg0 : int
            The ``arg0`` value from the returned packet
        arg1 : int
            The ``arg1`` value from the returned packet
        data : bytes
            The ADB packet's data

        """
        if arg0 is None or arg1 is None:
            arg0, arg1 = self.find(arg0, arg1)

        # Get the data from the queue
        cmd, data = self._dict[arg1][arg0].get_nowait()

        # If this is a `CLSE` packet, then clear the entry in the store
        if cmd == constants.CLSE:
            self.clear(arg0, arg1)

        return cmd, arg0, arg1, data

    def put(self, arg0, arg1, cmd, data):
        """Add an entry to the queue for ``arg0`` and ``arg1``.

        Note that a new dictionary entry will not be created if ``cmd == constants.CLSE``.

        Parameters
        ----------
        arg0 : int
            The ``arg0`` return value from the :meth:`adb_shell.adb_device._AdbIOManager._read_packet_from_device` and :meth:`adb_shell.adb_device_async._AdbIOManagerAsync._read_packet_from_device` methods
        arg1 : int
            The ``arg1`` return value from the :meth:`adb_shell.adb_device._AdbIOManager._read_packet_from_device` and :meth:`adb_shell.adb_device_async._AdbIOManagerAsync._read_packet_from_device` methods
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
        self._dict[arg1][arg0].put_nowait((cmd, data))
