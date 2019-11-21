# Copyright (c) 2019 Jeff Irion and contributors
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

"""Implement the :class:`AdbDevice` class, which can connect to a device and run ADB shell commands.

.. rubric:: Contents

* :class:`AdbDevice`

    * :meth:`AdbDevice._open`
    * :meth:`AdbDevice._read`
    * :meth:`AdbDevice._read_until`
    * :meth:`AdbDevice._read_until_close`
    * :meth:`AdbDevice._streaming_command`
    * :attr:`AdbDevice.available`
    * :meth:`AdbDevice.close`
    * :meth:`AdbDevice.connect`
    * :meth:`AdbDevice.shell`

"""


import collections
import io
import logging
import os
import socket
import struct
import time

from . import constants
from . import exceptions
from .adb_message import AdbMessage, checksum, unpack
from .tcp_handle import TcpHandle


try:
    file_types = (file, io.IOBase)
except NameError:
    file_types = (io.IOBase,)

_LOGGER = logging.getLogger(__name__)

DeviceFile = collections.namedtuple('DeviceFile', ['filename', 'mode', 'size', 'mtime'])


class AdbDevice(object):
    """A class with methods for connecting to a device and sending shell commands.

    Parameters
    ----------
    serial : str
        ``<host>`` or ``<host>:<port>``
    banner : str, None
        The hostname of the machine where the Python interpreter is currently running; if
        it is not provided, it will be determined via ``socket.gethostname()``
    default_timeout_s : float, None
        Default timeout in seconds for TCP packets, or ``None``; see :class:`~adb_shell.tcp_handle.TcpHandle`

    Attributes
    ----------
    _available : bool
        Whether an ADB connection to the device has been established
    _banner : str
        The hostname of the machine where the Python interpreter is currently running
    _banner_bytes : bytearray
        ``self._banner`` converted to a bytearray
    _handle : TcpHandle
        The :class:`~adb_shell.tcp_handle.TcpHandle` instance that is used to connect to the device
    _serial : str
        ``<host>`` or ``<host>:<port>``

    """

    def __init__(self, serial, banner=None, default_timeout_s=None):
        if banner and isinstance(banner, str):
            self._banner = banner
        else:
            try:
                self._banner = socket.gethostname()
            except:  # noqa pylint: disable=bare-except
                self._banner = 'unknown'

        self._banner_bytes = bytearray(self._banner, 'utf-8')

        self._serial = serial

        self._handle = TcpHandle(self._serial, default_timeout_s)

        self._available = False

        self.send_buffer = bytearray(constants.MAX_ADB_DATA)
        self.send_idx = 0

        self.recv_buffer = bytearray()

    @property
    def available(self):
        """Whether or not an ADB connection to the device has been established.

        Returns
        -------
        bool
            ``self._available``

        """
        return self._available

    def close(self):
        """Close the socket connection via :meth:`adb_shell.tcp_handle.TcpHandle.close`.

        """
        self._available = False
        self._handle.close()

    def connect(self, rsa_keys=None, timeout_s=None, auth_timeout_s=constants.DEFAULT_AUTH_TIMEOUT_S, total_timeout_s=constants.DEFAULT_TOTAL_TIMEOUT_S):
        """Establish an ADB connection to the device.

        1. Use the handle to establish a socket connection
        2. Send a ``b'CNXN'`` message
        3. Unpack the ``cmd``, ``arg0``, ``arg1``, and ``banner`` fields from the response
        4. If ``cmd`` is not ``b'AUTH'``, then authentication is not necesary and so we are done
        5. If no ``rsa_keys`` are provided, raise an exception
        6. Loop through our keys, signing the last ``banner`` that we received

            1. If the last ``arg0`` was not :const:`adb_shell.constants.AUTH_TOKEN`, raise an exception
            2. Sign the last ``banner`` and send it in an ``b'AUTH'`` message
            3. Unpack the ``cmd``, ``arg0``, and ``banner`` fields from the response via :func:`adb_shell.adb_message.unpack`
            4. If ``cmd`` is ``b'CNXN'``, return ``banner``

        7. None of the keys worked, so send ``rsa_keys[0]``'s public key; if the response does not time out, we must have connected successfully


        Parameters
        ----------
        rsa_keys : list, None
            A list of signers of type :class:`~adb_shell.auth.sign_cryptography.CryptographySigner`,
            :class:`~adb_shell.auth.sign_pycryptodome.PycryptodomeAuthSigner`, or :class:`~adb_shell.auth.sign_pythonrsa.PythonRSASigner`
        timeout_s : float, None
            Timeout in seconds for TCP packets, or ``None``; see :meth:`TcpHandle.bulk_read() <adb_shell.tcp_handle.TcpHandle.bulk_read>`
            and :meth:`TcpHandle.bulk_write() <adb_shell.tcp_handle.TcpHandle.bulk_write>`
        auth_timeout_s : float, None
            The time in seconds to wait for a ``b'CNXN'`` authentication response
        total_timeout_s : float
            The total time in seconds to wait for expected commands in :meth:`AdbDevice._read`

        Returns
        -------
        bool
            Whether the connection was established (:attr:`AdbDevice.available`)

        Raises
        ------
        adb_shell.exceptions.DeviceAuthError
            Device authentication required, no keys available
        adb_shell.exceptions.InvalidResponseError
            Invalid auth response from the device

        """
        # 1. Use the handle to establish a socket connection
        self._handle.close()
        self._handle.connect(timeout_s)

        # 2. Send a ``b'CNXN'`` message
        msg = AdbMessage(constants.CNXN, constants.VERSION, constants.MAX_ADB_DATA, b'host::%s\0' % self._banner_bytes)
        self._send(msg, timeout_s)

        # 3. Unpack the ``cmd``, ``arg0``, ``arg1``, and ``banner`` fields from the response
        cmd, arg0, arg1, banner = self._read([constants.AUTH, constants.CNXN], timeout_s, total_timeout_s)

        # 4. If ``cmd`` is not ``b'AUTH'``, then authentication is not necesary and so we are done
        if cmd != constants.AUTH:
            self._available = True
            return True  # return banner

        # 5. If no ``rsa_keys`` are provided, raise an exception
        if not rsa_keys:
            self._handle.close()
            raise exceptions.DeviceAuthError('Device authentication required, no keys available.')

        # 6. Loop through our keys, signing the last ``banner`` that we received
        for rsa_key in rsa_keys:
            # 6.1. If the last ``arg0`` was not :const:`adb_shell.constants.AUTH_TOKEN`, raise an exception
            if arg0 != constants.AUTH_TOKEN:
                self._handle.close()
                raise exceptions.InvalidResponseError('Unknown AUTH response: %s %s %s' % (arg0, arg1, banner))

            # 6.2. Sign the last ``banner`` and send it in an ``b'AUTH'`` message
            signed_token = rsa_key.Sign(banner)
            msg = AdbMessage(constants.AUTH, constants.AUTH_SIGNATURE, 0, signed_token)
            self._send(msg, timeout_s)

            # 6.3. Unpack the ``cmd``, ``arg0``, and ``banner`` fields from the response via :func:`adb_shell.adb_message.unpack`
            cmd, arg0, _, banner = self._read([constants.CNXN, constants.AUTH], timeout_s, total_timeout_s)

            # 6.4. If ``cmd`` is ``b'CNXN'``, return ``banner``
            if cmd == constants.CNXN:
                self._available = True
                return True  # return banner

        # 7. None of the keys worked, so send ``rsa_keys[0]``'s public key; if the response does not time out, we must have connected successfully
        pubkey = rsa_keys[0].GetPublicKey()
        if isinstance(pubkey, str):
            pubkey = bytearray(pubkey, 'utf-8')
        msg = AdbMessage(constants.AUTH, constants.AUTH_RSAPUBLICKEY, 0, pubkey + b'\0')
        self._send(msg, timeout_s)

        cmd, arg0, _, banner = self._read([constants.CNXN], auth_timeout_s, total_timeout_s)
        self._available = True
        return True  # return banner

    def shell(self, command, timeout_s=None, total_timeout_s=constants.DEFAULT_TOTAL_TIMEOUT_S):
        """Send an ADB shell command to the device.

        Parameters
        ----------
        command : str
            The shell command that will be sent
        timeout_s : float, None
            Timeout in seconds for TCP packets, or ``None``; see :meth:`TcpHandle.bulk_read() <adb_shell.tcp_handle.TcpHandle.bulk_read>`
            and :meth:`TcpHandle.bulk_write() <adb_shell.tcp_handle.TcpHandle.bulk_write>`
        total_timeout_s : float
            The total time in seconds to wait for a ``b'CLSE'`` or ``b'OKAY'`` command in :meth:`AdbDevice._read`

        Returns
        -------
        str
            The output of the ADB shell command

        """
        return b''.join(self._streaming_command(b'shell', command.encode('utf8'), timeout_s, total_timeout_s)).decode('utf8')

    # ======================================================================= #
    #                                                                         #
    #                                 FileSync                                #
    #                                                                         #
    # ======================================================================= #
    def list(self, device_path, timeout_s=None, total_timeout_s=constants.DEFAULT_TOTAL_TIMEOUT_S):
        """Return a directory listing of the given path.

        Parameters
        ----------
        device_path : str
            Directory to list.
        timeout_s : float, None
            Expected timeout for any part of the pull.
        total_timeout_s : float
            The total time in seconds to wait for a ``b'CLSE'`` or ``b'OKAY'`` command in :meth:`AdbDevice._read`

        Returns
        -------
        files : TODO
            TODO

        """
        local_id, remote_id = self._open(b'sync:', timeout_s, total_timeout_s)

        self._filesync_send(constants.LIST, device_path)
        files = []

        for cmd_id, header, filename in self._filesync_read_until((constants.DENT,), (constants.DONE,), local_id, remote_id, timeout_s, total_timeout_s):
            if cmd_id == constants.DONE:
                break

            mode, size, mtime = header
            files.append(DeviceFile(filename, mode, size, mtime))

        self._close(local_id, remote_id, timeout_s, total_timeout_s)

        return files

    def pull(self, device_filename, dest_file=None, progress_callback=None, timeout_s=None, total_timeout_s=constants.DEFAULT_TOTAL_TIMEOUT_S):
        """Pull a file from the device.

        Parameters
        ----------
        device_filename : TODO
            Filename on the device to pull.
        dest_file : str, file, io.IOBase, None
            If set, a filename or writable file-like object.
        progress_callback : TODO, None
            Callback method that accepts filename, bytes_written and total_bytes, total_bytes will be -1 for file-like
            objects
        timeout_ms : int, None
            Expected timeout for any part of the pull.
        total_timeout_s : float
            The total time in seconds to wait for a ``b'CLSE'`` or ``b'OKAY'`` command in :meth:`AdbDevice._read`

        Returns
        -------
        TODO
            The file data if ``dest_file`` is not set. Otherwise, ``True`` if the destination file exists

        Raises
        ------
        ValueError
            If ``dest_file`` is of unknown type.

        """
        if not dest_file:
            dest_file = io.BytesIO()
        elif isinstance(dest_file, str):
            dest_file = open(dest_file, 'wb')
        elif isinstance(dest_file, file_types):
            pass
        else:
            raise ValueError("dest_file is of unknown type")

        local_id, remote_id = self._open(b'sync:', timeout_s, total_timeout_s)
        self._pull(device_filename, dest_file, progress_callback, local_id, remote_id, timeout_s, total_timeout_s)
        self._close(local_id, remote_id, timeout_s, total_timeout_s)

        if isinstance(dest_file, io.BytesIO):
            return dest_file.getvalue()

        dest_file.close()
        if hasattr(dest_file, 'name'):
            return os.path.exists(dest_file.name)

        # We don't know what the path is, so we just assume it exists.
        return True

    def _pull(self, filename, dest_file, progress_callback, local_id, remote_id, timeout_s, total_timeout_s):
        """Pull a file from the device into the file-like ``dest_file``.

        Parameters
        ----------
        filename : str
            The file to be pulled
        dest_file : _io.BytesIO
            File-like object for writing to
        progress_callback : function, None
            Callback method that accepts ``filename``, ``bytes_written``, and ``total_bytes``

        Raises
        ------
        PullFailedError
            Unable to pull file

        """
        if progress_callback:
            total_bytes = self.stat(filename)[1]
            progress = self._handle_progress(lambda current: progress_callback(filename, current, total_bytes))
            next(progress)

        # cnxn = FileSyncConnection(connection, b'<2I')
        # cnxn.Send(b'RECV', filename)
        self._filesync_send(constants.RECV, local_id, remote_id, timeout_s, total_timeout_s, filename)
        for cmd_id, _, data in self._filesync_read_until((constants.DATA,), (constants.DONE,), local_id, remote_id, timeout_s, total_timeout_s):
            if cmd_id == constants.DONE:
                break

            dest_file.write(data)
            if progress_callback:
                progress.send(len(data))

    def push(self, source_file, device_filename, st_mode=constants.DEFAULT_PUSH_MODE, mtime=0, progress_callback=None, timeout_s=None, total_timeout_s=constants.DEFAULT_TOTAL_TIMEOUT_S):
        """Push a file or directory to the device.

        Parameters
        ----------
        source_file : TODO
            Either a filename, a directory or file-like object to push to the device.
        device_filename : TODO
            Destination on the device to write to.
        st_mode : TODO, None
            Stat mode for filename
        mtime : int
            Modification time to set on the file.
        progress_callback : TODO, None
            Callback method that accepts filename, bytes_written and total_bytes, total_bytes will be -1 for file-like
            objects
        timeout_ms : int, None
            Expected timeout for any part of the push.
        total_timeout_s : float
            The total time in seconds to wait for a ``b'CLSE'`` or ``b'OKAY'`` command in :meth:`AdbDevice._read`

        """
        if isinstance(source_file, str):
            if os.path.isdir(source_file):
                self.shell("mkdir " + device_filename, timeout_s, total_timeout_s)
                for f in os.listdir(source_file):
                    self.push(os.path.join(source_file, f), device_filename + '/' + f, progress_callback=progress_callback)
                return

            source_file = open(source_file, "rb")

        with source_file:
            local_id, remote_id = self._open(b'sync:', timeout_s, total_timeout_s)
            self._push(source_file, device_filename, st_mode, local_id, remote_id, timeout_s, total_timeout_s, mtime=int(mtime), progress_callback=progress_callback)

        self._close(local_id, remote_id, timeout_s, total_timeout_s)

    def _push(self, datafile, filename, st_mode, local_id, remote_id, timeout_s, total_timeout_s, mtime, progress_callback):
        """Push a file-like object to the device.

        Parameters
        ----------
        datafile : _io.BytesIO
            File-like object for reading from
        filename : str
            Filename to push to
        st_mode : int
            Stat mode for filename
        local_id: int
            TODO
        remote_id: int
            TODO
        timeout_s: float
            TODO
        total_timeout_s: float
            TODO
        mtime : int
            Modification time
        progress_callback : function, None
            Callback method that accepts ``filename``, ``bytes_written``, and ``total_bytes``

        Raises
        ------
        PushFailedError
            Raised on push failure.

        """
        fileinfo = ('{},{}'.format(filename, int(st_mode))).encode('utf-8')

        # cnxn = FileSyncConnection(connection, b'<2I')
        # cnxn.Send(b'SEND', fileinfo)
        self._filesync_send(constants.SEND, local_id, remote_id, timeout_s, total_timeout_s, fileinfo)

        if progress_callback:
            total_bytes = os.fstat(datafile.fileno()).st_size if isinstance(datafile, file_types) else -1
            progress = self._handle_progress(lambda current: progress_callback(filename, current, total_bytes))
            next(progress)

        while True:
            data = datafile.read(constants.MAX_PUSH_DATA)
            if data:
                # cnxn.Send(b'DATA', data)
                self._filesync_send(constants.DATA, local_id, remote_id, timeout_s, total_timeout_s, data)

                if progress_callback:
                    progress.send(len(data))
            else:
                break

        if mtime == 0:
            mtime = int(time.time())
        # DONE doesn't send data, but it hides the last bit of data in the size
        # field.

        # cnxn.Send(b'DONE', size=mtime)
        self._filesync_send(constants.DONE, local_id, remote_id, timeout_s, total_timeout_s, size=mtime)
        for cmd_id, _, data in self._filesync_read_until(tuple(), (constants.OKAY, constants.FAIL), local_id, remote_id, timeout_s, total_timeout_s):
            if cmd_id == constants.OKAY:
                return

            raise exceptions.PushFailedError(data)

    def stat(self, device_filename, timeout_s=None, total_timeout_s=constants.DEFAULT_TOTAL_TIMEOUT_S):
        """Get a file's ``stat()`` information.

        Parameters
        ----------
        device_filename : TODO
            TODO
        timeout_ms : int, None
            Expected timeout for any part of the pull.
        total_timeout_s : float
            The total time in seconds to wait for a ``b'CLSE'`` or ``b'OKAY'`` command in :meth:`AdbDevice._read`

        Returns
        -------
        mode : TODO
            TODO
        size : TODO
            TODO
        mtime : TODO
            TODO

        """
        local_id, remote_id = self._open(b'sync:', timeout_s, total_timeout_s)

        self._filesync_send(constants.STAT, device_filename)
        command, (mode, size, mtime) = self._filesync_read((constants.STAT,), local_id, remote_id, timeout_s, total_timeout_s, read_data=False)
        self._close(local_id, remote_id, timeout_s, total_timeout_s)

        if command != constants.STAT:
            raise exceptions.InvalidResponseError('Expected STAT response to STAT, got %s' % command)

        return mode, size, mtime

    # THIS FUNCTION IS PROBABLY UNNECESSARY
    def _stat(self, filename):
        """Get file status (mode, size, and mtime).

        Parameters
        ----------
        filename : str, bytes
            The file for which we are getting info

        Returns
        -------
        mode : int
            The mode of the file
        size : int
            The size of the file
        mtime : int
            The time of last modification for the file

        Raises
        ------
        adb.adb_protocol.InvalidResponseError
            Expected STAT response to STAT, got something else

        """
        # cnxn = FileSyncConnection(connection, b'<4I')
        # cnxn.Send(b'STAT', filename)
        self._filesync_send(constants.STAT, filename)
        command, (mode, size, mtime) = self._filesync_read([constants.STAT], read_data=False)

        if command != constants.STAT:
            raise exceptions.InvalidResponseError('Expected STAT response to STAT, got %s' % command)

        return mode, size, mtime

    # ======================================================================= #
    #                                                                         #
    #                              Hidden Methods                             #
    #                                                                         #
    # ======================================================================= #
    def _close(self, local_id, remote_id, timeout_s, total_timeout_s):
        """TODO

        .. warning::

           This is not to be confused with the :meth:`AdbDevice.close` method!


        Parameters
        ----------
        local_id : int
            The ID for the sender (i.e., the device running this code), or ``None`` if a connection could not be opened
        remote_id : int
            The ID for the recipient, or ``None`` if a connection could not be opened
        timeout_s : float, None
            Timeout in seconds for TCP packets, or ``None``; see :meth:`TcpHandle.bulk_read() <adb_shell.tcp_handle.TcpHandle.bulk_read>`
            and :meth:`TcpHandle.bulk_write() <adb_shell.tcp_handle.TcpHandle.bulk_write>`
        total_timeout_s : float
            The total time in seconds to wait for a command in ``expected_cmds`` in :meth:`AdbDevice._read`

        """
        msg = AdbMessage(constants.CLSE, local_id, remote_id)
        self._send(msg, timeout_s)
        self._read_until(local_id, remote_id, [constants.CLSE], timeout_s, total_timeout_s)

    def _okay(self, local_id, remote_id, timeout_s):
        """Send an ``b'OKAY'`` mesage.

        Parameters
        ----------
        local_id : int
            The ID for the sender (i.e., the device running this code), or ``None`` if a connection could not be opened
        remote_id : int
            The ID for the recipient, or ``None`` if a connection could not be opened
        timeout_s : float, None
            Timeout in seconds for TCP packets, or ``None``; see :meth:`TcpHandle.bulk_read() <adb_shell.tcp_handle.TcpHandle.bulk_read>`
            and :meth:`TcpHandle.bulk_write() <adb_shell.tcp_handle.TcpHandle.bulk_write>`

        """
        msg = AdbMessage(constants.OKAY, local_id, remote_id)
        self._send(msg, timeout_s)

    def _open(self, destination, timeout_s, total_timeout_s):
        """Opens a new connection to the device via an ``b'OPEN'`` message.

        1. :meth:`~AdbDevice._send` an ``b'OPEN'`` command to the device that specifies the ``local_id``
        2. :meth:`~AdbDevice._read` a response from the device that includes a command, another local ID (``their_local_id``), and ``remote_id``

            * If ``local_id`` and ``their_local_id`` do not match, raise an exception.
            * If the received command is ``b'CLSE'``, :meth:`~AdbDevice._read` another response from the device
            * If the received command is not ``b'OKAY'``, raise an exception
            * Return ``local_id`` and ``remote_id``


        Parameters
        ----------
        destination : bytes
            ``b'SERVICE:COMMAND'``
        timeout_s : float, None
            Timeout in seconds for TCP packets, or ``None``; see :meth:`TcpHandle.bulk_read() <adb_shell.tcp_handle.TcpHandle.bulk_read>`
            and :meth:`TcpHandle.bulk_write() <adb_shell.tcp_handle.TcpHandle.bulk_write>`
        total_timeout_s : float
            The total time in seconds to wait for a ``b'CLSE'`` or ``b'OKAY'`` command in :meth:`AdbDevice._read`

        Returns
        -------
        local_id : int, None
            The ID for the sender (i.e., the device running this code), or ``None`` if a connection could not be opened
        remote_id : int, None
            The ID for the recipient, or ``None`` if a connection could not be opened

        Raises
        ------
        adb_shell.exceptions.InvalidResponseError
            Wrong local_id sent to us.

        """
        local_id = 1
        msg = AdbMessage(constants.OPEN, local_id, 0, destination + b'\0')
        self._send(msg, timeout_s)
        _, remote_id, their_local_id, _ = self._read([constants.OKAY], timeout_s, total_timeout_s)

        if local_id != their_local_id:
            raise exceptions.InvalidResponseError('Expected the local_id to be {}, got {}'.format(local_id, their_local_id))

        return local_id, remote_id

    def _read(self, expected_cmds, timeout_s, total_timeout_s):
        """Receive a response from the device.

        1. Read a message from the device and unpack the ``cmd``, ``arg0``, ``arg1``, ``data_length``, and ``data_checksum`` fields
        2. If ``cmd`` is not a recognized command in :const:`adb_shell.constants.WIRE_TO_ID`, raise an exception
        3. If the time has exceeded ``total_timeout_s``, raise an exception
        4. Read ``data_length`` bytes from the device
        5. If the checksum of the read data does not match ``data_checksum``, raise an exception
        6. Return ``command``, ``arg0``, ``arg1``, and ``bytes(data)``


        Parameters
        ----------
        expected_cmds : list[bytes]
            We will read packets until we encounter one whose "command" field is in ``expected_cmds``
        timeout_s : float, None
            Timeout in seconds for TCP packets, or ``None``; see :meth:`TcpHandle.bulk_read() <adb_shell.tcp_handle.TcpHandle.bulk_read>`
            and :meth:`TcpHandle.bulk_write() <adb_shell.tcp_handle.TcpHandle.bulk_write>`
        total_timeout_s : float
            The total time in seconds to wait for a command in ``expected_cmds``

        Returns
        -------
        command : bytes
            The received command, which is in :const:`adb_shell.constants.WIRE_TO_ID` and must be in ``expected_cmds``
        arg0 : int
            TODO
        arg1 : int
            TODO
        bytes
            The data that was read

        Raises
        ------
        adb_shell.exceptions.InvalidCommandError
            Unknown command *or* never got one of the expected responses.
        adb_shell.exceptions.InvalidChecksumError
            Received checksum does not match the expected checksum.

        """
        start = time.time()

        while True:
            msg = self._handle.bulk_read(constants.MESSAGE_SIZE, timeout_s)
            _LOGGER.debug("bulk_read(%d): %s", constants.MESSAGE_SIZE, repr(msg))
            cmd, arg0, arg1, data_length, data_checksum = unpack(msg)
            command = constants.WIRE_TO_ID.get(cmd)

            if not command:
                raise exceptions.InvalidCommandError('Unknown command: %x' % cmd, cmd, (arg0, arg1))

            if command in expected_cmds:
                break

            if time.time() - start > total_timeout_s:
                raise exceptions.InvalidCommandError('Never got one of the expected responses (%s)' % expected_cmds, cmd, (timeout_s, total_timeout_s))

        if data_length > 0:
            data = bytearray()
            while data_length > 0:
                temp = self._handle.bulk_read(data_length, timeout_s)
                _LOGGER.debug("bulk_read(%d): %s", data_length, repr(temp))

                data += temp
                data_length -= len(temp)

            actual_checksum = checksum(data)
            if actual_checksum != data_checksum:
                raise exceptions.InvalidChecksumError('Received checksum {0} != {1}'.format(actual_checksum, data_checksum))

        else:
            data = b''

        return command, arg0, arg1, bytes(data)

    def _read_until(self, local_id, remote_id, expected_cmds, timeout_s, total_timeout_s):
        """Read a packet, acknowledging any write packets.

        1. Read data via :meth:`AdbDevice._read`
        2. If a ``b'WRTE'`` packet is received, send an ``b'OKAY'`` packet via :meth:`AdbDevice._okay`
        3. Return the ``cmd`` and ``data`` that were read by :meth:`AdbDevice._read`


        Parameters
        ----------
        local_id : int
            The ID for the sender (i.e., the device running this code), or ``None`` if a connection could not be opened
        remote_id : int
            The ID for the recipient, or ``None`` if a connection could not be opened
        expected_cmds : list[bytes]
            :meth:`AdbDevice._read` with look for a packet whose command is in ``expected_cmds``
        timeout_s : float, None
            Timeout in seconds for TCP packets, or ``None``; see :meth:`TcpHandle.bulk_read() <adb_shell.tcp_handle.TcpHandle.bulk_read>`
            and :meth:`TcpHandle.bulk_write() <adb_shell.tcp_handle.TcpHandle.bulk_write>`
        total_timeout_s : float
            The total time in seconds to wait for a command in ``expected_cmds`` in :meth:`AdbDevice._read`

        Returns
        -------
        cmd : bytes
            The command that was received by :meth:`AdbDevice._read`, which is in :const:`adb_shell.constants.WIRE_TO_ID` and must be in ``expected_cmds``
        data : bytes
            The data that was received by :meth:`AdbDevice._read`

        Raises
        ------
        adb_shell.exceptions.InterleavedDataError
            We don't support multiple streams...
        adb_shell.exceptions.InvalidResponseError
            Incorrect remote id.
        adb_shell.exceptions.InvalidCommandError
            Never got one of the expected responses.

        """
        start = time.time()

        while True:
            cmd, remote_id2, local_id2, data = self._read(expected_cmds, timeout_s, total_timeout_s)

            if local_id2 not in (0, local_id):
                raise exceptions.InterleavedDataError("We don't support multiple streams...")

            if remote_id2 in (0, remote_id):
                break

            if time.time() - start > total_timeout_s:
                raise exceptions.InvalidCommandError('Never got one of the expected responses (%s)' % expected_cmds, cmd, (timeout_s, total_timeout_s))

            # Ignore CLSE responses to previous commands
            # https://github.com/JeffLIrion/adb_shell/pull/14
            if cmd != constants.CLSE:
                raise exceptions.InvalidResponseError('Incorrect remote id, expected {0} got {1}'.format(remote_id, remote_id2))

        # Acknowledge write packets
        if cmd == constants.WRTE:
            self._okay(local_id, remote_id, timeout_s)

        return cmd, data

    def _read_until_close(self, local_id, remote_id, timeout_s, total_timeout_s):
        """Yield packets until a ``b'CLSE'`` packet is received.

        1. Read the ``cmd`` and ``data`` fields from a ``b'CLSE'`` or ``b'WRTE'`` packet via :meth:`AdbDevice._read_until`
        2. If ``cmd`` is ``b'CLSE'``, then send a ``b'CLSE'`` message and stop
        3. If ``cmd`` is not ``b'WRTE'``, raise an exception

            * If ``cmd`` is ``b'FAIL'``, raise :class:`~adb_shell.exceptions.AdbCommandFailureException`
            * Otherwise, raise :class:`~~adb_shell.exceptions.InvalidCommandError`

        4. Yield ``data`` and repeat


        Parameters
        ----------
        local_id : int
            The ID for the sender (i.e., the device running this code), or ``None`` if a connection could not be opened
        remote_id : int
            The ID for the recipient, or ``None`` if a connection could not be opened
        timeout_s : float, None
            Timeout in seconds for TCP packets, or ``None``; see :meth:`adb_shell.tcp_handle.TcpHandle.bulk_read <TcpHandle.bulk_read()>`
            and :meth:`adb_shell.tcp_handle.TcpHandle.bulk_write <TcpHandle.bulk_write()>`
        total_timeout_s : float
            The total time in seconds to wait for a ``b'CLSE'`` or ``b'WRTE'`` command in :meth:`AdbDevice._read`

        Yields
        ------
        data : bytes
            The data that was read by :meth:`AdbDevice._read_until`

        """
        while True:
            cmd, data = self._read_until(local_id, remote_id, [constants.CLSE, constants.WRTE], timeout_s, total_timeout_s)

            if cmd == constants.CLSE:
                msg = AdbMessage(constants.CLSE, local_id, remote_id)
                self._send(msg, timeout_s)
                break

            yield data

    def _send(self, msg, timeout_s):
        """Send a message to the device.

        1. Send the message header (:meth:`adb_shell.adb_message.AdbMessage.pack <AdbMessage.pack>`)
        2. Send the message data


        Parameters
        ----------
        msg : AdbMessage
            The data that will be sent
        timeout_s : float, None
            Timeout in seconds for TCP packets, or ``None``; see :meth:`TcpHandle.bulk_write() <adb_shell.tcp_handle.TcpHandle.bulk_write>`

        """
        _LOGGER.debug("bulk_write: %s", repr(msg.pack()))
        self._handle.bulk_write(msg.pack(), timeout_s)
        _LOGGER.debug("bulk_write: %s", repr(msg.data))
        self._handle.bulk_write(msg.data, timeout_s)

    def _streaming_command(self, service, command, timeout_s, total_timeout_s):
        """One complete set of USB packets for a single command.

        1. :meth:`~AdbDevice._open` a new connection to the device, where the ``destination`` parameter is ``service:command``
        2. Read the response data via :meth:`AdbDevice._read_until_close`


        .. note::

           All the data is held in memory, and thus large responses will be slow and can fill up memory.


        Parameters
        ----------
        service : bytes
            The ADB service (e.g., ``b'shell'``, as used by :meth:`AdbDevice.shell`)
        command : bytes
            The service command
        timeout_s : float, None
            Timeout in seconds for TCP packets, or ``None``; see :meth:`TcpHandle.bulk_read() <adb_shell.tcp_handle.TcpHandle.bulk_read>`
            and :meth:`TcpHandle.bulk_write() <adb_shell.tcp_handle.TcpHandle.bulk_write>`
        total_timeout_s : float
            The total time in seconds to wait for a command in ``expected_cmds`` in :meth:`AdbDevice._read`

        Yields
        ------
        str
            The responses from the service.

        """
        local_id, remote_id = self._open(b'%s:%s' % (service, command), timeout_s, total_timeout_s)

        for data in self._read_until_close(local_id, remote_id, timeout_s, total_timeout_s):
            yield data

    def _write(self, local_id, remote_id, data, timeout_s, total_timeout_s):
        """Write a packet and expect an Ack.

        Parameters
        ----------
        local_id : TODO
            TODO
        remote_id : TODO
            TODO
        data : TODO
            TODO

        Returns
        -------
        int
            ``len(data)``

        Raises
        ------
        usb_exceptions.AdbCommandFailureException
            The command failed.
        adb.adb_protocol.InvalidCommandError
            Expected an OKAY in response to a WRITE, got something else.

        """
        msg = AdbMessage(constants.WRTE, local_id, remote_id, data)
        self._send(msg, timeout_s)

        # Expect an ack in response.
        cmd, okay_data = self._read_until(local_id, remote_id, [constants.OKAY], timeout_s, total_timeout_s)
        if cmd != b'OKAY':
            if cmd == b'FAIL':
                raise exceptions.AdbCommandFailureException('Command failed.', okay_data)

            raise exceptions.InvalidCommandError('Expected an OKAY in response to a WRITE, got {0} ({1})'.format(cmd, okay_data), cmd, okay_data)

        return len(data)

    # ======================================================================= #
    #                                                                         #
    #                         FileSync Hidden Methods                         #
    #                                                                         #
    # ======================================================================= #
    @staticmethod
    def _handle_progress(progress_callback):
        """Calls the callback with the current progress and total bytes written/received.

        Parameters
        ----------
        progress_callback : function
            Callback method that accepts ``filename``, ``bytes_written``, and ``total_bytes``; total_bytes will be -1 for file-like
            objects.

        """
        current = 0
        while True:
            current += yield
            try:
                progress_callback(current)
            except Exception:  # pylint: disable=broad-except
                continue

    def _filesync_send(self, command_id, local_id, remote_id, timeout_s, total_timeout_s, data=b'', size=0):
        """Send/buffer FileSync packets.

        Packets are buffered and only flushed when this connection is read from. All
        messages have a response from the device, so this will always get flushed.

        Parameters
        ----------
        command_id : bytes
            Command to send.
        local_id: int
            TODO
        remote_id: int
            TODO
        timeout_s: float
            TODO
        total_timeout_s: float
            TODO
        data : str, bytes
            Optional data to send, must set data or size.
        size : int
            Optionally override size from len(data).

        """
        if data:
            if not isinstance(data, bytes):
                data = data.encode('utf8')
            size = len(data)

        if not self._can_add_to_send_buffer(len(data)):
            self._filesync_flush(local_id, remote_id, timeout_s, total_timeout_s)

        buf = struct.pack(constants.FILESYNC_FORMAT, constants.FILESYNC_ID_TO_WIRE[command_id], size) + data
        self.send_buffer[self.send_idx:self.send_idx + len(buf)] = buf
        self.send_idx += len(buf)

    def _filesync_read(self, expected_ids, local_id, remote_id, timeout_s, total_timeout_s, read_data=True):
        """Read ADB messages and return FileSync packets.

        Parameters
        ----------
        expected_ids : tuple[bytes]
            If the received header ID is not in ``expected_ids``, an exception will be raised
        local_id: int
            TODO
        remote_id: int
            TODO
        timeout_s: float
            TODO
        total_timeout_s: float
            TODO
        read_data : bool
            Whether to read the received data

        Returns
        -------
        command_id : bytes
            The received header ID
        tuple
            TODO
        data : bytearray
            The received data

        Raises
        ------
        adb.usb_exceptions.AdbCommandFailureException
            Command failed
        adb.adb_protocol.InvalidResponseError
            Received response was not in ``expected_ids``

        """
        if self.send_idx:
            self._filesync_flush(local_id, remote_id, timeout_s, total_timeout_s)

        # Read one filesync packet off the recv buffer.
        header_data = self._filesync_read_buffered(constants.FILESYNC_MESSAGE_SIZE, local_id, remote_id, timeout_s, total_timeout_s)
        header = struct.unpack(constants.FILESYNC_FORMAT, header_data)
        # Header is (ID, ...).
        command_id = constants.FILESYNC_WIRE_TO_ID[header[0]]

        if command_id not in expected_ids:
            if command_id == constants.FAIL:
                reason = ''
                if self.recv_buffer:
                    reason = self.recv_buffer.decode('utf-8', errors='ignore')

                raise exceptions.AdbCommandFailureException('Command failed: {}'.format(reason))

            raise exceptions.InvalidResponseError('Expected one of %s, got %s' % (expected_ids, command_id))

        if not read_data:
            return command_id, header[1:]

        # Header is (ID, ..., size).
        size = header[-1]
        data = self._filesync_read_buffered(size, local_id, remote_id, timeout_s, total_timeout_s)

        return command_id, header[1:-1], data

    def _filesync_read_until(self, expected_ids, finish_ids, local_id, remote_id, timeout_s, total_timeout_s):
        """Useful wrapper around :meth:`AdbDevice._filesync_read`.

        Parameters
        ----------
        expected_ids : tuple[bytes]
            If the received header ID is not in ``expected_ids``, an exception will be raised
        finish_ids : tuple[bytes]
            We will read until we find a header ID that is in ``finish_ids``
        local_id: int
            TODO
        remote_id: int
            TODO
        timeout_s: float
            TODO
        total_timeout_s: float
            TODO

        Yields
        ------
        cmd_id : bytes
            The received header ID
        header : tuple
            TODO
        data : bytearray
            The received data

        """
        while True:
            cmd_id, header, data = self._filesync_read(expected_ids + finish_ids, local_id, remote_id, timeout_s, total_timeout_s)
            yield cmd_id, header, data
            if cmd_id in finish_ids:
                break

    def _can_add_to_send_buffer(self, data_len):
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
        added_len = constants.FILESYNC_MESSAGE_SIZE + data_len
        return self.send_idx + added_len < constants.MAX_ADB_DATA

    def _filesync_flush(self, local_id, remote_id, timeout_s, total_timeout_s):
        """TODO

        """
        self._write(local_id, remote_id, self.send_buffer[:self.send_idx], timeout_s, total_timeout_s)
        self.send_idx = 0

    def _filesync_read_buffered(self, size, local_id, remote_id, timeout_s, total_timeout_s):
        """Read ``size`` bytes of data from ``self.recv_buffer``.

        Parameters
        ----------
        size : int
            The amount of data to read
        local_id: int
            TODO
        remote_id: int
            TODO
        timeout_s: float
            TODO
        total_timeout_s: float
            TODO

        Returns
        -------
        result : bytearray
            The read data

        """
        # Ensure recv buffer has enough data.
        while len(self.recv_buffer) < size:
            _, data = self._read_until(local_id, remote_id, [constants.WRTE], timeout_s, total_timeout_s)
            self.recv_buffer += data

        result = self.recv_buffer[:size]
        self.recv_buffer = self.recv_buffer[size:]
        return result
