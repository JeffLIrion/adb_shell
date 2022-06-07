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

"""Implement the :class:`AdbDevice` class, which can connect to a device and run ADB shell commands.

.. rubric:: Contents

* :class:`_AdbIOManager`

    * :meth:`_AdbIOManager._read_bytes_from_device`
    * :meth:`_AdbIOManager._read_expected_packet_from_device`
    * :meth:`_AdbIOManager._read_packet_from_device`
    * :meth:`_AdbIOManager._send`
    * :meth:`_AdbIOManager.close`
    * :meth:`_AdbIOManager.connect`
    * :meth:`_AdbIOManager.read`
    * :meth:`_AdbIOManager.send`

* :func:`_open_bytesio`

* :class:`AdbDevice`

    * :meth:`AdbDevice._clse`
    * :meth:`AdbDevice._filesync_flush`
    * :meth:`AdbDevice._filesync_read`
    * :meth:`AdbDevice._filesync_read_buffered`
    * :meth:`AdbDevice._filesync_read_until`
    * :meth:`AdbDevice._filesync_send`
    * :meth:`AdbDevice._okay`
    * :meth:`AdbDevice._open`
    * :meth:`AdbDevice._pull`
    * :meth:`AdbDevice._push`
    * :meth:`AdbDevice._read_until`
    * :meth:`AdbDevice._read_until_close`
    * :meth:`AdbDevice._service`
    * :meth:`AdbDevice._streaming_command`
    * :meth:`AdbDevice._streaming_service`
    * :attr:`AdbDevice.available`
    * :meth:`AdbDevice.close`
    * :meth:`AdbDevice.connect`
    * :meth:`AdbDevice.list`
    * :attr:`AdbDevice.max_chunk_size`
    * :meth:`AdbDevice.pull`
    * :meth:`AdbDevice.push`
    * :meth:`AdbDevice.root`
    * :meth:`AdbDevice.shell`
    * :meth:`AdbDevice.stat`
    * :meth:`AdbDevice.streaming_shell`

* :class:`AdbDeviceTcp`
* :class:`AdbDeviceUsb`

"""


from contextlib import contextmanager
from io import BytesIO
import logging
import os
import struct
import sys
from threading import Lock
import time

from . import constants
from . import exceptions
from .adb_message import AdbMessage, checksum, int_to_cmd, unpack
from .transport.base_transport import BaseTransport
from .transport.tcp_transport import TcpTransport
from .hidden_helpers import DeviceFile, _AdbPacketStore, _AdbTransactionInfo, _FileSyncTransactionInfo, get_banner, get_files_to_push

try:
    from .transport.usb_transport import UsbTransport
except (ImportError, OSError):
    UsbTransport = None


_LOGGER = logging.getLogger(__name__)

_DECODE_ERRORS = "backslashreplace" if sys.version_info[0] > 2 else "replace"


@contextmanager
def _open_bytesio(stream, *args, **kwargs):  # pylint: disable=unused-argument
    """A context manager for a BytesIO object that does nothing.

    Parameters
    ----------
    stream : BytesIO
        The BytesIO stream
    args : list
        Unused positional arguments
    kwargs : dict
        Unused keyword arguments

    Yields
    ------
    stream : BytesIO
        The `stream` input parameter

    """
    yield stream


class _AdbIOManager(object):
    """A class for handling all ADB I/O.

    Notes
    -----
    When the ``self._store_lock`` and ``self._transport_lock`` locks are held at the same time, it must always be the
    case that the ``self._transport_lock`` is acquired first.  This ensures that  there is no potential for deadlock.

    Parameters
    ----------
    transport : BaseTransport
        A transport for communicating with the device; must be an instance of a subclass of :class:`~adb_shell.transport.base_transport.BaseTransport`

    Attributes
    ----------
    _packet_store : _AdbPacketStore
        A store for holding packets that correspond to different ADB streams
    _store_lock : Lock
        A lock for protecting ``self._packet_store`` (this lock is never held for long)
    _transport : BaseTransport
        A transport for communicating with the device; must be an instance of a subclass of :class:`~adb_shell.transport.base_transport.BaseTransport`
    _transport_lock : Lock
        A lock for protecting ``self._transport``

    """

    def __init__(self, transport):
        self._packet_store = _AdbPacketStore()
        self._transport = transport

        self._store_lock = Lock()
        self._transport_lock = Lock()

    def close(self):
        """Close the connection via the provided transport's ``close()`` method and clear the packet store.

        """
        with self._transport_lock:
            self._transport.close()

            with self._store_lock:
                self._packet_store.clear_all()

    def connect(self, banner, rsa_keys, auth_timeout_s, auth_callback, adb_info):
        """Establish an ADB connection to the device.

        1. Use the transport to establish a connection
        2. Send a ``b'CNXN'`` message
        3. Read the response from the device
        4. If ``cmd`` is not ``b'AUTH'``, then authentication is not necesary and so we are done
        5. If no ``rsa_keys`` are provided, raise an exception
        6. Loop through our keys, signing the last ``banner2`` that we received

            1. If the last ``arg0`` was not :const:`adb_shell.constants.AUTH_TOKEN`, raise an exception
            2. Sign the last ``banner2`` and send it in an ``b'AUTH'`` message
            3. Read the response from the device
            4. If ``cmd`` is ``b'CNXN'``, we are done

        7. None of the keys worked, so send ``rsa_keys[0]``'s public key; if the response does not time out, we must have connected successfully


        Parameters
        ----------
        banner : bytearray, bytes
            The hostname of the machine where the Python interpreter is currently running (:attr:`adb_shell.adb_device.AdbDevice._banner`)
        rsa_keys : list, None
            A list of signers of type :class:`~adb_shell.auth.sign_cryptography.CryptographySigner`,
            :class:`~adb_shell.auth.sign_pycryptodome.PycryptodomeAuthSigner`, or :class:`~adb_shell.auth.sign_pythonrsa.PythonRSASigner`
        auth_timeout_s : float, None
            The time in seconds to wait for a ``b'CNXN'`` authentication response
        auth_callback : function, None
            Function callback invoked when the connection needs to be accepted on the device
        adb_info : _AdbTransactionInfo
            Info and settings for this connection attempt

        Returns
        -------
        bool
            Whether the connection was established
        maxdata : int
            Maximum amount of data in an ADB packet

        Raises
        ------
        adb_shell.exceptions.DeviceAuthError
            Device authentication required, no keys available
        adb_shell.exceptions.InvalidResponseError
            Invalid auth response from the device

        """
        with self._transport_lock:
            # 0. Close the connection and clear the store
            self._transport.close()

            with self._store_lock:
                # We can release this lock because packets are only added to the store when the transport lock is held
                self._packet_store.clear_all()

            # 1. Use the transport to establish a connection
            self._transport.connect(adb_info.transport_timeout_s)

            # 2. Send a ``b'CNXN'`` message
            msg = AdbMessage(constants.CNXN, constants.VERSION, constants.MAX_ADB_DATA, b'host::%s\0' % banner)
            self._send(msg, adb_info)

            # 3. Read the response from the device
            cmd, arg0, maxdata, banner2 = self._read_expected_packet_from_device([constants.AUTH, constants.CNXN], adb_info)

            # 4. If ``cmd`` is not ``b'AUTH'``, then authentication is not necesary and so we are done
            if cmd != constants.AUTH:
                return True, maxdata

            # 5. If no ``rsa_keys`` are provided, raise an exception
            if not rsa_keys:
                self._transport.close()
                raise exceptions.DeviceAuthError('Device authentication required, no keys available.')

            # 6. Loop through our keys, signing the last ``banner2`` that we received
            for rsa_key in rsa_keys:
                # 6.1. If the last ``arg0`` was not :const:`adb_shell.constants.AUTH_TOKEN`, raise an exception
                if arg0 != constants.AUTH_TOKEN:
                    self._transport.close()
                    raise exceptions.InvalidResponseError('Unknown AUTH response: %s %s %s' % (arg0, maxdata, banner2))

                # 6.2. Sign the last ``banner2`` and send it in an ``b'AUTH'`` message
                signed_token = rsa_key.Sign(banner2)
                msg = AdbMessage(constants.AUTH, constants.AUTH_SIGNATURE, 0, signed_token)
                self._send(msg, adb_info)

                # 6.3. Read the response from the device
                cmd, arg0, maxdata, banner2 = self._read_expected_packet_from_device([constants.CNXN, constants.AUTH], adb_info)

                # 6.4. If ``cmd`` is ``b'CNXN'``, we are done
                if cmd == constants.CNXN:
                    return True, maxdata

            # 7. None of the keys worked, so send ``rsa_keys[0]``'s public key; if the response does not time out, we must have connected successfully
            pubkey = rsa_keys[0].GetPublicKey()
            if not isinstance(pubkey, (bytes, bytearray)):
                pubkey = bytearray(pubkey, 'utf-8')

            if auth_callback is not None:
                auth_callback(self)

            msg = AdbMessage(constants.AUTH, constants.AUTH_RSAPUBLICKEY, 0, pubkey + b'\0')
            self._send(msg, adb_info)

            adb_info.transport_timeout_s = auth_timeout_s
            _, _, maxdata, _ = self._read_expected_packet_from_device([constants.CNXN], adb_info)
            return True, maxdata

    def read(self, expected_cmds, adb_info, allow_zeros=False):
        """Read packets from the device until we get an expected packet type.

        1. See if the expected packet is in the packet store
        2. While the time limit has not been exceeded:

            1. See if the expected packet is in the packet store
            2. Read a packet from the device.  If it matches what we are looking for, we are done.  If it corresponds to a different stream, add it to the store.

        3. Raise a timeout exception


        Parameters
        ----------
        expected_cmds : list[bytes]
            We will read packets until we encounter one whose "command" field is in ``expected_cmds``
        adb_info : _AdbTransactionInfo
            Info and settings for this ADB transaction
        allow_zeros : bool
            Whether to allow the received ``arg0`` and ``arg1`` values to match with 0, in addition to ``adb_info.remote_id`` and ``adb_info.local_id``, respectively

        Returns
        -------
        cmd : bytes
            The received command, which is in :const:`adb_shell.constants.WIRE_TO_ID` and must be in ``expected_cmds``
        arg0 : int
            TODO
        arg1 : int
            TODO
        data : bytes
            The data that was read

        Raises
        ------
        adb_shell.exceptions.AdbTimeoutError
            Never got one of the expected responses

        """
        # First, try reading from the store. This way, you won't be waiting for the transport if it isn't needed
        with self._store_lock:
            # Recall that `arg0` from the device corresponds to `adb_info.remote_id` and `arg1` from the device corresponds to `adb_info.local_id`
            arg0_arg1 = self._packet_store.find(adb_info.remote_id, adb_info.local_id) if not allow_zeros else self._packet_store.find_allow_zeros(adb_info.remote_id, adb_info.local_id)
            while arg0_arg1:
                cmd, arg0, arg1, data = self._packet_store.get(arg0_arg1[0], arg0_arg1[1])
                if cmd in expected_cmds:
                    return cmd, arg0, arg1, data

                arg0_arg1 = self._packet_store.find(adb_info.remote_id, adb_info.local_id) if not allow_zeros else self._packet_store.find_allow_zeros(adb_info.remote_id, adb_info.local_id)

        # Start the timer
        start = time.time()

        while True:
            with self._transport_lock:
                # Try reading from the store (again) in case a packet got added while waiting to acquire the transport lock
                with self._store_lock:
                    # Recall that `arg0` from the device corresponds to `adb_info.remote_id` and `arg1` from the device corresponds to `adb_info.local_id`
                    arg0_arg1 = self._packet_store.find(adb_info.remote_id, adb_info.local_id) if not allow_zeros else self._packet_store.find_allow_zeros(adb_info.remote_id, adb_info.local_id)
                    while arg0_arg1:
                        cmd, arg0, arg1, data = self._packet_store.get(arg0_arg1[0], arg0_arg1[1])
                        if cmd in expected_cmds:
                            return cmd, arg0, arg1, data

                        arg0_arg1 = self._packet_store.find(adb_info.remote_id, adb_info.local_id) if not allow_zeros else self._packet_store.find_allow_zeros(adb_info.remote_id, adb_info.local_id)

                # Read from the device
                cmd, arg0, arg1, data = self._read_packet_from_device(adb_info)

                if not adb_info.args_match(arg0, arg1, allow_zeros):
                    # The packet is not a match -> put it in the store
                    with self._store_lock:
                        self._packet_store.put(arg0, arg1, cmd, data)

                else:
                    # The packet is a match for this `(adb_info.local_id, adb_info.remote_id)` pair
                    if cmd == constants.CLSE:
                        # Clear the entry in the store
                        with self._store_lock:
                            self._packet_store.clear(arg0, arg1)

                    # If `cmd` is a match, then we are done
                    if cmd in expected_cmds:
                        return cmd, arg0, arg1, data

            # Check if time is up
            if time.time() - start > adb_info.read_timeout_s:
                break

        # Timeout
        raise exceptions.AdbTimeoutError("Never got one of the expected responses: {} (transport_timeout_s = {}, read_timeout_s = {})".format(expected_cmds, adb_info.transport_timeout_s, adb_info.read_timeout_s))

    def send(self, msg, adb_info):
        """Send a message to the device.

        Parameters
        ----------
        msg : AdbMessage
            The data that will be sent
        adb_info : _AdbTransactionInfo
            Info and settings for this ADB transaction

        """
        with self._transport_lock:
            self._send(msg, adb_info)

    def _read_expected_packet_from_device(self, expected_cmds, adb_info):
        """Read packets from the device until we get an expected packet type.

        Parameters
        ----------
        expected_cmds : list[bytes]
            We will read packets until we encounter one whose "command" field is in ``expected_cmds``
        adb_info : _AdbTransactionInfo
            Info and settings for this ADB transaction

        Returns
        -------
        cmd : bytes
            The received command, which is in :const:`adb_shell.constants.WIRE_TO_ID` and must be in ``expected_cmds``
        arg0 : int
            TODO
        arg1 : int
            TODO
        data : bytes
            The data that was read

        Raises
        ------
        adb_shell.exceptions.AdbTimeoutError
            Never got one of the expected responses

        """
        start = time.time()

        while True:
            cmd, arg0, arg1, data = self._read_packet_from_device(adb_info)

            if cmd in expected_cmds:
                return cmd, arg0, arg1, data

            if time.time() - start > adb_info.read_timeout_s:
                # Timeout
                raise exceptions.AdbTimeoutError("Never got one of the expected responses: {} (transport_timeout_s = {}, read_timeout_s = {})".format(expected_cmds, adb_info.transport_timeout_s, adb_info.read_timeout_s))

    def _read_bytes_from_device(self, length, adb_info):
        """Read ``length`` bytes from the device.

        Parameters
        ----------
        length : int
            We will read packets until we get this length of data
        adb_info : _AdbTransactionInfo
            Info and settings for this ADB transaction

        Returns
        -------
        bytes
            The data that was read

        Raises
        ------
        adb_shell.exceptions.AdbTimeoutError
            Did not read ``length`` bytes in time

        """
        start = time.time()
        data = bytearray()

        while length > 0:
            temp = self._transport.bulk_read(length, adb_info.transport_timeout_s)
            if temp:
                # Only log if `temp` is not empty
                _LOGGER.debug("bulk_read(%d): %.1000r", length, temp)

            data += temp
            length -= len(temp)

            if length == 0:
                break

            if time.time() - start > adb_info.read_timeout_s:
                # Timeout
                raise exceptions.AdbTimeoutError("Timeout: read {} of {} bytes (transport_timeout_s = {}, read_timeout_s = {})".format(len(data), len(data) + length, adb_info.transport_timeout_s, adb_info.read_timeout_s))

        return bytes(data)

    def _read_packet_from_device(self, adb_info):
        """Read a complete ADB packet (header + data) from the device.

        Parameters
        ----------
        adb_info : _AdbTransactionInfo
            Info and settings for this ADB transaction

        Returns
        -------
        cmd : bytes
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
            Unknown command
        adb_shell.exceptions.InvalidChecksumError
            Received checksum does not match the expected checksum

       """
        msg = self._read_bytes_from_device(constants.MESSAGE_SIZE, adb_info)
        cmd, arg0, arg1, data_length, data_checksum = unpack(msg)
        command = constants.WIRE_TO_ID.get(cmd)

        if not command:
            raise exceptions.InvalidCommandError("Unknown command: %d = '%s' (arg0 = %d, arg1 = %d, msg = '%s')" % (cmd, int_to_cmd(cmd), arg0, arg1, msg))

        if data_length == 0:
            return command, arg0, arg1, b""

        data = self._read_bytes_from_device(data_length, adb_info)
        actual_checksum = checksum(data)
        if actual_checksum != data_checksum:
            raise exceptions.InvalidChecksumError("Received checksum {} != {}".format(actual_checksum, data_checksum))

        return command, arg0, arg1, data

    def _send(self, msg, adb_info):
        """Send a message to the device.

        1. Send the message header (:meth:`adb_shell.adb_message.AdbMessage.pack <AdbMessage.pack>`)
        2. Send the message data


        Parameters
        ----------
        msg : AdbMessage
            The data that will be sent
        adb_info : _AdbTransactionInfo
            Info and settings for this ADB transaction

        """
        packed = msg.pack()
        _LOGGER.debug("bulk_write(%d): %r", len(packed), packed)
        self._transport.bulk_write(packed, adb_info.transport_timeout_s)

        if msg.data:
            _LOGGER.debug("bulk_write(%d): %r", len(msg.data), msg.data)
            self._transport.bulk_write(msg.data, adb_info.transport_timeout_s)


class AdbDevice(object):
    """A class with methods for connecting to a device and executing ADB commands.

    Parameters
    ----------
    transport : BaseTransport
        A user-provided transport for communicating with the device; must be an instance of a subclass of :class:`~adb_shell.transport.base_transport.BaseTransport`
    default_transport_timeout_s : float, None
        Default timeout in seconds for transport packets, or ``None``
    banner : str, bytes, None
        The hostname of the machine where the Python interpreter is currently running; if
        it is not provided, it will be determined via ``socket.gethostname()``

    Raises
    ------
    adb_shell.exceptions.InvalidTransportError
        The passed ``transport`` is not an instance of a subclass of :class:`~adb_shell.transport.base_transport.BaseTransport`

    Attributes
    ----------
    _available : bool
        Whether an ADB connection to the device has been established
    _banner : bytearray, bytes
        The hostname of the machine where the Python interpreter is currently running
    _default_transport_timeout_s : float, None
        Default timeout in seconds for transport packets, or ``None``
    _io_manager : _AdbIOManager
        Used for handling all ADB I/O
    _local_id : int
        The local ID that is used for ADB transactions; the value is incremented each time and is always in the range ``[1, 2^32)``
    _local_id_lock : Lock
        A lock for protecting ``_local_id``; this is never held for long
    _maxdata: int
        Maximum amount of data in an ADB packet

    """

    def __init__(self, transport, default_transport_timeout_s=None, banner=None):
        if banner and not isinstance(banner, (bytes, bytearray)):
            self._banner = bytearray(banner, 'utf-8')
        else:
            self._banner = banner

        if not isinstance(transport, BaseTransport):
            raise exceptions.InvalidTransportError("`transport` must be an instance of a subclass of `BaseTransport`")

        self._io_manager = _AdbIOManager(transport)

        self._available = False
        self._default_transport_timeout_s = default_transport_timeout_s
        self._local_id = 0
        self._local_id_lock = Lock()
        self._maxdata = constants.MAX_PUSH_DATA

    # ======================================================================= #
    #                                                                         #
    #                       Properties & simple methods                       #
    #                                                                         #
    # ======================================================================= #
    @property
    def available(self):
        """Whether or not an ADB connection to the device has been established.

        Returns
        -------
        bool
            ``self._available``

        """
        return self._available

    @property
    def max_chunk_size(self):
        """Maximum chunk size for filesync operations

        Returns
        -------
        int
            Minimum value based on :const:`adb_shell.constants.MAX_CHUNK_SIZE` and ``_max_data / 2``, fallback to legacy :const:`adb_shell.constants.MAX_PUSH_DATA`

        """
        return min(constants.MAX_CHUNK_SIZE, self._maxdata // 2) or constants.MAX_PUSH_DATA

    def _get_transport_timeout_s(self, transport_timeout_s):
        """Use the provided ``transport_timeout_s`` if it is not ``None``; otherwise, use ``self._default_transport_timeout_s``

        Parameters
        ----------
        transport_timeout_s : float, None
            The potential transport timeout

        Returns
        -------
        float
            ``transport_timeout_s`` if it is not ``None``; otherwise, ``self._default_transport_timeout_s``

        """
        return transport_timeout_s if transport_timeout_s is not None else self._default_transport_timeout_s

    # ======================================================================= #
    #                                                                         #
    #                             Close & Connect                             #
    #                                                                         #
    # ======================================================================= #
    def close(self):
        """Close the connection via the provided transport's ``close()`` method.

        """
        self._available = False
        self._io_manager.close()

    def connect(self, rsa_keys=None, transport_timeout_s=None, auth_timeout_s=constants.DEFAULT_AUTH_TIMEOUT_S, read_timeout_s=constants.DEFAULT_READ_TIMEOUT_S, auth_callback=None):
        """Establish an ADB connection to the device.

        See :meth:`_AdbIOManager.connect`.

        Parameters
        ----------
        rsa_keys : list, None
            A list of signers of type :class:`~adb_shell.auth.sign_cryptography.CryptographySigner`,
            :class:`~adb_shell.auth.sign_pycryptodome.PycryptodomeAuthSigner`, or :class:`~adb_shell.auth.sign_pythonrsa.PythonRSASigner`
        transport_timeout_s : float, None
            Timeout in seconds for sending and receiving data, or ``None``; see :meth:`BaseTransport.bulk_read() <adb_shell.transport.base_transport.BaseTransport.bulk_read>`
            and :meth:`BaseTransport.bulk_write() <adb_shell.transport.base_transport.BaseTransport.bulk_write>`
        auth_timeout_s : float, None
            The time in seconds to wait for a ``b'CNXN'`` authentication response
        read_timeout_s : float
            The total time in seconds to wait for expected commands in :meth:`_AdbIOManager._read_expected_packet_from_device`
        auth_callback : function, None
            Function callback invoked when the connection needs to be accepted on the device

        Returns
        -------
        bool
            Whether the connection was established (:attr:`AdbDevice.available`)

        """
        # Get `self._banner` if it was not provided in the constructor
        if not self._banner:
            self._banner = get_banner()

        # Instantiate the `_AdbTransactionInfo`
        adb_info = _AdbTransactionInfo(None, None, self._get_transport_timeout_s(transport_timeout_s), read_timeout_s, None)

        # Mark the device as unavailable
        self._available = False

        # Use the IO manager to connect
        self._available, self._maxdata = self._io_manager.connect(self._banner, rsa_keys, auth_timeout_s, auth_callback, adb_info)

        return self._available

    # ======================================================================= #
    #                                                                         #
    #                                 Services                                #
    #                                                                         #
    # ======================================================================= #
    def _service(self, service, command, transport_timeout_s=None, read_timeout_s=constants.DEFAULT_READ_TIMEOUT_S, timeout_s=None, decode=True):
        """Send an ADB command to the device.

        Parameters
        ----------
        service : bytes
            The ADB service to talk to (e.g., ``b'shell'``)
        command : bytes
            The command that will be sent
        transport_timeout_s : float, None
            Timeout in seconds for sending and receiving data, or ``None``; see :meth:`BaseTransport.bulk_read() <adb_shell.transport.base_transport.BaseTransport.bulk_read>`
            and :meth:`BaseTransport.bulk_write() <adb_shell.transport.base_transport.BaseTransport.bulk_write>`
        read_timeout_s : float
            The total time in seconds to wait for a ``b'CLSE'`` or ``b'OKAY'`` command in :meth:`_AdbIOManager.read`
        timeout_s : float, None
            The total time in seconds to wait for the ADB command to finish
        decode : bool
            Whether to decode the output to utf8 before returning

        Returns
        -------
        bytes, str
            The output of the ADB command as a string if ``decode`` is True, otherwise as bytes.

        """
        if decode:
            return b''.join(self._streaming_command(service, command, transport_timeout_s, read_timeout_s, timeout_s)).decode('utf8', _DECODE_ERRORS)
        return b''.join(self._streaming_command(service, command, transport_timeout_s, read_timeout_s, timeout_s))

    def _streaming_service(self, service, command, transport_timeout_s=None, read_timeout_s=constants.DEFAULT_READ_TIMEOUT_S, decode=True):
        """Send an ADB command to the device, yielding each line of output.

        Parameters
        ----------
        service : bytes
            The ADB service to talk to (e.g., ``b'shell'``)
        command : bytes
            The command that will be sent
        transport_timeout_s : float, None
            Timeout in seconds for sending and receiving data, or ``None``; see :meth:`BaseTransport.bulk_read() <adb_shell.transport.base_transport.BaseTransport.bulk_read>`
            and :meth:`BaseTransport.bulk_write() <adb_shell.transport.base_transport.BaseTransport.bulk_write>`
        read_timeout_s : float
            The total time in seconds to wait for a ``b'CLSE'`` or ``b'OKAY'`` command in :meth:`_AdbIOManager.read`
        decode : bool
            Whether to decode the output to utf8 before returning

        Yields
        -------
        bytes, str
            The line-by-line output of the ADB command as a string if ``decode`` is True, otherwise as bytes.

        """
        stream = self._streaming_command(service, command, transport_timeout_s, read_timeout_s, None)
        if decode:
            for line in (stream_line.decode('utf8', _DECODE_ERRORS) for stream_line in stream):
                yield line
        else:
            for line in stream:
                yield line

    def exec_out(self, command, transport_timeout_s=None, read_timeout_s=constants.DEFAULT_READ_TIMEOUT_S, timeout_s=None, decode=True):
        """Send an ADB ``exec-out`` command to the device.

        https://www.linux-magazine.com/Issues/2017/195/Ask-Klaus

        Parameters
        ----------
        command : str
            The exec-out command that will be sent
        transport_timeout_s : float, None
            Timeout in seconds for sending and receiving data, or ``None``; see :meth:`BaseTransport.bulk_read() <adb_shell.transport.base_transport.BaseTransport.bulk_read>`
            and :meth:`BaseTransport.bulk_write() <adb_shell.transport.base_transport.BaseTransport.bulk_write>`
        read_timeout_s : float
            The total time in seconds to wait for a ``b'CLSE'`` or ``b'OKAY'`` command in :meth:`_AdbIOManager.read`
        timeout_s : float, None
            The total time in seconds to wait for the ADB command to finish
        decode : bool
            Whether to decode the output to utf8 before returning

        Returns
        -------
        bytes, str
            The output of the ADB exec-out command as a string if ``decode`` is True, otherwise as bytes.

        """
        if not self.available:
            raise exceptions.AdbConnectionError("ADB command not sent because a connection to the device has not been established.  (Did you call `AdbDevice.connect()`?)")

        return self._service(b'exec', command.encode('utf8'), transport_timeout_s, read_timeout_s, timeout_s, decode)

    def reboot(self, fastboot=False, transport_timeout_s=None, read_timeout_s=constants.DEFAULT_READ_TIMEOUT_S, timeout_s=None):
        """Reboot the device.

        Parameters
        ----------
        fastboot : bool
            Whether to reboot the device into fastboot
        transport_timeout_s : float, None
            Timeout in seconds for sending and receiving data, or ``None``; see :meth:`BaseTransport.bulk_read() <adb_shell.transport.base_transport.BaseTransport.bulk_read>`
            and :meth:`BaseTransport.bulk_write() <adb_shell.transport.base_transport.BaseTransport.bulk_write>`
        read_timeout_s : float
            The total time in seconds to wait for a ``b'CLSE'`` or ``b'OKAY'`` command in :meth:`_AdbIOManager.read`
        timeout_s : float, None
            The total time in seconds to wait for the ADB command to finish

        """
        if not self.available:
            raise exceptions.AdbConnectionError("ADB command not sent because a connection to the device has not been established.  (Did you call `AdbDevice.connect()`?)")

        self._open(b'reboot:bootloader' if fastboot else b'reboot:', transport_timeout_s, read_timeout_s, timeout_s)

    def root(self, transport_timeout_s=None, read_timeout_s=constants.DEFAULT_READ_TIMEOUT_S, timeout_s=None):
        """Gain root access.

        The device must be rooted in order for this to work.

        Parameters
        ----------
        transport_timeout_s : float, None
            Timeout in seconds for sending and receiving data, or ``None``; see :meth:`BaseTransport.bulk_read() <adb_shell.transport.base_transport.BaseTransport.bulk_read>`
            and :meth:`BaseTransport.bulk_write() <adb_shell.transport.base_transport.BaseTransport.bulk_write>`
        read_timeout_s : float
            The total time in seconds to wait for a ``b'CLSE'`` or ``b'OKAY'`` command in :meth:`_AdbIOManager.read`
        timeout_s : float, None
            The total time in seconds to wait for the ADB command to finish

        """
        if not self.available:
            raise exceptions.AdbConnectionError("ADB command not sent because a connection to the device has not been established.  (Did you call `AdbDevice.connect()`?)")

        self._service(b'root', b'', transport_timeout_s, read_timeout_s, timeout_s, False)

    def shell(self, command, transport_timeout_s=None, read_timeout_s=constants.DEFAULT_READ_TIMEOUT_S, timeout_s=None, decode=True):
        """Send an ADB shell command to the device.

        Parameters
        ----------
        command : str
            The shell command that will be sent
        transport_timeout_s : float, None
            Timeout in seconds for sending and receiving data, or ``None``; see :meth:`BaseTransport.bulk_read() <adb_shell.transport.base_transport.BaseTransport.bulk_read>`
            and :meth:`BaseTransport.bulk_write() <adb_shell.transport.base_transport.BaseTransport.bulk_write>`
        read_timeout_s : float
            The total time in seconds to wait for a ``b'CLSE'`` or ``b'OKAY'`` command in :meth:`_AdbIOManager.read`
        timeout_s : float, None
            The total time in seconds to wait for the ADB command to finish
        decode : bool
            Whether to decode the output to utf8 before returning

        Returns
        -------
        bytes, str
            The output of the ADB shell command as a string if ``decode`` is True, otherwise as bytes.

        """
        if not self.available:
            raise exceptions.AdbConnectionError("ADB command not sent because a connection to the device has not been established.  (Did you call `AdbDevice.connect()`?)")

        return self._service(b'shell', command.encode('utf8'), transport_timeout_s, read_timeout_s, timeout_s, decode)

    def streaming_shell(self, command, transport_timeout_s=None, read_timeout_s=constants.DEFAULT_READ_TIMEOUT_S, decode=True):
        """Send an ADB shell command to the device, yielding each line of output.

        Parameters
        ----------
        command : str
            The shell command that will be sent
        transport_timeout_s : float, None
            Timeout in seconds for sending and receiving data, or ``None``; see :meth:`BaseTransport.bulk_read() <adb_shell.transport.base_transport.BaseTransport.bulk_read>`
            and :meth:`BaseTransport.bulk_write() <adb_shell.transport.base_transport.BaseTransport.bulk_write>`
        read_timeout_s : float
            The total time in seconds to wait for a ``b'CLSE'`` or ``b'OKAY'`` command in :meth:`_AdbIOManager.read`
        decode : bool
            Whether to decode the output to utf8 before returning

        Yields
        -------
        bytes, str
            The line-by-line output of the ADB shell command as a string if ``decode`` is True, otherwise as bytes.

        """
        if not self.available:
            raise exceptions.AdbConnectionError("ADB command not sent because a connection to the device has not been established.  (Did you call `AdbDevice.connect()`?)")

        for line in self._streaming_service(b'shell', command.encode('utf8'), transport_timeout_s, read_timeout_s, decode):
            yield line

    # ======================================================================= #
    #                                                                         #
    #                                 FileSync                                #
    #                                                                         #
    # ======================================================================= #
    def list(self, device_path, transport_timeout_s=None, read_timeout_s=constants.DEFAULT_READ_TIMEOUT_S):
        """Return a directory listing of the given path.

        Parameters
        ----------
        device_path : str
            Directory to list.
        transport_timeout_s : float, None
            Expected timeout for any part of the pull.
        read_timeout_s : float
            The total time in seconds to wait for a ``b'CLSE'`` or ``b'OKAY'`` command in :meth:`_AdbIOManager.read`

        Returns
        -------
        files : list[DeviceFile]
            Filename, mode, size, and mtime info for the files in the directory

        """
        if not device_path:
            raise exceptions.DevicePathInvalidError("Cannot list an empty device path")
        if not self.available:
            raise exceptions.AdbConnectionError("ADB command not sent because a connection to the device has not been established.  (Did you call `AdbDevice.connect()`?)")

        adb_info = self._open(b"sync:", transport_timeout_s, read_timeout_s, None)
        filesync_info = _FileSyncTransactionInfo(constants.FILESYNC_LIST_FORMAT, maxdata=self._maxdata)

        self._filesync_send(constants.LIST, adb_info, filesync_info, data=device_path)
        files = []

        for cmd_id, header, filename in self._filesync_read_until([constants.DENT], [constants.DONE], adb_info, filesync_info):
            if cmd_id == constants.DONE:
                break

            mode, size, mtime = header
            files.append(DeviceFile(filename, mode, size, mtime))

        self._clse(adb_info)

        return files

    def pull(self, device_path, local_path, progress_callback=None, transport_timeout_s=None, read_timeout_s=constants.DEFAULT_READ_TIMEOUT_S):
        """Pull a file from the device.

        Parameters
        ----------
        device_path : str
            The file on the device that will be pulled
        local_path : str, BytesIO
            The path or BytesIO stream where the file will be downloaded
        progress_callback : function, None
            Callback method that accepts ``device_path``, ``bytes_written``, and ``total_bytes``
        transport_timeout_s : float, None
            Expected timeout for any part of the pull.
        read_timeout_s : float
            The total time in seconds to wait for a ``b'CLSE'`` or ``b'OKAY'`` command in :meth:`_AdbIOManager.read`

        """
        if not device_path:
            raise exceptions.DevicePathInvalidError("Cannot pull from an empty device path")
        if not self.available:
            raise exceptions.AdbConnectionError("ADB command not sent because a connection to the device has not been established.  (Did you call `AdbDevice.connect()`?)")

        opener = _open_bytesio if isinstance(local_path, BytesIO) else open
        with opener(local_path, 'wb') as stream:
            adb_info = self._open(b'sync:', transport_timeout_s, read_timeout_s, None)
            filesync_info = _FileSyncTransactionInfo(constants.FILESYNC_PULL_FORMAT, maxdata=self._maxdata)

            try:
                self._pull(device_path, stream, progress_callback, adb_info, filesync_info)
            finally:
                self._clse(adb_info)

    def _pull(self, device_path, stream, progress_callback, adb_info, filesync_info):
        """Pull a file from the device into the file-like ``local_path``.

        Parameters
        ----------
        device_path : str
            The file on the device that will be pulled
        stream : _io.BytesIO
            File-like object for writing to
        progress_callback : function, None
            Callback method that accepts ``device_path``, ``bytes_written``, and ``total_bytes``
        adb_info : _AdbTransactionInfo
            Info and settings for this ADB transaction
        filesync_info : _FileSyncTransactionInfo
            Data and storage for this FileSync transaction

        """
        if progress_callback:
            total_bytes = self.stat(device_path)[1]

        self._filesync_send(constants.RECV, adb_info, filesync_info, data=device_path)
        for cmd_id, _, data in self._filesync_read_until([constants.DATA], [constants.DONE], adb_info, filesync_info):
            if cmd_id == constants.DONE:
                break

            stream.write(data)
            if progress_callback:
                try:
                    progress_callback(device_path, len(data), total_bytes)
                except:  # noqa pylint: disable=bare-except
                    pass

    def push(self, local_path, device_path, st_mode=constants.DEFAULT_PUSH_MODE, mtime=0, progress_callback=None, transport_timeout_s=None, read_timeout_s=constants.DEFAULT_READ_TIMEOUT_S):
        """Push a file or directory to the device.

        Parameters
        ----------
        local_path : str, BytesIO
            A filename, directory, or BytesIO stream to push to the device
        device_path : str
            Destination on the device to write to.
        st_mode : int
            Stat mode for ``local_path``
        mtime : int
            Modification time to set on the file.
        progress_callback : function, None
            Callback method that accepts ``device_path``, ``bytes_written``, and ``total_bytes``
        transport_timeout_s : float, None
            Expected timeout for any part of the push.
        read_timeout_s : float
            The total time in seconds to wait for a ``b'CLSE'`` or ``b'OKAY'`` command in :meth:`_AdbIOManager.read`

        """
        if not device_path:
            raise exceptions.DevicePathInvalidError("Cannot push to an empty device path")
        if not self.available:
            raise exceptions.AdbConnectionError("ADB command not sent because a connection to the device has not been established.  (Did you call `AdbDevice.connect()`?)")

        local_path_is_dir, local_paths, device_paths = get_files_to_push(local_path, device_path)

        if local_path_is_dir:
            self.shell("mkdir " + device_path, transport_timeout_s, read_timeout_s)

        for _local_path, _device_path in zip(local_paths, device_paths):
            opener = _open_bytesio if isinstance(local_path, BytesIO) else open
            with opener(_local_path, 'rb') as stream:
                adb_info = self._open(b'sync:', transport_timeout_s, read_timeout_s, None)
                filesync_info = _FileSyncTransactionInfo(constants.FILESYNC_PUSH_FORMAT, maxdata=self._maxdata)

                self._push(stream, _device_path, st_mode, mtime, progress_callback, adb_info, filesync_info)

            self._clse(adb_info)

    def _push(self, stream, device_path, st_mode, mtime, progress_callback, adb_info, filesync_info):
        """Push a file-like object to the device.

        Parameters
        ----------
        stream : _io.BytesIO
            File-like object for reading from
        device_path : str
            Destination on the device to write to
        st_mode : int
            Stat mode for the file
        mtime : int
            Modification time
        progress_callback : function, None
            Callback method that accepts ``device_path``, ``bytes_written``, and ``total_bytes``
        adb_info : _AdbTransactionInfo
            Info and settings for this ADB transaction

        Raises
        ------
        PushFailedError
            Raised on push failure.

        """
        fileinfo = ('{},{}'.format(device_path, int(st_mode))).encode('utf-8')

        self._filesync_send(constants.SEND, adb_info, filesync_info, data=fileinfo)

        if progress_callback:
            total_bytes = os.fstat(stream.fileno()).st_size

        while True:
            data = stream.read(self.max_chunk_size)
            if data:
                self._filesync_send(constants.DATA, adb_info, filesync_info, data=data)

                if progress_callback:
                    try:
                        progress_callback(device_path, len(data), total_bytes)
                    except:  # noqa pylint: disable=bare-except
                        pass
            else:
                break

        if mtime == 0:
            mtime = int(time.time())

        # DONE doesn't send data, but it hides the last bit of data in the size field.
        self._filesync_send(constants.DONE, adb_info, filesync_info, size=mtime)
        for cmd_id, _, data in self._filesync_read_until([], [constants.OKAY, constants.FAIL], adb_info, filesync_info):
            if cmd_id == constants.OKAY:
                return

            raise exceptions.PushFailedError(data)

    def stat(self, device_path, transport_timeout_s=None, read_timeout_s=constants.DEFAULT_READ_TIMEOUT_S):
        """Get a file's ``stat()`` information.

        Parameters
        ----------
        device_path : str
            The file on the device for which we will get information.
        transport_timeout_s : float, None
            Expected timeout for any part of the pull.
        read_timeout_s : float
            The total time in seconds to wait for a ``b'CLSE'`` or ``b'OKAY'`` command in :meth:`_AdbIOManager.read`

        Returns
        -------
        mode : int
            The octal permissions for the file
        size : int
            The size of the file
        mtime : int
            The last modified time for the file

        """
        if not device_path:
            raise exceptions.DevicePathInvalidError("Cannot stat an empty device path")
        if not self.available:
            raise exceptions.AdbConnectionError("ADB command not sent because a connection to the device has not been established.  (Did you call `AdbDevice.connect()`?)")

        adb_info = self._open(b'sync:', transport_timeout_s, read_timeout_s, None)
        filesync_info = _FileSyncTransactionInfo(constants.FILESYNC_STAT_FORMAT, maxdata=self._maxdata)

        self._filesync_send(constants.STAT, adb_info, filesync_info, data=device_path)
        _, (mode, size, mtime), _ = self._filesync_read([constants.STAT], adb_info, filesync_info)
        self._clse(adb_info)

        return mode, size, mtime

    # ======================================================================= #
    #                                                                         #
    #                       Hidden Methods: send packets                      #
    #                                                                         #
    # ======================================================================= #
    def _clse(self, adb_info):
        """Send a ``b'CLSE'`` message and then read a ``b'CLSE'`` message.

        .. warning::

           This is not to be confused with the :meth:`AdbDevice.close` method!


        Parameters
        ----------
        adb_info : _AdbTransactionInfo
            Info and settings for this ADB transaction

        """
        msg = AdbMessage(constants.CLSE, adb_info.local_id, adb_info.remote_id)
        self._io_manager.send(msg, adb_info)
        self._read_until([constants.CLSE], adb_info)

    def _okay(self, adb_info):
        """Send an ``b'OKAY'`` mesage.

        Parameters
        ----------
        adb_info : _AdbTransactionInfo
            Info and settings for this ADB transaction

        """
        msg = AdbMessage(constants.OKAY, adb_info.local_id, adb_info.remote_id)
        self._io_manager.send(msg, adb_info)

    # ======================================================================= #
    #                                                                         #
    #                              Hidden Methods                             #
    #                                                                         #
    # ======================================================================= #
    def _open(self, destination, transport_timeout_s, read_timeout_s, timeout_s):
        """Opens a new connection to the device via an ``b'OPEN'`` message.

        1. :meth:`~_AdbIOManager.send` an ``b'OPEN'`` command to the device that specifies the ``local_id``
        2. :meth:`~_AdbIOManager.read` the response from the device and fill in the ``adb_info.remote_id`` attribute


        Parameters
        ----------
        destination : bytes
            ``b'SERVICE:COMMAND'``
        transport_timeout_s : float, None
            Timeout in seconds for sending and receiving data, or ``None``; see :meth:`BaseTransport.bulk_read() <adb_shell.transport.base_transport.BaseTransport.bulk_read>`
            and :meth:`BaseTransport.bulk_write() <adb_shell.transport.base_transport.BaseTransport.bulk_write>`
        read_timeout_s : float
            The total time in seconds to wait for a ``b'CLSE'`` or ``b'OKAY'`` command in :meth:`_AdbIOManager.read`
        timeout_s : float, None
            The total time in seconds to wait for the ADB command to finish

        Returns
        -------
        adb_info : _AdbTransactionInfo
            Info and settings for this ADB transaction

        """
        with self._local_id_lock:
            self._local_id += 1
            if self._local_id == 2**32:
                self._local_id = 1

            adb_info = _AdbTransactionInfo(self._local_id, None, self._get_transport_timeout_s(transport_timeout_s), read_timeout_s, timeout_s)

        msg = AdbMessage(constants.OPEN, adb_info.local_id, 0, destination + b'\0')
        self._io_manager.send(msg, adb_info)
        _, adb_info.remote_id, _, _ = self._io_manager.read([constants.OKAY], adb_info)

        return adb_info

    def _read_until(self, expected_cmds, adb_info):
        """Read a packet, acknowledging any write packets.

        1. Read data via :meth:`_AdbIOManager.read`
        2. If a ``b'WRTE'`` packet is received, send an ``b'OKAY'`` packet via :meth:`AdbDevice._okay`
        3. Return the ``cmd`` and ``data`` that were read by :meth:`_AdbIOManager.read`


        Parameters
        ----------
        expected_cmds : list[bytes]
            :meth:`_AdbIOManager.read` will look for a packet whose command is in ``expected_cmds``
        adb_info : _AdbTransactionInfo
            Info and settings for this ADB transaction

        Returns
        -------
        cmd : bytes
            The command that was received by :meth:`_AdbIOManager.read`, which is in :const:`adb_shell.constants.WIRE_TO_ID` and must be in ``expected_cmds``
        data : bytes
            The data that was received by :meth:`_AdbIOManager.read`

        """
        cmd, _, _, data = self._io_manager.read(expected_cmds, adb_info, allow_zeros=True)

        # Acknowledge write packets
        if cmd == constants.WRTE:
            self._okay(adb_info)

        return cmd, data

    def _read_until_close(self, adb_info):
        """Yield packets until a ``b'CLSE'`` packet is received.

        1. Read the ``cmd`` and ``data`` fields from a ``b'CLSE'`` or ``b'WRTE'`` packet via :meth:`AdbDevice._read_until`
        2. If ``cmd`` is ``b'CLSE'``, then send a ``b'CLSE'`` message and stop
        3. Yield ``data`` and repeat


        Parameters
        ----------
        adb_info : _AdbTransactionInfo
            Info and settings for this ADB transaction

        Yields
        ------
        data : bytes
            The data that was read by :meth:`AdbDevice._read_until`

        """
        start = time.time()

        while True:
            cmd, data = self._read_until([constants.CLSE, constants.WRTE], adb_info)

            if cmd == constants.CLSE:
                msg = AdbMessage(constants.CLSE, adb_info.local_id, adb_info.remote_id)
                self._io_manager.send(msg, adb_info)
                break

            yield data

            # Make sure the ADB command has not timed out
            if adb_info.timeout_s is not None and time.time() - start > adb_info.timeout_s:
                raise exceptions.AdbTimeoutError("The command did not complete within {} seconds".format(adb_info.timeout_s))

    def _streaming_command(self, service, command, transport_timeout_s, read_timeout_s, timeout_s):
        """One complete set of packets for a single command.

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
        transport_timeout_s : float, None
            Timeout in seconds for sending and receiving data, or ``None``; see :meth:`BaseTransport.bulk_read() <adb_shell.transport.base_transport.BaseTransport.bulk_read>`
            and :meth:`BaseTransport.bulk_write() <adb_shell.transport.base_transport.BaseTransport.bulk_write>`
        read_timeout_s : float
            The total time in seconds to wait for a ``b'CLSE'`` or ``b'OKAY'`` command in :meth:`_AdbIOManager.read`
        timeout_s : float, None
            The total time in seconds to wait for the ADB command to finish

        Yields
        ------
        bytes
            The responses from the service.

        """
        adb_info = self._open(b'%s:%s' % (service, command), transport_timeout_s, read_timeout_s, timeout_s)

        for data in self._read_until_close(adb_info):
            yield data

    # ======================================================================= #
    #                                                                         #
    #                         FileSync Hidden Methods                         #
    #                                                                         #
    # ======================================================================= #
    def _filesync_flush(self, adb_info, filesync_info):
        """Write the data in the buffer up to ``filesync_info.send_idx``, then set ``filesync_info.send_idx`` to 0.

        Parameters
        ----------
        adb_info : _AdbTransactionInfo
            Info and settings for this ADB transaction
        filesync_info : _FileSyncTransactionInfo
            Data and storage for this FileSync transaction

        """
        # Send the buffer
        msg = AdbMessage(constants.WRTE, adb_info.local_id, adb_info.remote_id, filesync_info.send_buffer[:filesync_info.send_idx])
        self._io_manager.send(msg, adb_info)

        # Expect an 'OKAY' in response
        self._read_until([constants.OKAY], adb_info)

        # Reset the send index
        filesync_info.send_idx = 0

    def _filesync_read(self, expected_ids, adb_info, filesync_info):
        """Read ADB messages and return FileSync packets.

        Parameters
        ----------
        expected_ids : tuple[bytes]
            If the received header ID is not in ``expected_ids``, an exception will be raised
        adb_info : _AdbTransactionInfo
            Info and settings for this ADB transaction
        filesync_info : _FileSyncTransactionInfo
            Data and storage for this FileSync transaction

        Returns
        -------
        command_id : bytes
            The received header ID
        tuple
            The contents of the header
        data : bytearray, None
            The received data, or ``None`` if the command ID is :const:`adb_shell.constants.STAT`

        Raises
        ------
        adb_shell.exceptions.AdbCommandFailureException
            Command failed
        adb_shell.exceptions.InvalidResponseError
            Received response was not in ``expected_ids``

        """
        if filesync_info.send_idx:
            self._filesync_flush(adb_info, filesync_info)

        # Read one filesync packet off the recv buffer.
        header_data = self._filesync_read_buffered(filesync_info.recv_message_size, adb_info, filesync_info)
        header = struct.unpack(filesync_info.recv_message_format, header_data)

        # Header is (ID, ...).
        command_id = constants.FILESYNC_WIRE_TO_ID[header[0]]

        # Whether there is data to read
        read_data = command_id != constants.STAT

        if read_data:
            # Header is (ID, ..., size) --> read the data
            data = self._filesync_read_buffered(header[-1], adb_info, filesync_info)
        else:
            # No data to be read
            data = bytearray()

        if command_id not in expected_ids:
            if command_id == constants.FAIL:
                reason = data.decode('utf-8', errors=_DECODE_ERRORS)

                raise exceptions.AdbCommandFailureException('Command failed: {}'.format(reason))

            raise exceptions.InvalidResponseError('Expected one of %s, got %s' % (expected_ids, command_id))

        if not read_data:
            return command_id, header[1:], None

        return command_id, header[1:-1], data

    def _filesync_read_buffered(self, size, adb_info, filesync_info):
        """Read ``size`` bytes of data from ``self.recv_buffer``.

        Parameters
        ----------
        size : int
            The amount of data to read
        adb_info : _AdbTransactionInfo
            Info and settings for this ADB transaction
        filesync_info : _FileSyncTransactionInfo
            Data and storage for this FileSync transaction

        Returns
        -------
        result : bytearray
            The read data

        """
        # Ensure recv buffer has enough data.
        while len(filesync_info.recv_buffer) < size:
            _, data = self._read_until([constants.WRTE], adb_info)
            filesync_info.recv_buffer += data

        result = filesync_info.recv_buffer[:size]
        filesync_info.recv_buffer = filesync_info.recv_buffer[size:]
        return result

    def _filesync_read_until(self, expected_ids, finish_ids, adb_info, filesync_info):
        """Useful wrapper around :meth:`AdbDevice._filesync_read`.

        Parameters
        ----------
        expected_ids : tuple[bytes]
            If the received header ID is not in ``expected_ids``, an exception will be raised
        finish_ids : tuple[bytes]
            We will read until we find a header ID that is in ``finish_ids``
        adb_info : _AdbTransactionInfo
            Info and settings for this ADB transaction
        filesync_info : _FileSyncTransactionInfo
            Data and storage for this FileSync transaction

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
            cmd_id, header, data = self._filesync_read(expected_ids + finish_ids, adb_info, filesync_info)
            yield cmd_id, header, data

            # These lines are not reachable because whenever this method is called and `cmd_id` is in `finish_ids`, the code
            # either breaks (`list` and `_pull`), returns (`_push`), or raises an exception (`_push`)
            if cmd_id in finish_ids:  # pragma: no cover
                break

    def _filesync_send(self, command_id, adb_info, filesync_info, data=b'', size=None):
        """Send/buffer FileSync packets.

        Packets are buffered and only flushed when this connection is read from. All
        messages have a response from the device, so this will always get flushed.

        Parameters
        ----------
        command_id : bytes
            Command to send.
        adb_info : _AdbTransactionInfo
            Info and settings for this ADB transaction
        filesync_info : _FileSyncTransactionInfo
            Data and storage for this FileSync transaction
        data : str, bytes
            Optional data to send, must set data or size.
        size : int, None
            Optionally override size from len(data).

        """
        if not isinstance(data, bytes):
            data = data.encode('utf8')
        if size is None:
            size = len(data)

        if not filesync_info.can_add_to_send_buffer(len(data)):
            self._filesync_flush(adb_info, filesync_info)

        buf = struct.pack(b'<2I', constants.FILESYNC_ID_TO_WIRE[command_id], size) + data
        filesync_info.send_buffer[filesync_info.send_idx:filesync_info.send_idx + len(buf)] = buf
        filesync_info.send_idx += len(buf)


class AdbDeviceTcp(AdbDevice):
    """A class with methods for connecting to a device via TCP and executing ADB commands.

    Parameters
    ----------
    host : str
        The address of the device; may be an IP address or a host name
    port : int
        The device port to which we are connecting (default is 5555)
    default_transport_timeout_s : float, None
        Default timeout in seconds for TCP packets, or ``None``
    banner : str, bytes, None
        The hostname of the machine where the Python interpreter is currently running; if
        it is not provided, it will be determined via ``socket.gethostname()``

    Attributes
    ----------
    _available : bool
        Whether an ADB connection to the device has been established
    _banner : bytearray, bytes
        The hostname of the machine where the Python interpreter is currently running
    _default_transport_timeout_s : float, None
        Default timeout in seconds for TCP packets, or ``None``
    _local_id : int
        The local ID that is used for ADB transactions; the value is incremented each time and is always in the range ``[1, 2^32)``
    _maxdata : int
        Maximum amount of data in an ADB packet
    _transport : TcpTransport
        The transport that is used to connect to the device

    """

    def __init__(self, host, port=5555, default_transport_timeout_s=None, banner=None):
        transport = TcpTransport(host, port)
        super(AdbDeviceTcp, self).__init__(transport, default_transport_timeout_s, banner)


class AdbDeviceUsb(AdbDevice):
    """A class with methods for connecting to a device via USB and executing ADB commands.

    Parameters
    ----------
    serial : str, None
        The USB device serial ID
    port_path : TODO, None
        TODO
    default_transport_timeout_s : float, None
        Default timeout in seconds for USB packets, or ``None``
    banner : str, bytes, None
        The hostname of the machine where the Python interpreter is currently running; if
        it is not provided, it will be determined via ``socket.gethostname()``

    Raises
    ------
    adb_shell.exceptions.InvalidTransportError
        Raised if package was not installed with the "usb" extras option (``pip install adb-shell[usb]``)

    Attributes
    ----------
    _available : bool
        Whether an ADB connection to the device has been established
    _banner : bytearray, bytes
        The hostname of the machine where the Python interpreter is currently running
    _default_transport_timeout_s : float, None
        Default timeout in seconds for USB packets, or ``None``
    _local_id : int
        The local ID that is used for ADB transactions; the value is incremented each time and is always in the range ``[1, 2^32)``
    _maxdata : int
        Maximum amount of data in an ADB packet
    _transport : UsbTransport
        The transport that is used to connect to the device

    """

    def __init__(self, serial=None, port_path=None, default_transport_timeout_s=None, banner=None):
        if UsbTransport is None:
            raise exceptions.InvalidTransportError("To enable USB support you must install this package via `pip install adb-shell[usb]`")

        transport = UsbTransport.find_adb(serial, port_path, default_transport_timeout_s)
        super(AdbDeviceUsb, self).__init__(transport, default_transport_timeout_s, banner)
