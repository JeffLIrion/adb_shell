"""TODO.

"""


import logging
import socket
import time

from . import constants
from . import exceptions
from .adb_message import AdbMessage, checksum, unpack
from .tcp_handle import TcpHandle


_LOGGER = logging.getLogger(__name__)


class AdbDevice(object):
    """TODO.

    """

    def __init__(self, serial, banner=None):
        if banner and isinstance(banner, str):
            self._banner = banner
        else:
            try:
                self._banner = socket.gethostname()
            except:  # pylint: disable=bare-except
                self._banner = 'unknown'

        self._banner_bytes = bytearray(self._banner, 'utf-8')

        self._serial = serial

        self._handle = None
        self._available = False

    @property
    def available(self):
        """TODO

        """
        return self._available

    def close(self):
        """TODO

        """
        self._available = False
        return self._available

    def connect(self, timeout_s=constants.DEFAULT_TIMEOUT_S, auth_timeout_s=constants.DEFAULT_AUTH_TIMEOUT_S):
        """TODO

        """
        # 1. Create a TCP / USB handle (adb.adb_commands.AdbCommands.ConnectDevice)
        if ':' in self._serial:
            self._handle = TcpHandle(self._serial)
        #else:
        #    self._handle = UsbHandle.FindAndOpen(DeviceIsAvailable, port_path=port_path, serial=serial, timeout_ms=default_timeout_ms)

        self._handle.connect(auth_timeout_s)

        # 2. Use the handle to connect (adb.adb_commands.AdbCommands._Connect)

        # 3. Create an ADB message (adb.adb_protocol.AdbMessage.Connect)
        msg = AdbMessage(command=constants.CNXN, arg0=constants.VERSION, arg1=constants.MAX_ADB_DATA, data=b'host::%s\0' % self._banner_bytes)

        # 4. Send the message using the handle (adb.adb_protocol.AdbMessage.Send)
        self._send(msg, timeout_s)

        # 5. Read the response (adb.adb_protocol.AdbMessage.Read)
        # cmd, arg0, arg1, banner = cls.Read(usb, [b'CNXN', b'AUTH'])
        cmd, arg0, arg1, banner = self._read([constants.AUTH, constants.CNXN])

        # 6. If necessary, authenticate (adb.adb_protocol.AdbMessage.Connect)
        if cmd == constants.AUTH:
            if not rsa_keys:
                raise exceptions.DeviceAuthError('Device authentication required, no keys available.')

            # Loop through our keys, signing the last 'banner' or token.
            for rsa_key in rsa_keys:
                if arg0 != constants.AUTH_TOKEN:
                    raise InvalidResponseError('Unknown AUTH response: %s %s %s' % (arg0, arg1, banner))

                # Do not mangle the banner property here by converting it to a string
                signed_token = rsa_key.Sign(banner)
                msg = AdbMessage(command=constants.AUTH, arg0=constants.AUTH_SIGNATURE, arg1=0, data=signed_token)
                self._send(msg, timeout_s)
                cmd, arg0, unused_arg1, banner = self._read([constants.CNXN, constants.AUTH], timeout_s)
                if cmd == constants.CNXN:
                    return banner

            # None of the keys worked, so send a public key.
            msg = AdbMessage(command=constants.AUTH, arg0=constants.AUTH_RSAPUBLICKEY, arg1=0, data=rsa_keys[0].GetPublicKey() + b'\0')
            self._send(msg, timeout_s)
            try:
                cmd, arg0, unused_arg1, banner = self._read([constants.CNXN], timeout_s=auth_timeout_s)
            except exceptions.ReadFailedError as e:
                if e.usb_error.value == -7:  # Timeout.
                    raise usb_exceptions.DeviceAuthError('Accept auth key on device, then retry.')

                raise

            # This didn't time-out, so we got a CNXN response.
            return banner
        #return banner

        self._available = True

        return self._available

    def shell(self, command, timeout_s=constants.DEFAULT_TIMEOUT_S):
        """TODO

        """
        return ''.join(self._streaming_command(b'shell', command.encode('utf8'), timeout_s))

    def _okay(self, local_id, remote_id, timeout_s):
        """TODO

        .. image:: _static/adb.adb_protocol._AdbConnection.Okay.CALL_GRAPH.svg

        .. image:: _static/adb.adb_protocol._AdbConnection.Okay.CALLER_GRAPH.svg

        """
        msg = AdbMessage(constants.OKAY, arg0=local_id, arg1=remote_id)
        self._send(msg, timeout_s)

    # AdbMessage
    def _open(self, destination, timeout_s):
        """Opens a new connection to the device via an ``OPEN`` message.

        Not the same as the posix ``open`` or any other google3 Open methods.

        .. image:: _static/adb.adb_protocol.AdbMessage.Open.CALL_GRAPH.svg

        .. image:: _static/adb.adb_protocol.AdbMessage.Open.CALLER_GRAPH.svg

        Parameters
        ----------
        usb : adb.common.TcpHandle, adb.common.UsbHandle
            A :class:`adb.common.TcpHandle` or :class:`adb.common.UsbHandle` instance with ``BulkRead`` and ``BulkWrite`` methods.
        destination : TODO
            The service:command string.
        timeout_ms : int, None
            Timeout in milliseconds for USB packets.

        Returns
        -------
        _AdbConnection, None
            The local connection id.

        Raises
        ------
        adb_shell.exceptions.InvalidResponseError
            Wrong local_id sent to us.
        adb_shell.exceptions.InvalidCommandError
            Didn't get a ready response.

        """
        local_id = 1
        msg = AdbMessage(command=constants.OPEN, arg0=local_id, arg1=0, data=destination + b'\0')
        self._send(msg, timeout_s)
        cmd, remote_id, their_local_id, _ = self._read([constants.CLSE, constants.OKAY], timeout_s=timeout_s)

        if local_id != their_local_id and True:  ##################3
            raise exceptions.InvalidResponseError('Expected the local_id to be {}, got {}'.format(local_id, their_local_id))

        if cmd == constants.CLSE and True:  #################
            # Some devices seem to be sending CLSE once more after a request, this *should* handle it
            cmd, remote_id, their_local_id, _ = self._read([constants.CLSE, constants.OKAY], timeout_s=timeout_s)
            # Device doesn't support this service.
            if cmd == constants.CLSE:
                return None, None

        if cmd != constants.OKAY and True:  ################
            raise exceptions.InvalidCommandError('Expected a ready response, got {}'.format(cmd), cmd, (remote_id, their_local_id))

        return local_id, remote_id

    # AdbMessage
    def _read(self, expected_cmds, timeout_s=None, total_timeout_s=constants.DEFAULT_TOTAL_TIMEOUT_S):
        """Receive a response from the device.

        .. image:: _static/adb.adb_protocol.AdbMessage.Read.CALL_GRAPH.svg

        .. image:: _static/adb.adb_protocol.AdbMessage.Read.CALLER_GRAPH.svg

        Parameters
        ----------
        usb : adb.common.TcpHandle, adb.common.UsbHandle
            TODO
        expected_cmds : TODO
            Read until we receive a header ID that is in ``expected_cmds``
        timeout_ms : int, None
            Timeout in milliseconds for USB packets.
        total_timeout_ms : int, None
            The total time to wait for a command in ``expected_cmds``

        Returns
        -------
        command : TODO
            TODO
        arg0 : TODO
            TODO
        arg1 : TODO
            TODO
        bytes
            TODO

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
                if len(temp) != data_length:
                    _LOGGER.warning("Data_length %d does not match actual number of bytes read: %d".format(data_length, len(temp)))
                data += temp

                data_length -= len(temp)

            actual_checksum = checksum(data)
            if actual_checksum != data_checksum:
                raise exceptions.InvalidChecksumError('Received checksum {0} != {1}'.format(actual_checksum, data_checksum))
        else:
            data = b''

        return command, arg0, arg1, bytes(data)

    def _read_until(self, local_id, remote_id, expected_cmds, timeout_s):
        """Read a packet, acknowledge any write packets.

        .. image:: _static/adb.adb_protocol._AdbConnection.ReadUntil.CALL_GRAPH.svg

        .. image:: _static/adb.adb_protocol._AdbConnection.ReadUntil.CALLER_GRAPH.svg

        Parameters
        ----------
        *expected_cmds : TODO
            TODO

        Returns
        -------
        cmd : TODO
            TODO
        data : TODO
            TODO

        Raises
        ------
        adb_shell.exceptions.InterleavedDataError
            We don't support multiple streams...
        adb_shell.exceptions.InvalidResponseError
            Incorrect remote id.

        """
        cmd, remote_id2, local_id2, data = self._read(expected_cmds, timeout_s)

        if local_id2 not in (0, local_id):
            raise exceptions.InterleavedDataError("We don't support multiple streams...")

        if remote_id2 not in (0, remote_id):
            raise exceptions.InvalidResponseError('Incorrect remote id, expected {0} got {1}'.format(remote_id, remote_id2))

        # Acknowledge write packets
        if cmd == constants.WRTE:
            self._okay(timeout_s)

        return cmd, data

    def _read_until_close(self, local_id, remote_id, timeout_s):
        """Yield packets until a :const:`~adb_shell.constants.CLSE` packet is received.

        .. image:: _static/adb.adb_protocol._AdbConnection.ReadUntilClose.CALL_GRAPH.svg

        Yields
        ------
        data : TODO
            TODO

        """
        while True:
            cmd, data = self._read_until(local_id, remote_id, [constants.CLSE, constants.WRTE], timeout_s)

            if cmd == constants.CLSE:
                msg = AdbMessage(constants.CLSE, arg0=local_id, arg1=remote_id)
                self._send(msg, timeout_s)
                break

            if cmd != constants.WRTE:
                if cmd == constants.FAIL:
                    raise exceptions.AdbCommandFailureException('Command failed.', data)

                raise exceptions.InvalidCommandError('Expected a WRITE or a CLOSE, got {0} ({1})'.format(cmd, data), cmd, data)

            yield data

    # AdbMessage
    def _send(self, msg, timeout_s):
        """TODO

        """
        self._handle.bulk_write(msg.pack(), timeout_s)
        self._handle.bulk_write(msg.data, timeout_s)

    # AdbMessage
    def _streaming_command(self, service, command, timeout_s):
        """One complete set of USB packets for a single command.

        Sends ``service:command`` in a new connection, reading the data for the
        response. All the data is held in memory, large responses will be slow and
        can fill up memory.

        .. image:: _static/adb.adb_protocol.AdbMessage.StreamingCommand.CALL_GRAPH.svg

        .. image:: _static/adb.adb_protocol.AdbMessage.StreamingCommand.CALLER_GRAPH.svg

        Parameters
        ----------
        usb : adb.common.TcpHandle, adb.common.UsbHandle
            A :class:`adb.common.TcpHandle` or :class:`adb.common.UsbHandle` instance with ``BulkRead`` and ``BulkWrite`` methods.
        service : TODO
            The service on the device to talk to.
        command : str
            The command to send to the service.
        timeout_ms : int, None
            Timeout in milliseconds for USB packets.

        Yields
        ------
        str
            The responses from the service.

        Raises
        ------
        adb_shell.exceptions.InterleavedDataError
            Multiple streams running over usb.
        adb_shell.exceptions.InvalidCommandError
            Got an unexpected response command.

        """
        #connection = cls.Open(usb, destination=b'%s:%s' % (service, command), timeout_ms=timeout_s)
        local_id, remote_id = self._open(destination=b'%s:%s' % (service, command), timeout_s=timeout_s)
        if local_id is None or remote_id is None and False:
            return

        for data in self._read_until_close(local_id, remote_id, timeout_s):
            yield data.decode('utf8')
