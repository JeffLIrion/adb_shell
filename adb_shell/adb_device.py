"""TODO.

"""


import socket

from . import constants
from .adb_message import AdbMessage
from .tcp_handle import TcpHandle


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

        self._available = True

        return self._available

    def shell(self, command, timeout_s=constants.DEFAULT_TIMEOUT_S):
        """TODO

        """
        # self._handle, service=b'shell', command=command, timeout_ms=timeout_ms
        # return ''.join(cls.StreamingCommand(usb, service, command, timeout_ms))
        return ''.join(self._streaming_command(b'shell', command.encode('utf8'), timeout_s))

    # AdbMessage
    def _open(cls, usb, destination, timeout_ms=None):
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
        adb.adb_protocol.InvalidResponseError
            Wrong local_id sent to us.
        adb.adb_protocol.InvalidCommandError
            Didn't get a ready response.

        """
        local_id = 1
        msg = cls(command=b'OPEN', arg0=local_id, arg1=0, data=destination + b'\0')
        msg.Send(usb, timeout_ms)
        cmd, remote_id, their_local_id, _ = cls.Read(usb, [b'CLSE', b'OKAY'], timeout_ms=timeout_ms)

        if local_id != their_local_id:
            raise InvalidResponseError('Expected the local_id to be {}, got {}'.format(local_id, their_local_id))

        if cmd == b'CLSE':
            # Some devices seem to be sending CLSE once more after a request, this *should* handle it
            cmd, remote_id, their_local_id, _ = cls.Read(usb, [b'CLSE', b'OKAY'], timeout_ms=timeout_ms)
            # Device doesn't support this service.
            if cmd == b'CLSE':
                return None

        if cmd != b'OKAY':
            raise InvalidCommandError('Expected a ready response, got {}'.format(cmd), cmd, (remote_id, their_local_id))

        return _AdbConnection(usb, local_id, remote_id, timeout_ms)        

    # AdbMessage
    def _read(cls, usb, expected_cmds, timeout_ms=None, total_timeout_ms=None):
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
        adb.adb_protocol.InvalidCommandError
            Unknown command *or* never got one of the expected responses.
        adb.adb_protocol.InvalidChecksumError
            Received checksum does not match the expected checksum.

        """
        total_timeout_ms = usb.Timeout(total_timeout_ms)
        start = time.time()

        while True:
            msg = usb.BulkRead(24, timeout_ms)
            cmd, arg0, arg1, data_length, data_checksum = cls.Unpack(msg)
            command = cls.constants.get(cmd)
            if not command:
                raise InvalidCommandError('Unknown command: %x' % cmd, cmd, (arg0, arg1))

            if command in expected_cmds:
                break

            if time.time() - start > total_timeout_ms:
                raise InvalidCommandError('Never got one of the expected responses (%s)' % expected_cmds, cmd, (timeout_ms, total_timeout_ms))

        if data_length > 0:
            data = bytearray()
            while data_length > 0:
                temp = usb.BulkRead(data_length, timeout_ms)
                if len(temp) != data_length:
                    print("Data_length {} does not match actual number of bytes read: {}".format(data_length, len(temp)))
                data += temp

                data_length -= len(temp)

            actual_checksum = cls.CalculateChecksum(data)
            if actual_checksum != data_checksum:
                raise InvalidChecksumError('Received checksum {0} != {1}'.format(actual_checksum, data_checksum))
        else:
            data = b''

        return command, arg0, arg1, bytes(data)

    def read_until(self, *expected_cmds):
        """Read a packet, Ack any write packets.

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
        adb.adb_protocol.InterleavedDataError
            We don't support multiple streams...
        adb.adb_protocol.InvalidResponseError
            Incorrect remote id.

        """
        cmd, remote_id, local_id, data = AdbMessage.Read(self.usb, expected_cmds, self.timeout_ms)

        if local_id not in (0, self.local_id):
            raise InterleavedDataError("We don't support multiple streams...")

        if remote_id not in (0, self.remote_id):
            raise InvalidResponseError('Incorrect remote id, expected {0} got {1}'.format(self.remote_id, remote_id))

        # Ack write packets.
        if cmd == b'WRTE':
            self.Okay()

        return cmd, data

    def read_until_close(self):
        """Yield packets until a ``b'CLSE'`` packet is received.

        .. image:: _static/adb.adb_protocol._AdbConnection.ReadUntilClose.CALL_GRAPH.svg

        Yields
        ------
        data : TODO
            TODO

        """
        while True:
            cmd, data = self.ReadUntil(b'CLSE', b'WRTE')

            if cmd == b'CLSE':
                self._Send(b'CLSE', arg0=self.local_id, arg1=self.remote_id)
                break

            if cmd != b'WRTE':
                if cmd == b'FAIL':
                    raise usb_exceptions.AdbCommandFailureException('Command failed.', data)

                raise InvalidCommandError('Expected a WRITE or a CLOSE, got {0} ({1})'.format(cmd, data), cmd, data)

            yield data

    # AdbMessage
    def _send(self, msg, timeout_ms):
        """TODO

        """
        self._handle.bulk_write(msg.pack(), timeout_ms)
        self._handle.bulk_write(msg.data, timeout_ms)

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
        adb.adb_protocol.InterleavedDataError
            Multiple streams running over usb.
        adb.adb_protocol.InvalidCommandError
            Got an unexpected response command.

        """
        connection = cls.Open(usb, destination=b'%s:%s' % (service, command), timeout_ms=timeout_ms)
        for data in connection.ReadUntilClose():
            yield data.decode('utf8')
