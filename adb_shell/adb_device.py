"""TODO.

"""


from . import constants
from .adb_handle import TcpHandle, UsbHandle
from .adb_message import AdbMessage


class AdbDevice(object):
    """TODO.

    """
    
    def __init__(self, serial, banner=None):
        self._available = False

        if banner and isinstance(banner, str):
            self._banner = banner
        else:
            try:
                self._banner = socket.gethostname()
            except:
                self._banner = 'unknown'

        self._banner_bytes = bytearray(self._banner, 'utf-8')

        self._handle = None
        self._serial = serial

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

    def connect(self, timeout_ms=9000, auth_timeout_ms=10000):
        """TODO

        """
        # 1. Create a TCP / USB handle (adb.adb_commands.AdbCommands.ConnectDevice)
        if ':' in self._serial:
            self._handle = TcpHandle(self._serial, timeout_ms=timeout_ms)
        #else:
        #    self._handle = UsbHandle.FindAndOpen(DeviceIsAvailable, port_path=port_path, serial=serial, timeout_ms=default_timeout_ms)

        # 2. Use the handle to connect (adb.adb_commands.AdbCommands._Connect)

        # 3. Create an ADB message (adb.adb_protocol.AdbMessage.Connect)
        msg = AdbMessage(command=constants.CNXN, arg0=constants.VERSION, arg1=constants.MAX_ADB_DATA, data=b'host::%s\0' % self._banner_bytes)

        # 4. Send the message using the handle (adb.adb_protocol.AdbMessage.Send)
        self._send(msg, timeout_ms)

        # 5. Read the response (adb.adb_protocol.AdbMessage.Read)
        # cmd, arg0, arg1, banner = cls.Read(usb, [b'CNXN', b'AUTH'])
        cmd, arg0, arg1, banner = self._read([constants.AUTH, constants.CNXN])

        # 6. If necessary, authenticate (adb.adb_protocol.AdbMessage.Connect)
        
        self._available = True

        return self._available

    def _read(self, *args, **kwargs):
        """TODO

        """
        return None, None, None, None

    def _send(self, msg, timeout_ms):
        """TODO

        """
        self._handle.BulkWrite(msg.Pack(), timeout_ms)
        self._handle.BulkWrite(msg.data, timeout_ms)

    def shell(self, cmd):
        """TODO

        """
        pass
