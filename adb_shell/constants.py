"""TODO

"""


#: From adb.h
CLASS = 0xFF

#: From adb.h
SUBCLASS = 0x42

#: From adb.h
PROTOCOL = 0x01

#: Maximum amount of data in an ADB packet.
MAX_ADB_DATA = 4096

#: ADB protocol version.
VERSION = 0x01000000

#: AUTH constants for arg0.
AUTH_TOKEN = 1

#: AUTH constants for arg0.
AUTH_SIGNATURE = 2

#: AUTH constants for arg0.
AUTH_RSAPUBLICKEY = 3

AUTH = b'AUTH'
CLSE = b'CLSE'
CNXN = b'CNXN'
OKAY = b'OKAY'
OPEN = b'OPEN'
SYNC = b'SYNC'
WRTE = b'WRTE'

IDS = (AUTH, CLSE, CNXN, OKAY, OPEN, SYNC, WRTE)

ID_TO_WIRE = {cmd_id: sum(c << (i * 8) for i, c in enumerate(bytearray(cmd_id))) for cmd_id in IDS}
WIRE_TO_ID = {wire: cmd_id for cmd_id, wire in ID_TO_WIRE.items()}

#: An ADB message is 6 words in little-endian.
MESSAGE_FORMAT = b'<6I'

#: Default timeout for :meth:`adb_shell.tcp_handle.TcpHandle.bulk_read` and :meth:`adb_shell.tcp_handle.TcpHandle.bulk_write`
DEFAULT_TIMEOUT = 9.

#: Default authentication timeout for :meth:`adb_shell.tcp_handle.TcpHandle.connect`
DEFAULT_AUTH_TIMEOUT = 10.
