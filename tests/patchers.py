#import select
#import socket

from mock import patch

from adb_shell import constants
from adb_shell.adb_message import AdbMessage, unpack
from adb_shell.tcp_handle import TcpHandle


#MSG_CONNECT = AdbMessage(command=constants.CNXN, arg0=constants.VERSION, arg1=constants.MAX_ADB_DATA, data=b'host::%s\0' % 'unknown'.encode('utf-8'))
MSG_CONNECT = AdbMessage(command=constants.CNXN, arg0=constants.VERSION, arg1=constants.MAX_ADB_DATA, data=b'host::unknown1234567890\0')


class FakeSocket(object):
    def __init__(self):
        self.recv_list = [b'']

    def close(self):
        pass

    def recv(self, bufsize):
        return self.recv_list.pop(0)

    def send(self, data):
        pass

    def setblocking(self, *args, **kwargs):
        pass

    def shutdown(self, how):
        pass


class FakeTcpHandle(TcpHandle):
    def connect(self, auth_timeout_s=None):
        """TODO

        """
        #self._connection = FakeSocket()
        self.bulk_read_list = [MSG_CONNECT.pack(), MSG_CONNECT.data]

    def bulk_read(self, numbytes, timeout_s=None):
        return self.bulk_read_list.pop(0)

    def bulk_write(self, data, timeout_s=None):
        return len(data)


# `socket` patches
patch_create_connection = patch('socket.create_connection', return_value=FakeSocket())


# `select` patches
patch_select_success = patch('select.select', return_value=(True, True, True))

patch_select_fail = patch('select.select', return_value=(False, False, False))


# `TcpHandle` patches
patch_tcp_handle = patch('adb_shell.adb_device.TcpHandle', FakeTcpHandle)

#def patch_bulk_read(response):
#    def _bulk_read(self, numbytes, timeout_s=None):
#        return response
#
#    return patch('{}.FakeTcpHandle.bulk_read'.format(__name__), _bulk_read)
