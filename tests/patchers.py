import select
import socket

from mock import patch

from adb_shell.tcp_handle import TcpHandle


class FakeSocket(object):
    def __init__(self):
        pass

    def close(self):
        pass

    def recv(self, bufsize):
        pass

    def send(self, data):
        pass

    def setblocking(self, *args, **kwargs):
        pass


class FakeTcpHandle(TcpHandle):
    def connect(self, auth_timeout_ms=None):
        """TODO

        """
        self._connection = FakeSocket()

    def bulk_write(self, data, timeout_ms=None):
        return len(data)


#def _bulk_write(self, data, timeout_ms=None):
#    return len(data)

#patch_bulk_write = patch('{}.FakeTcpHandle.bulk_write'.format(__name__), _bulk_write)


# `socket` patches
patch_create_connection = patch('socket.create_connection', return_value=FakeSocket())

def patch_recv(response):
    def _recv(self, bufsize):
        return response

    return patch('{}.FakeSocket.recv'.format(__name__), _recv)


# `select` patches
patch_select_success = patch('select.select', return_value=(True, True, True))

patch_select_fail = patch('select.select', return_value=(False, False, False))


# `TcpHandle` patches
patch_tcp_handle = patch('adb_shell.adb_device.TcpHandle', FakeTcpHandle)

def patch_bulk_read(response):
    def _bulk_read(self, numbytes, timeout_ms=None):
        return response

    return patch('{}.FakeTcpHandle.bulk_read'.format(__name__), _bulk_read)
