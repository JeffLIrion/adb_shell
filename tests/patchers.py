import select
import socket

from mock import patch


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


patch_create_connection = patch('socket.create_connection', return_value=FakeSocket())

def patch_recv(response):
    def _recv(self, bufsize):
        return response

    return patch('{}.FakeSocket.recv'.format(__name__), _recv)

patch_select_success = patch('select.select', return_value=(True, True, True))

patch_select_fail = patch('select.select', return_value=(False, False, False))
