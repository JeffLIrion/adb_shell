import socket

from mock import patch


class FakeSocket(object):
    def __init__(self):
        pass

    def close(self):
        pass

    def recv(self, numbytes):
        pass

    def send(self, data):
        pass
