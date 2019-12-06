"""
Implementation of Base class for use with AdbDevice
"""


class HandleBase(object):
    def connect(self):
        raise NotImplementedError()

    def close(self):
        raise NotImplementedError()

    def bulk_read(self, *args):
        raise NotImplementedError()

    def bulk_write(self, *args):
        raise NotImplementedError()
