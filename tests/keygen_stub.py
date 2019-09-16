from contextlib import contextmanager
from mock import patch


class FileReadWrite(object):
    """Mock an opened file that can be read and written to."""
    def __init__(self):
        self._content = b''

    def read(self):
        return self._content

    def write(self, content):
        self._content = content


PRIVATE_KEY = FileReadWrite()
PUBLIC_KEY = FileReadWrite()


@contextmanager
def open_priv_pub(infile, mode='r'):
    try:
        if infile.endswith('.pub'):
            yield PUBLIC_KEY
        else:
            yield PRIVATE_KEY
    finally:
        pass
