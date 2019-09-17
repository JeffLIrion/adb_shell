from mock import patch
import unittest

from adb_shell.adb_handle import TcpHandle


class TestAdbHandle(unittest.TestCase):
    def setUp(self):
        """TODO

        """
        self.handle = TcpHandle('IP:PORT')

    def test_init(self):
        """TODO

        """
        self.assertTrue(True)
