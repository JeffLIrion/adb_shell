import unittest

from unittest.mock import patch

from aio_adb_shell.auth.keygen import get_user_info


class TestKeygen(unittest.TestCase):
    def test_get_user_info(self):
        with patch('aio_adb_shell.auth.keygen.os.getlogin', side_effect=OSError), patch('aio_adb_shell.auth.keygen.socket.gethostname', return_value=''):
            user_host = get_user_info()
            self.assertEqual(user_host, ' unknown@unknown')

        with patch('aio_adb_shell.auth.keygen.os.getlogin', return_value=''), patch('aio_adb_shell.auth.keygen.socket.gethostname', return_value=''):
            user_host = get_user_info()
            self.assertEqual(user_host, ' unknown@unknown')
