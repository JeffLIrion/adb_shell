import unittest

from aio_adb_shell import constants, exceptions


class TestInvalidCommandError(unittest.TestCase):
    def test_init_with_params(self):
        """Cover this case that does not get covered in the code."""
        with self.assertRaises(exceptions.InvalidCommandError):
            cmd = sum(c << (i * 8) for i, c in enumerate(bytearray(b'FAIL')))
            remote_id = 123
            their_local_id = 999
            raise exceptions.InvalidCommandError('Expected a ready response, got {}'.format(cmd), constants.FAIL, (remote_id, their_local_id))
