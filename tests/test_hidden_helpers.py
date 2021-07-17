import unittest

from adb_shell import constants
from adb_shell.hidden_helpers import _AdbPacketStore, _AdbTransactionInfo


class TestAdbPacketStore(unittest.TestCase):
    def setUp(self):
        self.packet_store = _AdbPacketStore()

    def test_init(self):
        self.assertEqual(len(self.packet_store), 0)
        self.assertFalse((None, None) in self.packet_store)

    def test_contains(self):
        self.assertFalse((None, None) in self.packet_store)

        self.packet_store.put(arg0=0, arg1=1, cmd=b"cmd1", data=b"data1")
        self.assertTrue((0, 1) in self.packet_store)
        self.assertTrue((None, 1) in self.packet_store)
        self.assertFalse((None, 0) in self.packet_store)
        self.assertTrue((0, None) in self.packet_store)
        self.assertFalse((1, None) in self.packet_store)
        self.assertFalse((1, 1) in self.packet_store)
        self.assertTrue((None, None) in self.packet_store)

    def test_put(self):
        self.packet_store.put(arg0=0, arg1=1, cmd=b"cmd1", data=b"data1")
        self.assertTrue((0, 1) in self.packet_store)
        self.assertEqual(len(self.packet_store), 1)

        self.packet_store.put(arg0=0, arg1=1, cmd=b"cmd2", data=b"data2")
        self.assertTrue((0, 1) in self.packet_store)
        self.assertEqual(len(self.packet_store), 1)

        self.packet_store.put(arg0=1, arg1=0, cmd=b"cmd3", data=b"data3")
        self.assertTrue((1, 0) in self.packet_store)
        self.assertEqual(len(self.packet_store), 2)

        self.packet_store.put(arg0=1, arg1=1, cmd=b"cmd4", data=b"data4")
        self.assertTrue((1, 1) in self.packet_store)
        self.assertEqual(len(self.packet_store), 3)

        self.packet_store.put(arg0=5, arg1=5, cmd=constants.CLSE, data=b"data5")
        self.assertEqual(len(self.packet_store), 3)
        self.assertFalse((5, 5) in self.packet_store)
        
        self.packet_store.put(arg0=5, arg1=1, cmd=constants.CLSE, data=b"data5")
        self.assertEqual(len(self.packet_store), 3)
        self.assertFalse((5, 1) in self.packet_store)

    def test_get(self):
        self.packet_store.put(arg0=0, arg1=1, cmd=b"cmd1", data=b"data1")
        self.packet_store.put(arg0=0, arg1=1, cmd=b"cmd2", data=b"data2")
        self.packet_store.put(arg0=1, arg1=0, cmd=b"cmd3", data=b"data3")
        self.packet_store.put(arg0=1, arg1=1, cmd=b"cmd4", data=b"data4")
        self.packet_store.put(arg0=2, arg1=3, cmd=b"cmd5", data=b"data5")
        self.packet_store.put(arg0=4, arg1=5, cmd=b"cmd6", data=b"data6")

        self.assertTrue((0, 1) in self.packet_store)
        cmd1, arg0, arg1, data1 = self.packet_store.get(arg0=0, arg1=1)
        self.assertEqual(arg0, 0)
        self.assertEqual(arg1, 1)
        self.assertEqual(cmd1, b"cmd1")
        self.assertEqual(data1, b"data1")
        self.assertTrue((0, 1) in self.packet_store)
        self.assertEqual(len(self.packet_store), 5)

        self.assertTrue((0, 1) in self.packet_store)
        cmd2, arg0, arg1, data2 = self.packet_store.get(arg0=0, arg1=1)
        self.assertEqual(arg0, 0)
        self.assertEqual(arg1, 1)
        self.assertEqual(cmd2, b"cmd2")
        self.assertEqual(data2, b"data2")
        self.assertFalse((0, 1) in self.packet_store)
        self.assertEqual(len(self.packet_store), 4)

        self.assertTrue((1, 0) in self.packet_store)
        cmd3, arg0, arg1, data3 = self.packet_store.get(arg0=1, arg1=0)
        self.assertEqual(arg0, 1)
        self.assertEqual(arg1, 0)
        self.assertEqual(cmd3, b"cmd3")
        self.assertEqual(data3, b"data3")
        self.assertEqual(len(self.packet_store), 3)

        self.assertTrue((1, None) in self.packet_store)
        cmd4, arg0, arg1, data4 = self.packet_store.get(arg0=1, arg1=None)
        self.assertEqual(arg0, 1)
        self.assertEqual(arg1, 1)
        self.assertEqual(cmd4, b"cmd4")
        self.assertEqual(data4, b"data4")
        self.assertEqual(len(self.packet_store), 2)

        self.assertTrue((None, 3) in self.packet_store)
        cmd5, arg0, arg1, data5 = self.packet_store.get(arg0=None, arg1=3)
        self.assertEqual(arg0, 2)
        self.assertEqual(arg1, 3)
        self.assertEqual(cmd5, b"cmd5")
        self.assertEqual(data5, b"data5")
        self.assertEqual(len(self.packet_store), 1)

        self.assertTrue((None, None) in self.packet_store)
        cmd6, arg0, arg1, data6 = self.packet_store.get(arg0=None, arg1=None)
        self.assertEqual(arg0, 4)
        self.assertEqual(arg1, 5)
        self.assertEqual(cmd6, b"cmd6")
        self.assertEqual(data6, b"data6")
        self.assertEqual(len(self.packet_store), 0)

        self.assertEqual(len(self.packet_store._dict), 4)
        self.assertEqual(len(self.packet_store._dict[1]), 2)
        self.assertEqual(len(self.packet_store._dict[0]), 1)
        self.assertEqual(len(self.packet_store._dict[3]), 1)
        self.assertEqual(len(self.packet_store._dict[5]), 1)
        
    def test_get_clse(self):
        self.packet_store.put(arg0=0, arg1=1, cmd=b"cmd1", data=b"data1")
        self.packet_store.put(arg0=0, arg1=1, cmd=constants.CLSE, data=b"data2")
        self.packet_store.put(arg0=0, arg1=1, cmd=b"cmd3", data=b"data3")

        self.assertTrue((0, 1) in self.packet_store)
        cmd1, arg0, arg1, data1 = self.packet_store.get(arg0=0, arg1=1)
        self.assertEqual(arg0, 0)
        self.assertEqual(arg1, 1)
        self.assertEqual(cmd1, b"cmd1")
        self.assertEqual(data1, b"data1")
        self.assertTrue((0, 1) in self.packet_store)
        self.assertEqual(len(self.packet_store), 1)

        self.assertTrue((0, 1) in self.packet_store)
        cmd2, arg0, arg1, data2 = self.packet_store.get(arg0=0, arg1=1)
        self.assertEqual(arg0, 0)
        self.assertEqual(arg1, 1)
        self.assertEqual(cmd2, constants.CLSE)
        self.assertEqual(data2, b"data2")
        self.assertFalse((0, 1) in self.packet_store)
        self.assertEqual(len(self.packet_store), 0)

        self.assertEqual(len(self.packet_store._dict), 0)

    def test_clear(self):
        self.packet_store.put(arg0=0, arg1=1, cmd=b"cmd1", data=b"data1")
        self.packet_store.put(arg0=2, arg1=1, cmd=b"cmd2", data=b"data2")

        self.packet_store.clear(arg0=None, arg1=None)
        self.assertEqual(len(self.packet_store), 2)

        self.packet_store.clear(arg0=1, arg1=0)
        self.assertEqual(len(self.packet_store), 2)

        self.packet_store.clear(arg0=0, arg1=1)
        self.assertEqual(len(self.packet_store), 1)
        self.assertEqual(len(self.packet_store._dict), 1)

        self.packet_store.clear(arg0=2, arg1=1)
        self.assertEqual(len(self.packet_store), 0)
        self.assertEqual(len(self.packet_store._dict), 0)

    def test_clear_all(self):
        self.packet_store.put(arg0=0, arg1=1, cmd=b"cmd1", data=b"data1")

        self.packet_store.clear_all()
        self.assertFalse((0, 1) in self.packet_store)
        self.assertEqual(len(self.packet_store), 0)

    def test_find_allow_zeros(self):
        self.packet_store.put(arg0=0, arg1=1, cmd=b"cmd", data=b"data")
        self.assertEqual(self.packet_store.find_allow_zeros(arg0=2, arg1=1), (0, 1))
        self.assertIsNone(self.packet_store.find_allow_zeros(arg0=2, arg1=2))


class TestAdbTransactionInfo(unittest.TestCase):

    def test_args_match(self):
        adb_info_1_None = _AdbTransactionInfo(1, None, 123, 456, 789)
        adb_info_1_2 = _AdbTransactionInfo(1, 2, 123, 456, 789)

        # (1, None) -> exact matches
        self.assertTrue(adb_info_1_None.args_match(6, 1))
        self.assertTrue(adb_info_1_None.args_match(7, 1))
        self.assertTrue(adb_info_1_None.args_match(6, 1, allow_zeros=True))
        self.assertTrue(adb_info_1_None.args_match(7, 1, allow_zeros=True))

        # (1, None) -> no match
        self.assertFalse(adb_info_1_None.args_match(0, 0))
        self.assertFalse(adb_info_1_None.args_match(1, 0))
        self.assertFalse(adb_info_1_None.args_match(2, 0))
        self.assertFalse(adb_info_1_None.args_match(3, 0))
        self.assertFalse(adb_info_1_None.args_match(4, 5, allow_zeros=True))

        # (1, None) -> zero matches
        self.assertTrue(adb_info_1_None.args_match(0, 0, allow_zeros=True))
        self.assertTrue(adb_info_1_None.args_match(1, 0, allow_zeros=True))
        self.assertTrue(adb_info_1_None.args_match(2, 0, allow_zeros=True))
        self.assertTrue(adb_info_1_None.args_match(3, 0, allow_zeros=True))

        # (1, 2) -> exact matches
        self.assertTrue(adb_info_1_2.args_match(2, 1))
        self.assertTrue(adb_info_1_2.args_match(2, 1, allow_zeros=True))

        # (1, 2) -> no match
        self.assertFalse(adb_info_1_2.args_match(0, 0))
        self.assertFalse(adb_info_1_2.args_match(2, 0))
        self.assertFalse(adb_info_1_2.args_match(0, 1))

        self.assertFalse(adb_info_1_2.args_match(1, 2))
        self.assertFalse(adb_info_1_2.args_match(1, 2, allow_zeros=True))

        self.assertFalse(adb_info_1_2.args_match(3, 0))
        self.assertFalse(adb_info_1_2.args_match(0, 4))
        self.assertFalse(adb_info_1_2.args_match(3, 4))
        self.assertFalse(adb_info_1_2.args_match(3, 0, allow_zeros=True))
        self.assertFalse(adb_info_1_2.args_match(0, 4, allow_zeros=True))
        self.assertFalse(adb_info_1_2.args_match(3, 4, allow_zeros=True))

        self.assertFalse(adb_info_1_2.args_match(2, 6))
        self.assertFalse(adb_info_1_2.args_match(2, 6, allow_zeros=True))
        self.assertFalse(adb_info_1_2.args_match(7, 1))
        self.assertFalse(adb_info_1_2.args_match(7, 1, allow_zeros=True))

        # (1, 2) -> zero matches
        self.assertTrue(adb_info_1_2.args_match(0, 0, allow_zeros=True))
        self.assertTrue(adb_info_1_2.args_match(2, 0, allow_zeros=True))
        self.assertTrue(adb_info_1_2.args_match(0, 1, allow_zeros=True))
