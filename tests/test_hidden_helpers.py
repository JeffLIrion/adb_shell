import unittest

from adb_shell import constants
from adb_shell.hidden_helpers import _AdbPacketStore


class TestAdbPacketStore(unittest.TestCase):
    def test_init(self):
        packet_store = _AdbPacketStore()
        self.assertEqual(len(packet_store), 0)
        self.assertFalse((None, None) in packet_store)

    def test_contains(self):
        packet_store = _AdbPacketStore()
        self.assertFalse((None, None) in packet_store)

        packet_store.put(arg0=0, arg1=1, cmd=b"cmd1", data=b"data1")
        self.assertTrue((0, 1) in packet_store)
        self.assertTrue((None, 1) in packet_store)
        self.assertFalse((None, 0) in packet_store)
        self.assertTrue((0, None) in packet_store)
        self.assertFalse((1, None) in packet_store)
        self.assertFalse((1, 1) in packet_store)
        self.assertTrue((None, None) in packet_store)

    def test_put(self):
        packet_store = _AdbPacketStore()
        packet_store.put(arg0=0, arg1=1, cmd=b"cmd1", data=b"data1")
        self.assertTrue((0, 1) in packet_store)
        self.assertEqual(len(packet_store), 1)

        packet_store.put(arg0=0, arg1=1, cmd=b"cmd2", data=b"data2")
        self.assertTrue((0, 1) in packet_store)
        self.assertEqual(len(packet_store), 1)

        packet_store.put(arg0=1, arg1=0, cmd=b"cmd3", data=b"data3")
        self.assertTrue((1, 0) in packet_store)
        self.assertEqual(len(packet_store), 2)

        packet_store.put(arg0=1, arg1=1, cmd=b"cmd4", data=b"data4")
        self.assertTrue((1, 1) in packet_store)
        self.assertEqual(len(packet_store), 3)

        packet_store.put(arg0=5, arg1=5, cmd=constants.CLSE, data=b"data5")
        self.assertEqual(len(packet_store), 3)
        self.assertFalse((5, 5) in packet_store)
        
        packet_store.put(arg0=5, arg1=1, cmd=constants.CLSE, data=b"data5")
        self.assertEqual(len(packet_store), 3)
        self.assertFalse((5, 1) in packet_store)

    def test_get(self):
        packet_store = _AdbPacketStore()
        packet_store.put(arg0=0, arg1=1, cmd=b"cmd1", data=b"data1")
        packet_store.put(arg0=0, arg1=1, cmd=b"cmd2", data=b"data2")
        packet_store.put(arg0=1, arg1=0, cmd=b"cmd3", data=b"data3")
        packet_store.put(arg0=1, arg1=1, cmd=b"cmd4", data=b"data4")
        packet_store.put(arg0=2, arg1=3, cmd=b"cmd5", data=b"data5")
        packet_store.put(arg0=4, arg1=5, cmd=b"cmd6", data=b"data6")

        self.assertTrue((0, 1) in packet_store)
        arg0, arg1, cmd1, data1 = packet_store.get(arg0=0, arg1=1)
        self.assertEqual(arg0, 0)
        self.assertEqual(arg1, 1)
        self.assertEqual(cmd1, b"cmd1")
        self.assertEqual(data1, b"data1")
        self.assertTrue((0, 1) in packet_store)
        self.assertEqual(len(packet_store), 5)

        self.assertTrue((0, 1) in packet_store)
        arg0, arg1, cmd2, data2 = packet_store.get(arg0=0, arg1=1)
        self.assertEqual(arg0, 0)
        self.assertEqual(arg1, 1)
        self.assertEqual(cmd2, b"cmd2")
        self.assertEqual(data2, b"data2")
        self.assertFalse((0, 1) in packet_store)
        self.assertEqual(len(packet_store), 4)

        self.assertTrue((1, 0) in packet_store)
        arg0, arg1, cmd3, data3 = packet_store.get(arg0=1, arg1=0)
        self.assertEqual(arg0, 1)
        self.assertEqual(arg1, 0)
        self.assertEqual(cmd3, b"cmd3")
        self.assertEqual(data3, b"data3")
        self.assertEqual(len(packet_store), 3)

        self.assertTrue((1, None) in packet_store)
        arg0, arg1, cmd4, data4 = packet_store.get(arg0=1, arg1=None)
        self.assertEqual(arg0, 1)
        self.assertEqual(arg1, 1)
        self.assertEqual(cmd4, b"cmd4")
        self.assertEqual(data4, b"data4")
        self.assertEqual(len(packet_store), 2)

        self.assertTrue((None, 3) in packet_store)
        arg0, arg1, cmd5, data5 = packet_store.get(arg0=None, arg1=3)
        self.assertEqual(arg0, 2)
        self.assertEqual(arg1, 3)
        self.assertEqual(cmd5, b"cmd5")
        self.assertEqual(data5, b"data5")
        self.assertEqual(len(packet_store), 1)

        self.assertTrue((None, None) in packet_store)
        arg0, arg1, cmd6, data6 = packet_store.get(arg0=None, arg1=None)
        self.assertEqual(arg0, 4)
        self.assertEqual(arg1, 5)
        self.assertEqual(cmd6, b"cmd6")
        self.assertEqual(data6, b"data6")
        self.assertEqual(len(packet_store), 0)

        self.assertEqual(len(packet_store._dict), 4)
        self.assertEqual(len(packet_store._dict[1]), 2)
        self.assertEqual(len(packet_store._dict[0]), 1)
        self.assertEqual(len(packet_store._dict[3]), 1)
        self.assertEqual(len(packet_store._dict[5]), 1)
        
    def test_clear(self):
        packet_store = _AdbPacketStore()
        packet_store.put(arg0=0, arg1=1, cmd=b"cmd1", data=b"data1")

        packet_store.clear(arg0=None, arg1=None)
        self.assertEqual(len(packet_store), 1)

        packet_store.clear(arg0=1, arg1=0)
        self.assertEqual(len(packet_store), 1)

        packet_store.clear(arg0=0, arg1=1)
        self.assertEqual(len(packet_store), 0)
        self.assertEqual(len(packet_store._dict), 1)

    def test_clear_all(self):
        packet_store = _AdbPacketStore()
        packet_store.put(arg0=0, arg1=1, cmd=b"cmd1", data=b"data1")

        packet_store.clear_all()
        self.assertFalse((0, 1) in packet_store)
        self.assertEqual(len(packet_store), 0)

