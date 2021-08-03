import functools
import inspect
import pickle
import re
import unittest
try:
    from unittest import mock
except ImportError:
    import mock

import adb_shell.exceptions

try:
    getargspec = inspect.getfullargspec
except AttributeError:
    getargspec = inspect.getargspec

try:
    _assertRegex = unittest.TestCase.assertRegex
except AttributeError:
    _assertRegex = unittest.TestCase.assertRegexpMatches


class TestExceptionSerialization(unittest.TestCase):
    def __test_serialize_one_exc_cls(exc_cls):
        # Work out how many args we need to instantiate this object
        try:
            exc_required_arity = len(getargspec(exc_cls.__init__).args)
        except TypeError:
            # In Python 2.7 this could be a slot wrapper which means `__init__`
            # wasn't overridden by the exception subclass - use 0 arity.
            exc_required_arity = 0
        # Don't try to provide `self` - we assume strings will be fine here
        fake_args = ("foo", ) * (exc_required_arity - 1)
        # Instantiate the exception object and then attempt a serializion cycle
        # using `pickle` - we mainly care about whether this blows up or not
        exc_obj = exc_cls(*fake_args)
        pickled_exc_data = pickle.dumps(exc_obj)
        depickled_exc_obj = pickle.loads(pickled_exc_data)

    for __obj in adb_shell.exceptions.__dict__.values():
        if isinstance(__obj, type) and issubclass(__obj, BaseException):
            __test_method = functools.partial(
                __test_serialize_one_exc_cls, __obj
            )
            __test_name = "test_serialize_{}".format(__obj.__name__)
            locals()[__test_name] = __test_method

    # We want to confirm what the stringification and representation of
    # `UsbReadFailedError` look like since it's a non-trivial subclass of
    # `Exception`
    def test_usbreadfailederror_as_str(self):
        exc_args = (mock.sentinel.error_msg, mock.sentinel.usb1_exc_obj)
        exc_obj = adb_shell.exceptions.UsbReadFailedError(*exc_args)
        expected_str = "{}: {}".format(*exc_args)
        _assertRegex(self, str(exc_obj), re.escape(expected_str))

    def test_usbreadfailederror_as_repr(self):
        exc_args = (mock.sentinel.error_msg, mock.sentinel.usb1_exc_obj)
        exc_obj = adb_shell.exceptions.UsbReadFailedError(*exc_args)
        expected_repr = "{}{!r}".format(
            adb_shell.exceptions.UsbReadFailedError.__name__, exc_args
        )
        _assertRegex(self, repr(exc_obj), re.escape(expected_repr))
