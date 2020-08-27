import unittest

from drpc.shared.exceptions import CallError as shared_call_error
import drpc.v1 as drpc_v1
import drpc.v2 as drpc_v2

class TestExceptCrossVersions(unittest.TestCase):
    """ Tests that the exceptions from the various imports are deemed equal by python except blocks. """
    def test_v1_catch_shared(self):
        with self.assertRaises(drpc_v1.CallError):
            raise shared_call_error('shared call error')

    def test_v1_catch_v2(self):
        with self.assertRaises(drpc_v1.CallError):
            raise drpc_v2.CallError('v2 call error')

    def test_v2_catch_shared(self):
        with self.assertRaises(drpc_v1.CallError):
            raise shared_call_error('shared call error')

    def test_v2_catch_v1(self):
        with self.assertRaises(drpc_v2.CallError):
            raise drpc_v1.CallError('v1 call error')

    def test_shared_catch_v1(self):
        with self.assertRaises(shared_call_error):
            raise drpc_v1.CallError('v1 call error')

    def test_shared_catch_v2(self):
        with self.assertRaises(shared_call_error):
            raise drpc_v2.CallError('v2 call error')


class TestCallErrorEquality(unittest.TestCase):
    """ Testing the __eq__ function for CallError. """
    def test_totally_equal(self):
        a = shared_call_error('hi', {'a':1, 'b':2})
        b = shared_call_error('hi', {'a':1, 'b':2})
        self.assertEqual(a, b)

    def test_totally_different(self):
        a = shared_call_error('hi', {'a':1, 'b':2})
        b = shared_call_error('hello', {'x':1, 'y':2})
        self.assertNotEqual(a, b)

    def test_different_error(self):
        a = shared_call_error('hi', {'a':1, 'b':2})
        b = shared_call_error('hello', {'a':1, 'b':2})
        self.assertNotEqual(a, b)

    def test_different_error_args(self):
        a = shared_call_error('hi', {'a':1, 'b':2})
        b = shared_call_error('hi', {'x':1, 'y':2})
        self.assertNotEqual(a, b)


if __name__ == '__main__':
    unittest.main()
