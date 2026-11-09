#!/usr/bin/env python3
"""Shared enrollment failure cases and real Unix sockets; no disks/USB/TPM."""
from contextlib import ExitStack
import copy
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import enrollment
import key_sockets


class SocketTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='shared-sockets-')
        self.addCleanup(self.temporary.cleanup)
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.listeners = []
        for number in range(2):
            listener = self.stack.enter_context(socket.socket(socket.AF_UNIX, socket.SOCK_STREAM))
            listener.bind(self.temporary.name + '/' + str(number))
            listener.listen(4)
            self.listeners.append(listener)

    def client(self, number):
        client = self.stack.enter_context(socket.socket(socket.AF_UNIX, socket.SOCK_STREAM))
        client.settimeout(2)
        client.connect(self.listeners[number].getsockname())
        return client

    def start(self, producer, timeout=2):
        errors = []

        def worker():
            try:
                key_sockets.serve(self.listeners, producer, timeout)
            except Exception as error:
                errors.append(error)

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        return thread, errors

    def test_one_derivation_for_two_volumes_and_retry_cannot_steal_delivery(self):
        calls = []
        thread, errors = self.start(lambda: calls.append('proof-and-touch') or b'group-key')
        first = self.client(0)
        self.assertEqual(first.recv(100), b'group-key')
        retry = self.client(0)
        second = self.client(1)
        self.assertEqual(second.recv(100), b'group-key')
        thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(calls, ['proof-and-touch'])
        retry.settimeout(.05)
        with self.assertRaises(TimeoutError):
            retry.recv(100)

    def test_single_volume_compatibility(self):
        errors = []

        def worker():
            try:
                key_sockets.serve(self.listeners[:1], lambda: b'single-key', 2)
            except Exception as error:
                errors.append(error)

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        self.assertEqual(self.client(0).recv(100), b'single-key')
        thread.join(1)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])

    def test_no_request_never_derives_key(self):
        calls = []
        with self.assertRaises(TimeoutError):
            key_sockets.serve(self.listeners, lambda: calls.append(True) or b'key', .05)
        self.assertEqual(calls, [])

    def test_missing_member_has_bounded_lifetime(self):
        thread, errors = self.start(lambda: b'key', .2)
        self.assertEqual(self.client(0).recv(100), b'key')
        thread.join(1)
        self.assertFalse(thread.is_alive())
        self.assertIsInstance(errors[0], TimeoutError)

    def test_failed_identity_producer_sends_no_key(self):
        def reject():
            raise ValueError('Bad signature')

        thread, errors = self.start(reject)
        self.assertEqual(self.client(0).recv(100), b'')
        thread.join(1)
        self.assertIsInstance(errors[0], ValueError)

    def test_new_invocation_derives_again(self):
        calls = []
        for expected in [b'first-proof-key', b'new-proof-key']:
            thread, errors = self.start(lambda: calls.append(True) or expected)
            for number in range(2):
                self.assertEqual(self.client(number).recv(100), expected)
            thread.join(1)
            self.assertEqual(errors, [])
        self.assertEqual(len(calls), 2)

    def test_systemd_multiple_fds_are_checked_and_served(self):
        program = '''
import json, os, sys
from contextlib import ExitStack
sys.path.insert(0, sys.argv[1])
import key_sockets
copies = [os.dup(int(fd)) for fd in sys.argv[2].split(',')]
for number, fd in enumerate(copies, 3):
    os.dup2(fd, number)
os.environ.update(LISTEN_PID=str(os.getpid()), LISTEN_FDS='2')
with ExitStack() as stack:
    listeners = key_sockets.activated(stack, json.loads(sys.argv[3]))
    key_sockets.serve(listeners, lambda: b'activated-key', 2)
print('OK')
'''
        paths = [s.getsockname() for s in reversed(self.listeners)]
        with subprocess.Popen([sys.executable, '-c', program,
            str(Path(key_sockets.__file__).parent),
            ','.join(str(s.fileno()) for s in self.listeners), json.dumps(paths)],
            pass_fds=tuple(s.fileno() for s in self.listeners),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE) as child:
            for number in range(2):
                self.assertEqual(self.client(number).recv(100), b'activated-key')
            output, error = child.communicate(timeout=3)
            self.assertEqual(child.returncode, 0, error.decode())
            self.assertEqual(output, b'OK\n')

    def test_token_lock_is_bounded_and_released(self):
        path = self.temporary.name + '/token.lock'
        with key_sockets.token_lock(path):
            with self.assertRaises(TimeoutError):
                with key_sockets.token_lock(path, timeout=.05):
                    self.fail('Concurrent token access')
        with key_sockets.token_lock(path, timeout=.05):
            pass


class FakeLuks:
    def __init__(self):
        self.headers = {device: dict(keyslots={'0': {'original': device}}, tokens={})
                        for device in ['/dev/test-a', '/dev/test-b']}
        self.uuids = {device: str(uuid.uuid4()) for device in self.headers}
        self.writes = []
        self.fail_device = None

    def run(self, *args, data=None):
        action = args[1]
        device = args[-2] if action == 'luksAddKey' else args[-1]
        if action == 'luksUUID':
            return self.uuids[device].encode()
        if action == 'luksDump':
            return json.dumps(self.headers[device]).encode()
        if action == 'open':
            return b''
        if action == 'luksAddKey':
            if device == self.fail_device:
                raise RuntimeError('Injected write failure')
            recovery = Path(args[args.index('--key-file') + 1])
            assert recovery.stat().st_mode & 0o777 == 0o600
            assert recovery.read_bytes() == b'recovery'
            self.writes.append((device, data))
            self.headers[device]['keyslots'][args[args.index('--key-slot') + 1]] = {'new': True}
            return b''
        raise AssertionError('Unexpected mutation')


class EnrollmentTests(unittest.TestCase):
    def setUp(self):
        self.luks = FakeLuks()
        self.targets = [dict(device=device, slot=1, recovery_slot=0, recovery=b'recovery')
                        for device in self.luks.headers]

    def test_same_key_on_both_preserves_recovery(self):
        before = copy.deepcopy(self.luks.headers)
        prepared = enrollment.preflight(self.targets, self.luks.run)
        self.assertEqual(self.luks.writes, [])
        with tempfile.TemporaryDirectory() as directory:
            enrollment.install(prepared, b'shared-derived-key', self.luks.run, directory)
        self.assertEqual(self.luks.writes,
            [('/dev/test-a', b'shared-derived-key'), ('/dev/test-b', b'shared-derived-key')])
        for device in before:
            self.assertEqual(self.luks.headers[device]['keyslots']['0'], before[device]['keyslots']['0'])

    def test_occupied_second_slot_rejected_before_any_write(self):
        self.luks.headers['/dev/test-b']['keyslots']['1'] = {'occupied': True}
        with self.assertRaises(ValueError):
            enrollment.preflight(self.targets, self.luks.run)
        self.assertEqual(self.luks.writes, [])

    def test_duplicate_volume_alias_is_rejected(self):
        self.luks.uuids['/dev/test-b'] = self.luks.uuids['/dev/test-a']
        with self.assertRaises(ValueError):
            enrollment.preflight(self.targets, self.luks.run)
        self.assertEqual(self.luks.writes, [])

    def test_metadata_change_during_touch_rejected_before_writes(self):
        prepared = enrollment.preflight(self.targets, self.luks.run)
        self.luks.headers['/dev/test-b']['tokens']['unexpected'] = {}
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(RuntimeError):
                enrollment.install(prepared, b'key', self.luks.run, directory)
        self.assertEqual(self.luks.writes, [])

    def test_partial_write_failure_preserves_old_slots_and_stops(self):
        prepared = enrollment.preflight(self.targets, self.luks.run)
        self.luks.fail_device = '/dev/test-b'
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(RuntimeError):
                enrollment.install(prepared, b'key', self.luks.run, directory)
        self.assertEqual(set(self.luks.headers['/dev/test-a']['keyslots']), {'0', '1'})
        self.assertEqual(set(self.luks.headers['/dev/test-b']['keyslots']), {'0'})
        self.assertEqual(len(self.luks.writes), 1)


if __name__ == '__main__':
    unittest.main()
