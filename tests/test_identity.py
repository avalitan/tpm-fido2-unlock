#!/usr/bin/env python3
"""Real signatures and simulated hostile CTAP peers; no USB or TPM access."""
import hashlib
import hmac
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest

from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec
from fido2 import cbor
from fido2.cose import ES256
from fido2.ctap2 import AssertionResponse
from fido2.ctap2.pin import PinProtocolV1
from fido2.webauthn import AuthenticatorData

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import identity


def enrolled(label, presence=False):
    key = ec.generate_private_key(ec.SECP256R1())
    record = dict(version=1, rp='test.identity', presence=presence,
        credential=identity.encode(label.encode()),
        public_key=identity.encode(cbor.encode(dict(ES256.from_cryptography_key(key.public_key())))))
    return record, key


class Peer:
    def __init__(self, credentials, attack=None):
        self.credentials = credentials
        self.attack = attack
        self.info = SimpleNamespace(pin_uv_protocols=[1], options={'clientPin': False})
        self.requests = []
        self.previous = None
        self.agreement = ec.generate_private_key(ec.SECP256R1())

    def client_pin(self, *_args, **_kwargs):
        key = dict(ES256.from_cryptography_key(self.agreement.public_key()))
        key[3] = -25
        return {1: key}

    def get_assertion(self, rp, digest, allow_list, options, extensions=None, **_kwargs):
        self.requests.append(dict(rp=rp, digest=digest, allow_list=allow_list, extensions=extensions))
        cid = allow_list[0]['id']
        record, key = self.credentials[cid]  # Unknown key fails before any unlock request.
        if rp != record['rp']:
            raise ValueError('Unknown RP')
        if self.attack == 'replay' and self.previous:
            return self.previous
        output = None
        if extensions:
            ext = extensions['hmac-secret']
            public = ext[1]
            peer = ec.EllipticCurvePublicNumbers(int.from_bytes(public[-2], 'big'),
                int.from_bytes(public[-3], 'big'), ec.SECP256R1()).public_key()
            shared = hashlib.sha256(self.agreement.exchange(ec.ECDH(), peer)).digest()
            protocol = PinProtocolV1()
            if not hmac.compare_digest(protocol.authenticate(shared, ext[2]), ext[3]):
                raise ValueError('Invalid salt authentication')
            salt = protocol.decrypt(shared, ext[2])
            secret = hmac.digest(b'test-token-private-secret', salt, 'sha256')
            output = {'hmac-secret': protocol.encrypt(shared, secret)}
        flags = AuthenticatorData.FLAG.UP if options['up'] else AuthenticatorData.FLAG(0)
        if self.attack == 'no-presence':
            flags = AuthenticatorData.FLAG(0)
        if output is not None:
            flags |= AuthenticatorData.FLAG.ED
        data = AuthenticatorData.create(hashlib.sha256(
            ('wrong.rp' if self.attack == 'wrong-rp' else rp).encode()).digest(),
            flags, 1, extensions=output)
        signature = key.sign(bytes(data) + digest, ec.ECDSA(hashes.SHA256()))
        if self.attack == 'bad-signature' or (self.attack == 'bad-unlock' and extensions):
            signature = signature[:-1] + bytes([signature[-1] ^ 1])
        response = AssertionResponse(
            {'type': 'public-key', 'id': b'other' if self.attack == 'wrong-id' else cid}, data, signature)
        self.previous = response
        return response


def token(peer):
    result = object.__new__(identity.Token)
    result.ctap = peer
    return result


class IdentityTests(unittest.TestCase):
    def setUp(self):
        self.primary, self.primary_key = enrolled('primary')
        self.backup, self.backup_key = enrolled('backup')
        self.unlock_record, self.unlock_key = enrolled('secret-unlock')
        self.policy = dict(version=1, keys=[
            dict(name=name, identity=record, bundle='/test/' + name + '.json')
            for name, record in [('primary', self.primary), ('backup', self.backup)]])
        self.recovered = []

    def peer(self, record=None, key=None, attack=None):
        record = record or self.primary
        key = key or self.primary_key
        return Peer({identity.decode(record['credential']): (record, key),
            identity.decode(self.unlock_record['credential']): (self.unlock_record, self.unlock_key)}, attack)

    def recover(self, entry):
        self.recovered.append(entry['name'])
        return dict(version=2, presence=True, pin=False, uv=False,
            identity=identity.fingerprint(entry['identity']), rp=self.unlock_record['rp'],
            credential=self.unlock_record['credential'], public_key=self.unlock_record['public_key'],
            salt=identity.encode(b'S' * 32))

    def test_primary_and_backup_each_unlock_without_other_key(self):
        for name, record, key in [('primary', self.primary, self.primary_key),
                                   ('backup', self.backup, self.backup_key)]:
            with self.subTest(name=name):
                self.recovered.clear()
                peer = self.peer(record, key)
                result = identity.unlock_with_policy(self.policy, token(peer), self.recover)
                self.assertEqual(result, identity.encode(hmac.digest(
                    b'test-token-private-secret', b'S' * 32, 'sha256')).encode())
                self.assertEqual(self.recovered, [name])
                self.assertIsNone(peer.requests[-2]['extensions'])
                self.assertIn('hmac-secret', peer.requests[-1]['extensions'])

    def test_hostile_responses_cannot_trigger_unseal_or_unlock_request(self):
        for attack in ['bad-signature', 'wrong-rp', 'wrong-id', 'no-presence']:
            with self.subTest(attack=attack):
                record = dict(self.primary, presence=True)
                policy = dict(version=1, keys=[dict(name='primary', identity=record, bundle='/test/root')])
                peer = self.peer(record, attack=attack)
                with self.assertRaises(Exception):
                    identity.unlock_with_policy(policy, token(peer), self.recover)
                self.assertEqual(self.recovered, [])
                self.assertTrue(all(r['extensions'] is None for r in peer.requests))
                self.assertTrue(all(r['allow_list'][0]['id'] != b'secret-unlock' for r in peer.requests))

    def test_another_key_cannot_use_copied_public_identity(self):
        peer = self.peer(self.primary, self.backup_key)
        with self.assertRaises(ValueError):
            identity.unlock_with_policy(self.policy, token(peer), self.recover)
        self.assertEqual(self.recovered, [])
        self.assertTrue(all(r['extensions'] is None for r in peer.requests))

    def test_recorded_success_rejected_for_new_challenge(self):
        peer = self.peer(attack='replay')
        connection = token(peer)
        connection.prove(self.primary)
        first = peer.requests[0]['digest']
        with self.assertRaises(ValueError):
            identity.unlock_with_policy(self.policy, connection, self.recover)
        self.assertNotEqual(first, peer.requests[1]['digest'])
        self.assertEqual(self.recovered, [])
        self.assertTrue(all(r['extensions'] is None for r in peer.requests))

    def test_reconnect_requires_new_proof(self):
        peer = self.peer()
        token(peer).prove(self.primary)
        replay = peer.previous
        replacement = self.peer(attack='replay')
        replacement.previous = replay
        with self.assertRaises(ValueError):
            identity.unlock_with_policy(self.policy, token(replacement), self.recover)
        self.assertEqual(self.recovered, [])

    def test_wrong_bundle_binding_and_legacy_payload_never_sent_to_usb(self):
        for patch in [dict(identity=identity.fingerprint(self.backup)), dict(version=1)]:
            with self.subTest(patch=patch):
                peer = self.peer()
                with self.assertRaises(ValueError):
                    identity.unlock_with_policy(self.policy, token(peer),
                        lambda entry: dict(self.recover(entry), **patch))
                self.assertTrue(all(r['extensions'] is None for r in peer.requests))

    def test_unlock_response_signature_is_checked(self):
        with self.assertRaises(InvalidSignature):
            identity.unlock_with_policy(self.policy, token(self.peer(attack='bad-unlock')), self.recover)

    def test_proof_is_required_and_consumed_once(self):
        peer = self.peer()
        connection = token(peer)
        params = self.recover(self.policy['keys'][0])
        with self.assertRaises(ValueError):
            connection.unlock(params)
        self.assertEqual(peer.requests, [])
        connection.prove(self.primary)
        connection.unlock(params)
        count = len(peer.requests)
        with self.assertRaises(ValueError):
            connection.unlock(params)
        self.assertEqual(len(peer.requests), count)

    def test_reject_empty_duplicate_or_algorithm_downgraded_allowlist(self):
        for policy in [dict(version=1, keys=[]),
            dict(version=1, keys=[self.policy['keys'][0]] * 2),
            dict(self.policy, unexpected=True)]:
            with self.assertRaises(ValueError):
                identity.validate_policy(policy)
        key = cbor.decode(identity.decode(self.primary['public_key']))
        key[3] = -257
        with self.assertRaises(ValueError):
            identity.validate_identity(dict(self.primary, public_key=identity.encode(cbor.encode(key))))


if __name__ == '__main__':
    unittest.main()
