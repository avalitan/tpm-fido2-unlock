"""Pinned FIDO identities. Public bootstrap credentials never contain unlock salts."""
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import threading

from cryptography.hazmat.primitives.asymmetric import ec
from fido2 import cbor
from fido2.cose import CoseKey
from fido2.ctap2 import Ctap2
from fido2.ctap2.pin import ClientPin
from fido2.hid import open_device

DOMAIN = b'tpm-fido2-unlock/identity/v1\0'


def encode(value):
    return base64.b64encode(value).decode('ascii')


def decode(value):
    if not isinstance(value, str):
        raise ValueError('Expected base64 text')
    return base64.b64decode(value, validate=True)


def relying_party(value):
    if (not isinstance(value, str) or not 1 <= len(value) <= 253
        or any(c in value for c in '\r\n\0')):
        raise ValueError('Invalid relying party')
    return value


def public_key(value):
    raw = decode(value)
    if len(raw) > 256:
        raise ValueError('Oversized public key')
    key = cbor.decode(raw)
    # Pin ES256, available on both Solo and YubiKey; no algorithm downgrade.
    if (not isinstance(key, dict) or set(key) != {1, 3, -1, -2, -3}
        or key[1] != 2 or key[3] != -7 or key[-1] != 1
        or not isinstance(key[-2], bytes) or len(key[-2]) != 32
        or not isinstance(key[-3], bytes) or len(key[-3]) != 32
        or cbor.encode(key) != raw):
        raise ValueError('Expected canonical ES256 public key')
    ec.EllipticCurvePublicNumbers(int.from_bytes(key[-2], 'big'),
        int.from_bytes(key[-3], 'big'), ec.SECP256R1()).public_key()
    return CoseKey.parse(key)


def validate_identity(record):
    if (not isinstance(record, dict)
        or set(record) != {'version', 'rp', 'credential', 'public_key', 'presence'}
        or type(record['version']) is not int or record['version'] != 1
        or type(record['presence']) is not bool):
        raise ValueError('Unsupported identity record')
    relying_party(record['rp'])
    if not 1 <= len(decode(record['credential'])) <= 1024:
        raise ValueError('Invalid identity credential')
    public_key(record['public_key'])


def fingerprint(record):
    validate_identity(record)
    return hashlib.sha256(json.dumps(record, sort_keys=True,
        separators=(',', ':')).encode()).hexdigest()


def validate_policy(policy):
    if (not isinstance(policy, dict) or set(policy) != {'version', 'keys'}
        or type(policy['version']) is not int or policy['version'] != 1
        or not isinstance(policy['keys'], list) or not 1 <= len(policy['keys']) <= 16):
        raise ValueError('Expected a nonempty identity allowlist (maximum 16)')
    names, identities = set(), set()
    for entry in policy['keys']:
        if not isinstance(entry, dict) or set(entry) != {'name', 'identity', 'bundle'}:
            raise ValueError('Invalid identity policy entry')
        name = entry['name']
        if (not isinstance(name, str) or not 1 <= len(name) <= 64
            or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-' for c in name)
            or name in names):
            raise ValueError('Invalid or duplicate key name')
        bundle = entry['bundle']
        if not isinstance(bundle, str) or not bundle.startswith('/') or any(c in bundle for c in '\r\n\0'):
            raise ValueError('Expected an absolute runtime bundle path')
        digest = fingerprint(entry['identity'])
        if digest in identities:
            raise ValueError('Duplicate verification identity')
        names.add(name)
        identities.add(digest)


def read_json(path):
    with Path(path).open('rb') as handle:
        raw = handle.read(262145)
    if len(raw) > 262144:
        raise ValueError('Oversized identity file')
    return json.loads(raw)


def challenge(purpose, binding=b''):
    return hashlib.sha256(DOMAIN + purpose + b'\0' + binding + secrets.token_bytes(32)).digest()


def verify_assertion(response, record, digest, presence):
    expected = decode(record['credential'])
    credential = response.credential
    if (not isinstance(credential, dict) or credential.get('type') != 'public-key'
        or credential.get('id') != expected
        or response.number_of_credentials not in (None, 1)
        or response.auth_data.rp_id_hash != hashlib.sha256(record['rp'].encode()).digest()
        or (presence and not response.auth_data.is_user_present())
        or response.auth_data.is_attested()):
        raise ValueError('Assertion does not match enrolled credential/policy')
    response.verify(digest, public_key(record['public_key']))


class Token:
    """One open HID connection for proof and unlock; errors never reopen it."""

    def __init__(self, path):
        self._proven = None
        self.device = open_device(os.fsencode(path))
        try:
            self.ctap = Ctap2(self.device)
        except Exception:
            self.device.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self._proven = None
        self.device.close()

    def call(self, operation, *args, **kwargs):
        cancel = threading.Event()
        timer = threading.Timer(20, cancel.set)
        timer.daemon = True
        timer.start()
        try:
            return operation(*args, event=cancel, **kwargs)
        finally:
            timer.cancel()

    def prove(self, record):
        self._proven = None
        validate_identity(record)
        digest = challenge(b'proof', bytes.fromhex(fingerprint(record)))
        response = self.call(self.ctap.get_assertion, record['rp'], digest,
            allow_list=[{'type': 'public-key', 'id': decode(record['credential'])}],
            options={'up': record['presence'], 'uv': False})
        verify_assertion(response, record, digest, record['presence'])
        self._proven = fingerprint(record)

    def create(self, rp, hmac_secret=False):
        relying_party(rp)
        digest = challenge(b'enroll')
        response = self.call(self.ctap.make_credential, digest,
            {'id': rp, 'name': 'TPM FIDO2 unlock'},
            {'id': secrets.token_bytes(32), 'name': 'encrypted-volume'},
            [{'type': 'public-key', 'alg': -7}],
            options={'rk': False, 'uv': False},
            extensions={'hmac-secret': True} if hmac_secret else None)
        data = response.auth_data
        if (data.rp_id_hash != hashlib.sha256(rp.encode()).digest()
            or not data.is_user_present() or not data.credential_data
            or (hmac_secret and (data.extensions or {}).get('hmac-secret') is not True)):
            raise ValueError('Unexpected credential creation response')
        record = dict(version=1, rp=rp, presence=False,
            credential=encode(data.credential_data.credential_id),
            public_key=encode(cbor.encode(dict(data.credential_data.public_key))))
        validate_identity(record)
        return record

    def unlock(self, params):
        proven, self._proven = getattr(self, '_proven', None), None
        if (not proven or params.get('identity') != proven or params.get('version') != 2
            or (params.get('presence'), params.get('pin'), params.get('uv')) != (True, False, False)):
            raise ValueError('Unlock requires an unused matching identity proof')
        record = dict(version=1, rp=params['rp'], presence=True,
            credential=params['credential'], public_key=params['public_key'])
        validate_identity(record)
        client = ClientPin(self.ctap)
        # Public APIs: getKeyAgreement, then the library's encapsulation/encryption.
        peer = self.call(self.ctap.client_pin, client.protocol.VERSION,
                         ClientPin.CMD.GET_KEY_AGREEMENT)[ClientPin.RESULT.KEY_AGREEMENT]
        agreement, shared = client.protocol.encapsulate(peer)
        salt = decode(params['salt'])
        if len(salt) != 32:
            raise ValueError('Invalid unlock salt')
        encrypted = client.protocol.encrypt(shared, salt)
        extension = {1: agreement, 2: encrypted,
                     3: client.protocol.authenticate(shared, encrypted),
                     4: client.protocol.VERSION}
        digest = challenge(b'unlock')
        response = self.call(self.ctap.get_assertion, record['rp'], digest,
            allow_list=[{'type': 'public-key', 'id': decode(record['credential'])}],
            options={'up': True, 'uv': False}, extensions={'hmac-secret': extension})
        # The encrypted hmac-secret output is part of the signed authenticator data.
        verify_assertion(response, record, digest, True)
        output = (response.auth_data.extensions or {}).get('hmac-secret')
        if not isinstance(output, bytes):
            raise ValueError('Missing hmac-secret output')
        secret = client.protocol.decrypt(shared, output)
        if len(secret) != 32:
            raise ValueError('Unexpected hmac-secret length')
        return encode(secret).encode('ascii')


def unlock_with_policy(policy, token, recover):
    """recover(entry) must only run after this entry's fresh identity proof."""
    validate_policy(policy)
    for entry in policy['keys']:
        try:
            token.prove(entry['identity'])
        except Exception:
            # Try only explicitly enrolled identities, never an unguarded path.
            continue
        params = recover(entry)
        if (params.get('version') != 2
            or params.get('identity') != fingerprint(entry['identity'])):
            raise ValueError('Sealed parameters belong to a different identity')
        return token.unlock(params)
    raise ValueError('No approved identity proved possession')
