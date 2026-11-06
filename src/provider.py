"""Experimental TPM+FIDO2 key provider. No enrollment or signing capabilities."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from tpm2_pytss import (ESAPI, ESYS_TR, TPM2_ALG, TPM2_CC, TPM2_EO, TPM2_SE,
                       TPM2B_PUBLIC, TPM2B_PRIVATE, TPMT_SIGNATURE)

AAD = b'nixos-trial/fido2-envelope/v1'
PCRS = 'sha256:4,7,9'
PHASE_DIGEST = hashlib.sha256(bytes(32)).digest()
CLOSED = hashlib.sha256(b'nixos-trial/combined-unlock/closed/v1').digest()


def decode(value):
    return base64.b64decode(value, validate=True)


def encode(value):
    return base64.b64encode(value).decode()


def policy_ref(epoch):
    return b'nixos-trial/unseal/v1/epoch/' + epoch.to_bytes(8, 'big')


def run(*args, data=None):
    result = subprocess.run(args, input=data, capture_output=True, timeout=20)
    if result.returncode:
        raise RuntimeError(f'{args[0]} failed')
    return result.stdout


def session(tpm, trial=False):
    return tpm.start_auth_session(ESYS_TR.NONE, ESYS_TR.NONE,
                                 TPM2_SE.TRIAL if trial else TPM2_SE.POLICY,
                                 None, TPM2_ALG.SHA256)


def finish_policy(tpm, auth, signer_name, ticket, approved, epoch, index):
    tpm.policy_authorize(auth, approved, signer_name, ticket, policy_ref(epoch))
    tpm.policy_nv(index, index, auth, epoch.to_bytes(8, 'big'), TPM2_EO.EQ)
    # This mandatory phase check follows PolicyAuthorize too.
    tpm.policy_pcr(auth, PHASE_DIGEST, 'sha256:11')
    tpm.policy_command_code(auth, TPM2_CC.Unseal)


def recover_parameters(bundle, tcti):
    """Return authenticated parameters; flush only handles allocated here."""
    if bundle['version'] != 1:
        raise ValueError('Unsupported bundle version')
    epoch = bundle['epoch']
    ref = policy_ref(epoch)
    approved = decode(bundle['approved'])
    signature = decode(bundle['signature'])
    # TPMT_SIGNATURE: RSASSA + SHA256 + TPM2B_PUBLIC_KEY_RSA.
    sig, consumed = TPMT_SIGNATURE.unmarshal(
        b'\x00\x14\x00\x0b' + len(signature).to_bytes(2, 'big') + signature)
    if consumed != len(signature) + 6:
        raise ValueError('Invalid signature encoding')
    public, _ = TPM2B_PUBLIC.unmarshal(decode(bundle['public']))
    private, _ = TPM2B_PRIVATE.unmarshal(decode(bundle['private']))
    with ESAPI(tcti) as tpm:
        handles = []
        try:
            parent = tpm.tr_from_tpmpublic(bundle['parent'])
            index = tpm.tr_from_tpmpublic(bundle['index'])
            signer = tpm.load_external(TPM2B_PUBLIC.from_pem(bundle['authority'].encode()),
                                       hierarchy=ESYS_TR.OWNER)
            handles.append(signer)
            ticket = tpm.verify_signature(signer, hashlib.sha256(approved + ref).digest(), sig)
            name = tpm.tr_get_name(signer)
            tpm.flush_context(signer)
            handles.remove(signer)
            obj = tpm.load(parent, private, public)
            handles.append(obj)
            auth = session(tpm)
            handles.append(auth)
            tpm.policy_pcr(auth, None, bundle.get('pcrs', PCRS))
            finish_policy(tpm, auth, name, ticket, approved, epoch, index)
            wrapping_key = bytes(tpm.unseal(obj, session1=auth))
            plaintext = AESGCM(wrapping_key).decrypt(decode(bundle['nonce']),
                                                    decode(bundle['envelope']), AAD)
            del wrapping_key
            params = json.loads(plaintext)
            del plaintext
            validate_parameters(params)
            return params
        finally:
            for handle in reversed(handles):
                tpm.flush_context(handle)


def validate_parameters(params):
    if (params.get('version'), params.get('presence'), params.get('pin'), params.get('uv')) != (1, True, False, False):
        raise ValueError('Unsupported interaction settings')
    rp = params.get('rp')
    if not isinstance(rp, str) or not 1 <= len(rp) <= 253 or any(c in rp for c in '\n\r\0'):
        raise ValueError('Invalid relying party')
    if len(decode(params['salt'])) != 32 or not 1 <= len(decode(params['credential'])) <= 1024:
        raise ValueError('Invalid credential parameters')


def derive_key(params, device):
    validate_parameters(params)
    request = '\n'.join([encode(secrets.token_bytes(32)), params['rp'],
                         params['credential'], params['salt'], '']).encode()
    output = run('fido2-assert', '-G', '-h', '-p', '-t', 'pin=false',
                 '-t', 'uv=false', device, data=request).splitlines()
    if len(output) != 5 or len(decode(output[-1])) != 32:
        raise RuntimeError('Unexpected assertion output')
    return output[-1]


def select_token(device='auto'):
    if device != 'auto':
        if not device.startswith('/dev/') or any(c in device for c in '\n\r\0'):
            raise ValueError('Invalid FIDO2 device path')
        return device
    for _ in range(40):
        tokens = run('fido2-token', '-L').decode().splitlines()
        devices = [line.split(':', 1)[0] for line in tokens if line.startswith('/dev/')]
        if len(devices) == 1:
            return devices[0]
        if len(devices) > 1:
            raise RuntimeError('Multiple FIDO2 devices; configure a device explicitly')
        time.sleep(.25)
    raise RuntimeError('FIDO2 device not available')


def read_bundle(path):
    with Path(path).open('rb') as handle:
        raw = handle.read(65537)
    if len(raw) > 65536:
        raise ValueError('Oversized bundle')
    return json.loads(raw)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('bundle')
    parser.add_argument('--socket-activated', action='store_true', required=True)
    parser.add_argument('--device', default='auto', help='FIDO2 device path or auto for exactly one device')
    args = parser.parse_args()
    os.umask(0o077)
    if os.geteuid() != 0:
        raise SystemExit('Requires root')
    try:
        # Only the kernel resource manager, never an environment-selected TPM.
        bundle = read_bundle(args.bundle)
        if args.socket_activated:
            if os.environ.get('LISTEN_PID') != str(os.getpid()) or os.environ.get('LISTEN_FDS') != '1':
                raise RuntimeError('Expected one systemd socket')
            with socket.socket(fileno=3) as listener:
                listener.settimeout(25)
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(5)
                    params = recover_parameters(bundle, 'device:/dev/tpmrm0')
                    key = derive_key(params, select_token(args.device))
                    connection.sendall(key)
                    del key, params
        print('combined-unlock: success', file=sys.stderr)
    except Exception:
        # No tracebacks or subprocess output with credential material in journals.
        print('combined-unlock: unavailable; recovery required', file=sys.stderr)
        raise SystemExit(1)


if __name__ == '__main__':
    main()
