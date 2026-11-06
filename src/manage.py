"""Explicit enrollment and approval; never installed in the initrd."""
import argparse
import getpass
import json
import os
from pathlib import Path
import secrets
import tempfile

from cryptography.hazmat.primitives import serialization
from tpm2_pytss import ESAPI, TPM2_CAP

import management
import provider


def atomic_bundle(path, bundle):
    temporary = path.with_name(path.name + '.new')
    with temporary.open('x') as handle:
        handle.write(json.dumps(bundle) + '\n')
        handle.flush()
        os.fsync(handle.fileno())
    temporary.replace(path)
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def load_authority(path):
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument('--tcti', default='device:/dev/tpmrm0')
    sub = result.add_subparsers(dest='command', required=True)
    keygen = sub.add_parser('keygen', help='Create a new approval private key; never overwrites')
    keygen.add_argument('--authority', type=Path, required=True)
    provision = sub.add_parser('provision', help='Reserve a counter/parent using EXISTING protected owner auth')
    provision.add_argument('--owner-auth-file', type=Path, required=True)
    provision.add_argument('--index', type=lambda value: int(value, 0), default=management.INDEX)
    provision.add_argument('--parent', type=lambda value: int(value, 0), default=management.PARENT)
    enroll = sub.add_parser('enroll', help='Add a new combined LUKS slot; preserve all existing slots')
    enroll.add_argument('--device', required=True)
    enroll.add_argument('--slot', type=int, required=True)
    enroll.add_argument('--recovery-slot', type=int, default=0)
    enroll.add_argument('--recovery-key-file', type=Path)
    enroll.add_argument('--bundle', type=Path, required=True)
    enroll.add_argument('--authority', type=Path, required=True)
    enroll.add_argument('--index', type=lambda value: int(value, 0), default=management.INDEX)
    enroll.add_argument('--parent', type=lambda value: int(value, 0), default=management.PARENT)
    enroll.add_argument('--fido2-device', default='auto')
    enroll.add_argument('--rp', default='io.github.tpm-fido2-unlock')
    enroll.add_argument('--pcrs', default=provider.PCRS)
    enroll.add_argument('--profile', choices=['legacy', 'uki'], default='legacy')
    approve = sub.add_parser('approve', help='Explicitly sign the current measured state in the bundle epoch')
    approve.add_argument('--bundle', type=Path, required=True)
    approve.add_argument('--authority', type=Path, required=True)
    approve.add_argument('--expected-pcrs', type=Path, help='JSON map of expected SHA256 PCR values, from trusted artifacts')
    return result


def main():
    args = parser().parse_args()
    os.umask(0o077)
    if args.command == 'keygen':
        key = management.new_authority()
        with args.authority.open('xb') as handle:
            handle.write(key.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        print('Created approval key. Keep it outside the initrd and Nix store.')
        return
    if os.geteuid():
        raise SystemExit('TPM and LUKS management requires root')
    if args.command == 'provision':
        if not 0x01000000 <= args.index <= 0x01ffffff or not 0x81000000 <= args.parent <= 0x817fffff:
            raise ValueError('Invalid reserved handle range')
        owner = args.owner_auth_file.read_bytes()
        if len(owner) != 32:
            raise ValueError('Supply an existing protected owner authorization of exactly 32 bytes')
        with ESAPI(args.tcti) as tpm:
            for wanted in [args.index, args.parent]:
                _, capability = tpm.get_capability(TPM2_CAP.HANDLES, wanted, 1)
                if wanted in list(capability.data.handles):
                    raise RuntimeError('Reserved handle occupied; refusing replacement')
            management.provision(tpm, owner, args.index, args.parent)
        print('Reserved counter and storage parent; owner authorization was not changed.')
        return
    authority = load_authority(args.authority)
    if args.command == 'approve':
        bundle = provider.read_bundle(args.bundle)
        with ESAPI(args.tcti) as tpm:
            index = tpm.tr_from_tpmpublic(bundle['index'])
            epoch = int.from_bytes(bytes(tpm.nv_read(index, 8)), 'big')
            if epoch != bundle['epoch']:
                raise RuntimeError('Bundle epoch is revoked; approval cannot repair it')
            if authority.public_key().public_bytes(serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo).decode() != bundle['authority']:
                raise RuntimeError('Approval key does not match enrollment authority')
            expected = None
            if args.expected_pcrs:
                if bundle['version'] != 2 or bundle['pcrs'] != 'sha256:4,7,11':
                    raise ValueError('Expected-PCR approval requires the UKI v2 profile')
                values = json.loads(args.expected_pcrs.read_text())
                if set(values) != {'4', '7', '11'}:
                    raise ValueError('Expected exactly PCRs 4, 7 and 11')
                raw = [bytes.fromhex(values[str(n)]) for n in (4, 7, 11)]
                if any(len(value) != 32 for value in raw):
                    raise ValueError('Expected SHA256 PCR values')
                import hashlib
                expected = hashlib.sha256(b''.join(raw)).digest()
            elif bundle['version'] == 2:
                raise ValueError('UKI profile requires artifact-derived expected PCRs')
            management.approve(tpm, bundle, authority, expected)
        atomic_bundle(args.bundle, bundle)
        print('Approved measurements explicitly; epoch and LUKS slots unchanged.')
        return
    if not 0 <= args.slot <= 31 or not 0 <= args.recovery_slot <= 31 or args.slot == args.recovery_slot:
        raise ValueError('Choose a distinct free slot in 0–31')
    if not args.device.startswith('/dev/'):
        raise ValueError('Enrollment requires an explicit /dev/ LUKS device')
    if args.bundle.exists() or args.bundle.with_name(args.bundle.name + '.new').exists():
        raise RuntimeError('Bundle already exists; refusing replacement')
    if not args.bundle.parent.is_dir() or str(args.bundle.resolve()).startswith('/nix/store/'):
        raise ValueError('Create a writable runtime bundle directory outside the Nix store')
    before = json.loads(provider.run('cryptsetup', 'luksDump', '--dump-json-metadata', args.device))
    if str(args.slot) in before['keyslots'] or str(args.recovery_slot) not in before['keyslots']:
        raise RuntimeError('New slot is occupied or recovery slot is absent')
    recovery = args.recovery_key_file.read_bytes() if args.recovery_key_file else getpass.getpass('Recovery passphrase: ').encode()
    if not recovery:
        raise ValueError('Empty recovery key')
    provider.run('cryptsetup', 'open', '--test-passphrase', '--key-slot', str(args.recovery_slot),
                 '--key-file', '-', args.device, data=recovery)
    # Validate TPM handles/authority before modifying LUKS. No owner secret is needed to seal.
    with ESAPI(args.tcti) as tpm:
        index = tpm.tr_from_tpmpublic(args.index)
        parent = tpm.tr_from_tpmpublic(args.parent)
        tpm.nv_read(index, 8)
        token = provider.select_token(args.fido2_device)
        template = dict(version=1, presence=True, pin=False, uv=False, rp=args.rp,
                        credential=provider.encode(b'test'), salt=provider.encode(bytes(32)))
        provider.validate_parameters(template)
        request = '\n'.join([provider.encode(secrets.token_bytes(32)), args.rp,
                             'encrypted-volume', provider.encode(secrets.token_bytes(32)), ''])
        attestation = provider.run('fido2-cred', '-M', '-h', '-q', token, data=request.encode())
        verified = provider.run('fido2-cred', '-V', '-h', data=attestation).splitlines()
        params = dict(template, credential=verified[0].decode(), salt=provider.encode(secrets.token_bytes(32)))
        key = provider.derive_key(params, token)
        # Seal before slot mutation; no plaintext wrapping-key artifact is retained.
        bundle = management.seal(tpm, index, parent, params, authority,
                                 'sha256:4,7,11' if args.profile == 'uki' else args.pcrs, args.profile)
        del params
    with tempfile.TemporaryDirectory(prefix='combined-enroll-', dir='/run') as directory:
        recovery_file = Path(directory) / 'recovery'
        recovery_file.write_bytes(recovery)
        provider.run('cryptsetup', 'luksAddKey', '--key-slot', str(args.slot), '--pbkdf', 'pbkdf2',
                     '--pbkdf-force-iterations', '100000', '--key-file', str(recovery_file),
                     args.device, '-', data=key)
    del recovery
    provider.run('cryptsetup', 'open', '--test-passphrase', '--key-slot', str(args.slot),
                 '--key-file', '-', args.device, data=key)
    del key
    atomic_bundle(args.bundle, bundle)
    after = json.loads(provider.run('cryptsetup', 'luksDump', '--dump-json-metadata', args.device))
    if after['tokens'] != before['tokens'] or any(after['keyslots'].get(k) != v for k, v in before['keyslots'].items()):
        raise RuntimeError('Unexpected change to prior slots/token metadata')
    print('Combined slot enrolled and verified; all prior slots preserved. No public FIDO2 token added.')
    print('Boot-test and verify recovery before separately retiring old standalone unlock paths.')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # Never dump credential inputs or subprocess output.
        raise SystemExit(f'Management failed: {type(error).__name__}: {error}')
