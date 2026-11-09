#!/usr/bin/env python3
"""Opt-in CanoKey/CLI smoke test: trial VM ONLY, disposable LUKS + private swtpm.

Creates two nonresident bootstrap/unlock credential pairs on the emulator.
Never accesses the installed root disk, system TPM or boot configuration.
"""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time

from cryptography.hazmat.primitives import serialization
from tpm2_pytss import ESAPI

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import identity
import management
import provider


def run(*args, data=None):
    result = subprocess.run(args, input=data, capture_output=True, timeout=90)
    if result.returncode:
        raise RuntimeError(f'{args[0]} failed with status {result.returncode}')
    return result.stdout


def main():
    if socket.gethostname() != 'nixos-trial' or os.geteuid() != 0:
        raise SystemExit('Only run as root inside the disposable nixos-trial VM')
    os.umask(0o077)
    token_path = provider.select_token()
    # Refuse arbitrary physical authenticators, even on a renamed machine.
    if 'CanoKey' not in run('fido2-token', '-L').decode():
        raise SystemExit('Expected the trial CanoKey emulator')
    with tempfile.TemporaryDirectory(prefix='identity-smoke-', dir='/var/tmp') as directory:
        root = Path(directory)
        image = root / 'disposable.img'
        with image.open('wb') as handle:
            handle.truncate(64 * 1024 * 1024)
        recovery = root / 'recovery'
        recovery.write_bytes(os.urandom(32))
        (root / 'state').mkdir()
        address = str(root / 'tpm')
        proc = subprocess.Popen(['swtpm', 'socket', '--tpm2', '--tpmstate', f'dir={root}/state',
            '--server', f'type=unixio,path={address}', '--ctrl', f'type=unixio,path={address}.ctrl',
            '--flags', 'not-need-init,startup-clear'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        loop = None
        try:
            for _ in range(100):
                if Path(address).is_socket():
                    break
                time.sleep(.05)
            tcti = f'swtpm:path={address}'
            authority = management.new_authority()
            authority_file = root / 'authority.pem'
            authority_file.write_bytes(authority.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            with ESAPI(tcti) as tpm:
                management.initialize(tpm, os.urandom(32))
            loop = run('losetup', '--find', '--show', str(image)).decode().strip()
            run('cryptsetup', 'luksFormat', '--batch-mode', '--type', 'luks2',
                '--pbkdf', 'pbkdf2', '--pbkdf-force-iterations', '1000',
                '--key-file', str(recovery), loop)
            before = json.loads(run('cryptsetup', 'luksDump', '--dump-json-metadata', loop))
            cli = [sys.executable, str(Path(__file__).resolve().parents[1] / 'src/manage.py'), '--tcti', tcti]
            entries = []
            for slot, name in [(1, 'primary'), (2, 'backup')]:
                public = root / (name + '-public.json')
                bundle = root / (name + '-bundle.json')
                run(*cli, 'identity-enroll', '--output', str(public), '--fido2-device', token_path)
                run(*cli, 'enroll', '--device', loop, '--slot', str(slot),
                    '--recovery-slot', '0', '--recovery-key-file', str(recovery),
                    '--authority', str(authority_file), '--bundle', str(bundle),
                    '--identity', str(public), '--fido2-device', token_path)
                entries.append(dict(name=name, identity=identity.read_json(public), bundle=str(bundle)))
            policy_file = root / 'policy.json'
            run(*cli, 'identity-policy', '--output', str(policy_file),
                '--key', 'primary', str(root / 'primary-public.json'), entries[0]['bundle'],
                '--key', 'backup', str(root / 'backup-public.json'), entries[1]['bundle'])
            policy = identity.read_json(policy_file)
            for slot, entry in zip((1, 2), entries):
                # Both credentials live on one emulator; put each first to exercise its path.
                selected = dict(policy, keys=[entry] + [e for e in entries if e != entry])
                recovered = []

                def recover(item):
                    recovered.append(item['name'])
                    return provider.recover_parameters(provider.read_bundle(item['bundle']), tcti)

                with identity.Token(token_path) as token:
                    key = identity.unlock_with_policy(selected, token, recover)
                assert recovered == [entry['name']]
                run('cryptsetup', 'open', '--test-passphrase', '--key-slot', str(slot),
                    '--key-file', '-', loop, data=key)
                del key
                print(f'PASS: {entry["name"]} identity proves and unlocks its disposable slot.', flush=True)
            run('cryptsetup', 'open', '--test-passphrase', '--key-slot', '0',
                '--key-file', str(recovery), loop)
            after = json.loads(run('cryptsetup', 'luksDump', '--dump-json-metadata', loop))
            assert after['keyslots']['0'] == before['keyslots']['0']
            assert set(after['keyslots']) == {'0', '1', '2'} and after['tokens'] == before['tokens']
            print('PASS: recovery slot/metadata preserved; no public LUKS tokens added.', flush=True)
        finally:
            if loop:
                run('losetup', '--detach', loop)
            proc.terminate()
            proc.wait(timeout=5)


if __name__ == '__main__':
    main()
