#!/usr/bin/env python3
"""Opt-in trial-only two-volume shared-key test; private swtpm, disposable loops."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time

from cryptography.hazmat.primitives import serialization
from tpm2_pytss import ESAPI

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import identity
import key_sockets
import management
import provider
from smoke_identity_vm import run


def main():
    if socket.gethostname() != 'nixos-trial' or os.geteuid() != 0:
        raise SystemExit('Only run as root inside the disposable nixos-trial VM')
    os.umask(0o077)
    token_path = provider.select_token()
    if 'CanoKey' not in run('fido2-token', '-L').decode():
        raise SystemExit('Expected trial CanoKey emulator')
    with tempfile.TemporaryDirectory(prefix='shared-smoke-', dir='/var/tmp') as directory:
        root = Path(directory)
        (root / 'state').mkdir()
        address = str(root / 'tpm')
        proc = subprocess.Popen(['swtpm', 'socket', '--tpm2', '--tpmstate', f'dir={root}/state',
            '--server', f'type=unixio,path={address}', '--ctrl', f'type=unixio,path={address}.ctrl',
            '--flags', 'not-need-init,startup-clear'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        loops, recoveries, originals = [], [], []
        try:
            for _ in range(100):
                if Path(address).is_socket():
                    break
                time.sleep(.05)
            tcti = f'swtpm:path={address}'
            with ESAPI(tcti) as tpm:
                management.initialize(tpm, os.urandom(32))
            authority = management.new_authority()
            authority_file = root / 'authority.pem'
            authority_file.write_bytes(authority.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            for number in range(2):
                image = root / f'disk-{number}.img'
                with image.open('wb') as handle:
                    handle.truncate(64 * 1024 * 1024)
                loop = run('losetup', '--find', '--show', str(image)).decode().strip()
                loops.append(loop)
                recovery = root / f'recovery-{number}'
                recovery.write_bytes(os.urandom(32))
                recoveries.append(recovery)
                run('cryptsetup', 'luksFormat', '--batch-mode', '--type', 'luks2', '--pbkdf', 'pbkdf2',
                    '--pbkdf-force-iterations', '1000', '--key-file', str(recovery), loop)
                originals.append(json.loads(run('cryptsetup', 'luksDump', '--dump-json-metadata', loop)))
            cli = [sys.executable, str(Path(__file__).resolve().parents[1] / 'src/manage.py'), '--tcti', tcti]
            for primary_slot, extra_slot, name in [(1, 3, 'primary'), (2, 4, 'backup')]:
                public = root / (name + '-public.json')
                bundle = root / (name + '-bundle.json')
                run(*cli, 'identity-enroll', '--output', str(public), '--fido2-device', token_path)
                run(*cli, 'enroll', '--device', loops[0], '--slot', str(primary_slot),
                    '--recovery-key-file', str(recoveries[0]), '--authority', str(authority_file),
                    '--bundle', str(bundle), '--identity', str(public), '--fido2-device', token_path,
                    '--additional-volume', loops[1], str(extra_slot), '0', str(recoveries[1]))
                policy = dict(version=1, keys=[dict(name=name,
                    identity=identity.read_json(public), bundle=str(bundle))])
                listeners = []
                workers, errors, calls = [], [], []

                def consume(number, slot):
                    try:
                        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                            client.settimeout(60)
                            client.connect(str(root / f'{name}-{number}.sock'))
                            key = b''
                            while chunk := client.recv(256):
                                key += chunk
                            run('cryptsetup', 'open', '--test-passphrase', '--key-slot', str(slot),
                                '--key-file', '-', loops[number], data=key)
                    except Exception as error:
                        errors.append(error)

                def produce():
                    calls.append('proof-and-touch')
                    with key_sockets.token_lock(str(root / 'token.lock')):
                        with identity.Token(token_path) as token:
                            return identity.unlock_with_policy(policy, token,
                                lambda entry: provider.recover_parameters(provider.read_bundle(entry['bundle']), tcti))

                try:
                    for number, slot in enumerate([primary_slot, extra_slot]):
                        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                        listener.bind(str(root / f'{name}-{number}.sock'))
                        listener.listen(1)
                        listeners.append(listener)
                        worker = threading.Thread(target=consume, args=(number, slot), daemon=True)
                        worker.start()
                        workers.append(worker)
                    key_sockets.serve(listeners, produce, timeout=60)
                    for worker in workers:
                        worker.join(60)
                        assert not worker.is_alive()
                    assert not errors, [type(error).__name__ for error in errors]
                    assert calls == ['proof-and-touch']
                    print(f'PASS: {name}: one identity proof/derivation unlocks both disposable disks.', flush=True)
                finally:
                    for listener in listeners:
                        listener.close()
            # Real preflight rejection: secondary slot3 is already occupied.
            before = [json.loads(run('cryptsetup', 'luksDump', '--dump-json-metadata', loop)) for loop in loops]
            rejected = root / 'must-not-exist.json'
            result = subprocess.run([*cli, 'enroll', '--device', loops[0], '--slot', '5',
                '--recovery-key-file', str(recoveries[0]), '--authority', str(authority_file),
                '--bundle', str(rejected), '--identity', str(root / 'primary-public.json'),
                '--additional-volume', loops[1], '3', '0', str(recoveries[1])], capture_output=True, timeout=60)
            assert result.returncode != 0 and not rejected.exists()
            for number, loop in enumerate(loops):
                after = json.loads(run('cryptsetup', 'luksDump', '--dump-json-metadata', loop))
                assert after == before[number]
                assert after['keyslots']['0'] == originals[number]['keyslots']['0']
                assert after['tokens'] == originals[number]['tokens']
                run('cryptsetup', 'open', '--test-passphrase', '--key-slot', '0',
                    '--key-file', str(recoveries[number]), loop)
            print('PASS: occupied second-volume slot rejected before writes; both independent recovery keys work.', flush=True)
        finally:
            try:
                for loop in reversed(loops):
                    run('losetup', '--detach', loop)
            finally:
                proc.terminate()
                proc.wait(timeout=5)


if __name__ == '__main__':
    main()
