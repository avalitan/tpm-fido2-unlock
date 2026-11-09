#!/usr/bin/env python3
"""Actual provider epoch-set/crash-resume tests on an exclusively owned swtpm."""
import copy
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from tpm2_pytss import (ESAPI, ESYS_TR, TPM2_ALG, TPML_DIGEST_VALUES,
                       TPMT_HA, TPMU_HA, TSS2_Exception)

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import management
import provider


def denied(operation, code=None):
    try:
        operation()
    except TSS2_Exception as error:
        if code is None or error.rc & 0xfff != code:
            raise
    except ValueError:
        if code is not None:
            raise
    else:
        raise RuntimeError('Operation unexpectedly accepted')


def main():
    with tempfile.TemporaryDirectory(prefix='epoch-transition-', dir='/dev/shm') as directory:
        root = Path(directory)
        (root / 'state').mkdir()
        address = str(root / 'socket')
        process = subprocess.Popen(['swtpm', 'socket', '--tpm2', '--tpmstate', f'dir={root}/state',
            '--server', f'type=unixio,path={address}', '--ctrl', f'type=unixio,path={address}.ctrl',
            '--flags', 'not-need-init,startup-clear'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            for _ in range(100):
                if Path(address).is_socket():
                    break
                time.sleep(.05)
            tcti = f'swtpm:path={address}'
            owner = os.urandom(32)
            authority = management.new_authority()
            old_params = dict(version=1, presence=True, pin=False, uv=False, rp='epoch.test',
                              salt=provider.encode(os.urandom(32)), credential=provider.encode(os.urandom(70)))
            new_params = dict(old_params, salt=provider.encode(os.urandom(32)))
            with ESAPI(tcti) as tpm:
                index, parent = management.initialize(tpm, owner)
                previous = int.from_bytes(bytes(tpm.nv_read(index, 8)), 'big')
                old = management.seal(tpm, index, parent, old_params, authority, 'sha256:4,7,11', 'uki')
                future = management.seal(tpm, index, parent, new_params, authority, 'sha256:4,7,11', 'uki', previous + 1)
                management.approve(tpm, old, authority)
                management.approve(tpm, future, authority)
                denied(lambda: management.seal(tpm, index, parent, new_params, authority,
                                               'sha256:4,7,11', 'uki', previous + 2))
            denied(lambda: provider.recover_parameters(future, tcti), 0x126)
            denied(lambda: management.epoch_set(old, dict(future, index=future['index'] + 1)))
            denied(lambda: management.epoch_set(old, dict(future, approvals=[])))
            staged = management.epoch_set(old, future)
            assert provider.recover_parameters(staged, tcti) == old_params
            # An interrupted stage has no effect on the existing current bundle.
            assert provider.recover_parameters(old, tcti) == old_params
            print('PASS: both epochs staged; current unlocks, future and incomplete/mismatched staging rejected.', flush=True)
            with ESAPI(tcti) as tpm:
                index = tpm.tr_from_tpmpublic(management.INDEX)
                denied(lambda: management.advance_epoch(tpm, index, previous, previous + 1, bytes(32)), 0x9a2)
                assert int.from_bytes(bytes(tpm.nv_read(index, 8)), 'big') == previous
                assert management.advance_epoch(tpm, index, previous, previous + 1, owner)
            assert provider.recover_parameters(staged, tcti) == new_params
            denied(lambda: provider.recover_parameters(old, tcti), 0x126)
            replay = dict(staged, bundles={str(previous): old})
            denied(lambda: provider.recover_parameters(replay, tcti))
            wrong = copy.deepcopy(staged)
            wrong['bundles'][str(previous + 1)]['epoch'] = previous
            denied(lambda: provider.recover_parameters(wrong, tcti))
            with ESAPI(tcti) as tpm:
                index = tpm.tr_from_tpmpublic(management.INDEX)
                assert not management.advance_epoch(tpm, index, previous, previous + 1, owner)
                assert int.from_bytes(bytes(tpm.nv_read(index, 8)), 'big') == previous + 1
            print('PASS: commit switches to new secret; old bundles/replay rejected; crash-resume never increments twice.', flush=True)
            with ESAPI(tcti) as tpm:
                tpm.pcr_extend(ESYS_TR.PCR15, TPML_DIGEST_VALUES(digests=[
                    TPMT_HA(hashAlg=TPM2_ALG.SHA256, digest=TPMU_HA(sha256=provider.CLOSED))]))
            denied(lambda: provider.recover_parameters(staged, tcti), 0x1c4)
            print('PASS: epoch-set routing preserves mandatory phase closure.', flush=True)
        finally:
            process.terminate()
            process.wait(timeout=5)


if __name__ == '__main__':
    main()
