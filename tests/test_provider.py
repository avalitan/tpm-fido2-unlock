#!/usr/bin/env python3
"""Exercise the actual boot-provider TPM code using a fresh, private simulator."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from cryptography.exceptions import InvalidTag
from tpm2_pytss import ESAPI, ESYS_TR, TPM2_ALG, TPML_DIGEST_VALUES, TPMT_HA, TPMU_HA, TSS2_Exception

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import management
import provider


def main():
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix='boot-provider-', dir='/dev/shm') as directory:
        root = Path(directory)
        (root / 'state').mkdir()
        address = str(root / 'socket')
        proc = subprocess.Popen(['swtpm', 'socket', '--tpm2', '--tpmstate', f'dir={root}/state',
            '--server', f'type=unixio,path={address}', '--ctrl', f'type=unixio,path={address}.ctrl',
            '--flags', 'not-need-init,startup-clear'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            for _ in range(100):
                if Path(address).is_socket():
                    break
                time.sleep(.05)
            tcti = f'swtpm:path={address}'
            with ESAPI(tcti) as tpm:
                owner = os.urandom(32)
                index, parent = management.initialize(tpm, owner)
                params = dict(version=1, presence=True, pin=False, uv=False,
                              rp='nixos-trial.epoch-test', credential=provider.encode(os.urandom(70)),
                              salt=provider.encode(os.urandom(32)))
                authority = management.new_authority()
                bundle = management.seal(tpm, index, parent, params, authority)
            for _ in range(5):
                assert provider.recover_parameters(bundle, tcti) == params
            print('PASS: actual provider repeatedly unseals without global TPM flushes.', flush=True)
            corrupted = dict(bundle, envelope=provider.encode(bytes(32)))
            try:
                provider.recover_parameters(corrupted, tcti)
            except InvalidTag:
                pass
            else:
                raise RuntimeError('Unauthenticated envelope accepted')
            with ESAPI(tcti) as tpm:
                index = tpm.tr_from_tpmpublic(management.INDEX)
                tpm.tr_set_auth(ESYS_TR.OWNER, owner)
                tpm.nv_increment(index, auth_handle=ESYS_TR.OWNER)
            try:
                provider.recover_parameters(bundle, tcti)
            except TSS2_Exception as error:
                if error.rc & 0xfff != 0x126:
                    raise
            else:
                raise RuntimeError('Old epoch accepted')
            with ESAPI(tcti) as tpm:
                index = tpm.tr_from_tpmpublic(management.INDEX)
                parent = tpm.tr_from_tpmpublic(management.PARENT)
                bundle = management.seal(tpm, index, parent, params, authority)
            assert provider.recover_parameters(bundle, tcti) == params
            print('PASS: actual provider rejects tampering and revoked epoch; new epoch works.', flush=True)
            with ESAPI(tcti) as tpm:
                tpm.pcr_extend(ESYS_TR.PCR11, TPML_DIGEST_VALUES(digests=[TPMT_HA(hashAlg=TPM2_ALG.SHA256,
                    digest=TPMU_HA(sha256=provider.CLOSED))]))
            try:
                provider.recover_parameters(bundle, tcti)
            except TSS2_Exception as error:
                if error.rc & 0xfff != 0x1c4:
                    raise
            else:
                raise RuntimeError('Phase closure did not block unsealing')
            print('PASS: closing PCR11 prevents later unsealing.', flush=True)
            # Predict a future UKI state, approve BEFORE extending, then boot it.
            import hashlib
            with ESAPI(tcti) as tpm:
                index = tpm.tr_from_tpmpublic(management.INDEX)
                parent = tpm.tr_from_tpmpublic(management.PARENT)
                uki = management.seal(tpm, index, parent, params, authority,
                                      'sha256:4,7,11', 'uki')
                future4 = hashlib.sha256(bytes(32) + bytes([42]) * 32).digest()
                current11 = hashlib.sha256(bytes(32) + provider.CLOSED).digest()
                expected = hashlib.sha256(future4 + bytes(32) + current11).digest()
                management.approve(tpm, uki, authority, expected)
            try:
                provider.recover_parameters(uki, tcti)
            except ValueError:
                pass
            else:
                raise RuntimeError('Unapproved UKI state accepted')
            with ESAPI(tcti) as tpm:
                tpm.pcr_extend(ESYS_TR.PCR4, TPML_DIGEST_VALUES(digests=[
                    TPMT_HA(hashAlg=TPM2_ALG.SHA256, digest=TPMU_HA(sha256=bytes([42]) * 32))]))
            assert provider.recover_parameters(uki, tcti) == params
            print('PASS: pre-approved future UKI measurements unlock only after matching PCR extension.', flush=True)
            with ESAPI(tcti) as tpm:
                index = tpm.tr_from_tpmpublic(management.INDEX)
                tpm.tr_set_auth(ESYS_TR.OWNER, owner)
                tpm.nv_increment(index, auth_handle=ESYS_TR.OWNER)
            try:
                provider.recover_parameters(uki, tcti)
            except TSS2_Exception as error:
                if error.rc & 0xfff != 0x126:
                    raise
            else:
                raise RuntimeError('Revoked UKI epoch accepted')
            with ESAPI(tcti) as tpm:
                index = tpm.tr_from_tpmpublic(management.INDEX)
                parent = tpm.tr_from_tpmpublic(management.PARENT)
                uki = management.seal(tpm, index, parent, params, authority, 'sha256:4,7,11', 'uki')
                management.approve(tpm, uki, authority, expected)
                tpm.pcr_extend(ESYS_TR.PCR15, TPML_DIGEST_VALUES(digests=[
                    TPMT_HA(hashAlg=TPM2_ALG.SHA256, digest=TPMU_HA(sha256=provider.CLOSED))]))
                # Even an authority signature for current PCR4/7/11 cannot
                # override the mandatory zero-PCR15 guard outside Authorize.
                management.approve(tpm, uki, authority)
            try:
                provider.recover_parameters(uki, tcti)
            except TSS2_Exception as error:
                if error.rc & 0xfff != 0x1c4:
                    raise
            else:
                raise RuntimeError('UKI late-phase authorization bypassed')
            print('PASS: UKI epoch revocation and mandatory PCR15 phase closure block unsealing.', flush=True)
        finally:
            proc.terminate()
            proc.wait(timeout=5)


if __name__ == '__main__':
    main()
