"""Close the experimental zero-PCR11 boot phase before switch-root."""
import hashlib
from tpm2_pytss import ESAPI, ESYS_TR, TPM2_ALG, TPML_DIGEST_VALUES, TPMT_HA, TPMU_HA


def main():
    with ESAPI('device:/dev/tpmrm0') as tpm:
        tpm.pcr_extend(ESYS_TR.PCR11, TPML_DIGEST_VALUES(digests=[
            TPMT_HA(hashAlg=TPM2_ALG.SHA256, digest=TPMU_HA(
                sha256=hashlib.sha256(b'nixos-trial/combined-unlock/closed/v1').digest()))]))


if __name__ == '__main__':
    main()
