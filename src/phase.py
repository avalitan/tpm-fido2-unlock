"""Close the experimental zero-PCR11 boot phase before switch-root."""
import argparse
import hashlib
from tpm2_pytss import ESAPI, ESYS_TR, TPM2_ALG, TPML_DIGEST_VALUES, TPMT_HA, TPMU_HA


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--pcr', choices=['11', '15'], default='11')
    args = parser.parse_args()
    with ESAPI('device:/dev/tpmrm0') as tpm:
        tpm.pcr_extend(ESYS_TR.PCR15 if args.pcr == '15' else ESYS_TR.PCR11, TPML_DIGEST_VALUES(digests=[
            TPMT_HA(hashAlg=TPM2_ALG.SHA256, digest=TPMU_HA(
                sha256=hashlib.sha256(b'nixos-trial/combined-unlock/closed/v1').digest()))]))


if __name__ == '__main__':
    main()
