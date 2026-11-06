"""Enrollment helpers. This file is deliberately excluded from the boot package."""
import json
import secrets
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from tpm2_pytss import (ESYS_TR, TPM2_ALG, TPM2_ST, TPM2_RH, TPMA_NV, TPMA_OBJECT, TPM2B_NV_PUBLIC,
                       TPMS_NV_PUBLIC, TPM2B_PUBLIC, TPM2B_SENSITIVE_CREATE,
                       TPMS_SENSITIVE_CREATE, TPMT_TK_VERIFIED)
from provider import AAD, PCRS, encode, policy_ref, session, finish_policy

INDEX = 0x01500020
PARENT = 0x81010020


def initialize(tpm, owner_auth):
    """Compatibility helper for a fresh simulator; never used by generic CLI."""
    tpm.hierarchy_change_auth(ESYS_TR.OWNER, owner_auth)
    return provision(tpm, owner_auth)


def provision(tpm, owner_auth, index_handle=INDEX, parent_handle=PARENT):
    """Create reserved objects using existing owner authorization; do not change it."""
    tpm.tr_set_auth(ESYS_TR.OWNER, owner_auth)
    index = tpm.nv_define_space(None, TPM2B_NV_PUBLIC(nvPublic=TPMS_NV_PUBLIC(
        nvIndex=index_handle, nameAlg=TPM2_ALG.SHA256, dataSize=8,
        attributes=TPMA_NV.parse('authread|ownerwrite|nt=1|no_da'))))
    tpm.nv_increment(index, auth_handle=ESYS_TR.OWNER)
    primary, *_ = tpm.create_primary(None, 'ecc', primary_handle=ESYS_TR.OWNER)
    try:
        parent = tpm.evict_control(ESYS_TR.OWNER, primary, parent_handle)
    finally:
        tpm.flush_context(primary)
    return index, parent


def new_authority():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def approve(tpm, bundle, authority):
    auth = session(tpm, trial=True)
    try:
        tpm.policy_pcr(auth, None, bundle.get('pcrs', PCRS))
        digest = bytes(tpm.policy_get_digest(auth))
    finally:
        tpm.flush_context(auth)
    bundle['approved'] = encode(digest)
    bundle['signature'] = encode(authority.sign(digest + policy_ref(bundle['epoch']),
                                               padding.PKCS1v15(), hashes.SHA256()))


def seal(tpm, index, parent, params, authority, pcrs=PCRS):
    epoch = int.from_bytes(bytes(tpm.nv_read(index, 8)), 'big')
    public_key = authority.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    signer = tpm.load_external(TPM2B_PUBLIC.from_pem(public_key), hierarchy=ESYS_TR.OWNER)
    try:
        name = tpm.tr_get_name(signer)
    finally:
        tpm.flush_context(signer)
    auth = session(tpm, trial=True)
    try:
        finish_policy(tpm, auth, name, TPMT_TK_VERIFIED(tag=TPM2_ST.VERIFIED, hierarchy=TPM2_RH.NULL), b'', epoch, index)
        digest = bytes(tpm.policy_get_digest(auth))
    finally:
        tpm.flush_context(auth)
    wrapping_key = secrets.token_bytes(32)
    private, public, *_ = tpm.create(parent,
        TPM2B_SENSITIVE_CREATE(sensitive=TPMS_SENSITIVE_CREATE(data=wrapping_key)),
        TPM2B_PUBLIC.parse('keyedhash', objectAttributes=TPMA_OBJECT.FIXEDTPM | TPMA_OBJECT.FIXEDPARENT,
                          authPolicy=digest))
    nonce = secrets.token_bytes(12)
    envelope = AESGCM(wrapping_key).encrypt(nonce, json.dumps(params).encode(), AAD)
    del wrapping_key
    bundle = dict(version=1, epoch=epoch, parent=int(tpm.tr_get_tpm_handle(parent)),
                  index=int(tpm.tr_get_tpm_handle(index)), pcrs=pcrs,
                  authority=public_key.decode(), public=encode(public.marshal()),
                  private=encode(private.marshal()), nonce=encode(nonce), envelope=encode(envelope))
    approve(tpm, bundle, authority)
    return bundle
