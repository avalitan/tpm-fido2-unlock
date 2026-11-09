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


def approve(tpm, bundle, authority, expected=None):
    auth = session(tpm, trial=True)
    try:
        tpm.policy_pcr(auth, expected, bundle.get('pcrs', PCRS))
        digest = bytes(tpm.policy_get_digest(auth))
    finally:
        tpm.flush_context(auth)
    profile = 'uki' if bundle['version'] == 2 else 'legacy'
    entry = dict(approved=encode(digest), signature=encode(authority.sign(
        digest + policy_ref(bundle['epoch'], profile), padding.PKCS1v15(), hashes.SHA256())))
    if profile == 'uki':
        entries = [item for item in bundle.get('approvals', []) if item['approved'] != entry['approved']]
        if len(entries) >= 16:
            raise ValueError('Approval limit reached; explicitly retire an older approval')
        bundle['approvals'] = entries + [entry]
    else:
        bundle.update(entry)


def seal(tpm, index, parent, params, authority, pcrs=PCRS, profile='legacy', epoch=None):
    current = int.from_bytes(bytes(tpm.nv_read(index, 8)), 'big')
    if epoch is None:
        epoch = current
    if epoch != current and (profile != 'uki' or epoch != current + 1 or epoch >= 2**64):
        raise ValueError('Only the current or immediately next UKI epoch can be sealed')
    public_key = authority.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    signer = tpm.load_external(TPM2B_PUBLIC.from_pem(public_key), hierarchy=ESYS_TR.OWNER)
    try:
        name = tpm.tr_get_name(signer)
    finally:
        tpm.flush_context(signer)
    auth = session(tpm, trial=True)
    try:
        finish_policy(tpm, auth, name, TPMT_TK_VERIFIED(tag=TPM2_ST.VERIFIED, hierarchy=TPM2_RH.NULL), b'', epoch, index, profile)
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
    bundle = dict(version=2 if profile == 'uki' else 1, epoch=epoch, parent=int(tpm.tr_get_tpm_handle(parent)),
                  index=int(tpm.tr_get_tpm_handle(index)), pcrs=pcrs,
                  authority=public_key.decode(), public=encode(public.marshal()),
                  private=encode(private.marshal()), nonce=encode(nonce), envelope=encode(envelope))
    if profile == 'legacy':
        approve(tpm, bundle, authority)
    else:
        bundle['approvals'] = []
    return bundle


def epoch_set(current, following):
    """Create a public two-epoch routing set; never changes the TPM."""
    if (current.get('version') != 2 or following.get('version') != 2
        or following.get('epoch') != current.get('epoch', -2) + 1
        or any(current.get(key) != following.get(key) for key in ('index', 'parent', 'authority', 'pcrs'))
        or current.get('pcrs') != 'sha256:4,7,11'
        or not current.get('approvals') or not following.get('approvals')):
        raise ValueError('Expected approved consecutive UKI epochs with common TPM/authority')
    return dict(version=3, index=current['index'], bundles={
        str(current['epoch']): current, str(following['epoch']): following})


def advance_epoch(tpm, index, previous, target, owner):
    """Low-level commit AFTER caller durably stages and boot-verifies artifacts.

    Idempotent after a crash following NV increment. Never advances twice.
    Caller must serialize operations and verify its transaction readiness.
    """
    if len(owner) != 32 or target != previous + 1 or not 0 <= previous < target < 2**64:
        raise ValueError('Expected protected owner auth and one adjacent epoch step')
    current = int.from_bytes(bytes(tpm.nv_read(index, 8)), 'big')
    if current == target:
        return False
    if current != previous:
        raise ValueError('Counter is outside the prepared transaction')
    tpm.tr_set_auth(ESYS_TR.OWNER, owner)
    tpm.nv_increment(index, auth_handle=ESYS_TR.OWNER)
    if int.from_bytes(bytes(tpm.nv_read(index, 8)), 'big') != target:
        raise RuntimeError('Counter advanced unexpectedly; recovery review required')
    return True
