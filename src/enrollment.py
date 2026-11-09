"""Management-only helpers for explicit shared-key LUKS slot enrollment."""
import json
from pathlib import Path
import tempfile
import uuid


def metadata(run, device):
    return json.loads(run('cryptsetup', 'luksDump', '--dump-json-metadata', device))


def preflight(targets, run):
    if not 1 <= len(targets) <= 16:
        raise ValueError('Expected 1 to 16 explicitly selected LUKS volumes')
    seen = set()
    result = []
    for target in targets:
        device, slot, recovery_slot = target['device'], target['slot'], target['recovery_slot']
        if (not device.startswith('/dev/') or any(c in device for c in '\r\n\0')
            or not 0 <= slot <= 31 or not 0 <= recovery_slot <= 31 or slot == recovery_slot
            or not target['recovery']):
            raise ValueError('Expected explicit device, free slot and nonempty recovery key')
        volume = str(uuid.UUID(run('cryptsetup', 'luksUUID', device).decode().strip()))
        if volume in seen:
            raise ValueError('Duplicate LUKS volume or UUID; refusing aliases/cloned headers')
        seen.add(volume)
        before = metadata(run, device)
        if str(slot) in before['keyslots'] or str(recovery_slot) not in before['keyslots']:
            raise ValueError('New slot occupied or recovery slot absent')
        run('cryptsetup', 'open', '--test-passphrase', '--key-slot', str(recovery_slot),
            '--key-file', '-', device, data=target['recovery'])
        result.append(dict(target, before=before))
    return result


def install(targets, key, run, directory='/run'):
    # Recheck ALL devices before the first write, after token interaction.
    if any(metadata(run, target['device']) != target['before'] for target in targets):
        raise RuntimeError('LUKS metadata changed after preflight')
    for target in targets:
        with tempfile.TemporaryDirectory(prefix='combined-enroll-', dir=directory) as temporary:
            recovery_file = Path(temporary) / 'recovery'
            # open mode sets permissions even if this helper is called outside CLI umask.
            with recovery_file.open('xb') as handle:
                recovery_file.chmod(0o600)
                handle.write(target['recovery'])
            run('cryptsetup', 'luksAddKey', '--key-slot', str(target['slot']), '--pbkdf', 'pbkdf2',
                '--pbkdf-force-iterations', '100000', '--key-file', str(recovery_file),
                target['device'], '-', data=key)
        run('cryptsetup', 'open', '--test-passphrase', '--key-slot', str(target['slot']),
            '--key-file', '-', target['device'], data=key)
        after = metadata(run, target['device'])
        before = target['before']
        if (after['tokens'] != before['tokens']
            or set(after['keyslots']) != set(before['keyslots']) | {str(target['slot'])}
            or any(after['keyslots'].get(k) != v for k, v in before['keyslots'].items())):
            raise RuntimeError('Unexpected change to LUKS slots/token metadata')
