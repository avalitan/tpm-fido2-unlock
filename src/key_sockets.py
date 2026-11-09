"""Bounded, memory-only key distribution to one socket per configured volume."""
from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import selectors
import socket
import time


def activated(stack, paths=None):
    count = int(os.environ.get('LISTEN_FDS', '0'))
    if (os.environ.get('LISTEN_PID') != str(os.getpid()) or not 1 <= count <= 16
        or (paths is None and count != 1)
        or (paths is not None and (len(paths) != count or len(set(paths)) != count))):
        raise ValueError('Unexpected systemd socket activation')
    listeners = []
    for fd in range(3, 3 + count):
        os.set_inheritable(fd, False)
        listener = stack.enter_context(socket.socket(fileno=fd))
        if (listener.family != socket.AF_UNIX or listener.type != socket.SOCK_STREAM
            or not listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)):
            raise ValueError('Expected listening Unix stream sockets')
        listeners.append(listener)
    if paths is not None and {s.getsockname() for s in listeners} != set(paths):
        raise ValueError('Activated sockets do not match configured volumes')
    return listeners


@contextmanager
def token_lock(path='/run/combined-unlock/token.lock', timeout=20):
    """Serialize initrd providers; never keep the token locked while serving peers."""
    Path(path).parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        deadline = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise TimeoutError('FIDO provider lock unavailable')
                time.sleep(.05)
        yield
    finally:
        os.close(fd)


def serve(listeners, produce, timeout=40):
    """Produce once on first request, send once per volume, discard on completion.

    Distinct listeners prevent a retry on one volume from consuming another
    volume's delivery. No disk file, cross-run cache, or restart continuation.
    Caller owns listeners; closing them must not shut down systemd's copies.
    """
    if not listeners or len({s.fileno() for s in listeners}) != len(listeners) or timeout <= 0:
        raise ValueError('Expected distinct listeners and a positive deadline')
    deadline = time.monotonic() + timeout
    key = None
    try:
        with selectors.DefaultSelector() as pending:
            for listener in listeners:
                pending.register(listener, selectors.EVENT_READ)
            while pending.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('Not all configured volumes requested their key')
                for ready, _ in pending.select(remaining):
                    listener = ready.fileobj
                    with listener.accept()[0] as connection:
                        pending.unregister(listener)
                        if key is None:
                            key = produce()
                            if not isinstance(key, bytes) or not 1 <= len(key) <= 4096:
                                raise ValueError('Invalid derived key')
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise TimeoutError('Key distribution deadline expired')
                        connection.settimeout(min(5, remaining))
                        connection.sendall(key)
    finally:
        # Python cannot guarantee zeroization; retain no reference across runs.
        key = None
