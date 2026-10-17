#!/usr/bin/env python3
"""qemu-console.py - drive an OpenWrt guest's serial console through QEMU's unix-socket chardev.

Used by scripts/awg/qemu-e2e.sh. Standard library only, so it runs on any runner with python3.

  qemu-console.py --sock PATH wait-shell [--timeout S]     wait for the boot, activate the console
  qemu-console.py --sock PATH run [--timeout S] -- CMD...  run one shell command line in the guest,
                                                           print its output, exit with its status
  qemu-console.py --sock PATH poweroff [--timeout S]       ask the guest to power off

Each call connects, works and disconnects; QEMU's chardev server takes the next connection. A command
is wrapped in random start/end markers and its status is read from the end marker, so the terminal's
echo of the typed line (which contains the marker text but not the expanded status) never matches.
"""
import argparse
import os
import re
import secrets
import socket
import sys
import time

PROMPT = re.compile(rb"root@[\w.-]+:[^\r\n]*# $")


class Console:
    def __init__(self, path, connect_timeout=60.0):
        deadline = time.monotonic() + connect_timeout
        while True:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                sock.connect(path)
                break
            except OSError:
                sock.close()
                if time.monotonic() > deadline:
                    raise
                time.sleep(0.5)
        self.sock = sock
        self.buf = b""
        self.echo = os.environ.get("AWG_E2E_CONSOLE_ECHO") == "1"

    def send(self, text):
        data = text.encode()
        # Small chunks: a guest UART under TCG drains slowly, and a long burst is where a busy
        # emulated serial port has been seen to lose characters.
        for i in range(0, len(data), 64):
            self.sock.sendall(data[i:i + 64])
            time.sleep(0.01)

    def _fill(self, timeout):
        self.sock.settimeout(timeout)
        try:
            chunk = self.sock.recv(65536)
        except socket.timeout:
            return False
        if not chunk:
            raise EOFError("console closed (the guest powered off or QEMU exited)")
        self.buf += chunk
        if self.echo:
            sys.stderr.buffer.write(chunk)
            sys.stderr.buffer.flush()
        return True

    def expect(self, pattern, timeout, start=0):
        deadline = time.monotonic() + timeout
        while True:
            m = pattern.search(self.buf, start)
            if m:
                return m
            left = deadline - time.monotonic()
            if left <= 0:
                raise TimeoutError(f"no match for {pattern.pattern!r} within {timeout:.0f}s")
            self._fill(min(left, 1.0))


def wait_shell(con, timeout):
    """Press Enter until a root prompt answers: before procd starts askconsole the key presses are
    harmless (at the x86 GRUB menu one only boots the default entry sooner)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        con.send("\r")
        try:
            con.expect(PROMPT, 5.0, max(0, len(con.buf) - 4096))
            # Let the console settle, then make sure the prompt still answers.
            mark = len(con.buf)
            con.send("\r")
            con.expect(PROMPT, 10.0, mark)
            return 0
        except TimeoutError:
            continue
    print(f"qemu-console: no shell prompt within {timeout}s", file=sys.stderr)
    return 124


def run(con, cmd, timeout):
    tok = secrets.token_hex(6)
    start_re = re.compile(rb"(?:^|\n)__AWGS_" + tok.encode() + rb"__\r?\n")
    end_re = re.compile(rb"__AWGE_" + tok.encode() + rb"__(\d+)\r?\n")
    mark = len(con.buf)
    con.send(f"echo __AWGS_{tok}__; {cmd}; echo __AWGE_{tok}__$?\r")
    try:
        s = con.expect(start_re, 30.0, mark)
        e = con.expect(end_re, timeout, s.end())
    except TimeoutError as err:
        sys.stdout.write(con.buf[mark:].decode(errors="replace").replace("\r", ""))
        print(f"\nqemu-console: {err}", file=sys.stderr)
        return 124
    out = con.buf[s.end():e.start()].decode(errors="replace").replace("\r", "")
    sys.stdout.write(out)
    sys.stdout.flush()
    return min(int(e.group(1)), 255)


def poweroff(con, timeout):
    con.send("\rpoweroff\r")
    deadline = time.monotonic() + timeout
    try:
        while time.monotonic() < deadline:
            con._fill(1.0)
            if b"Power down" in con.buf or b"reboot: System halted" in con.buf:
                return 0
    except EOFError:
        return 0
    return 124


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--sock", required=True)
    sub = ap.add_subparsers(dest="op", required=True)
    w = sub.add_parser("wait-shell")
    w.add_argument("--timeout", type=float, default=600)
    r = sub.add_parser("run")
    r.add_argument("--timeout", type=float, default=300)
    r.add_argument("cmd", nargs=argparse.REMAINDER)
    p = sub.add_parser("poweroff")
    p.add_argument("--timeout", type=float, default=60)
    a = ap.parse_args()

    con = Console(a.sock)
    try:
        if a.op == "wait-shell":
            return wait_shell(con, a.timeout)
        if a.op == "run":
            cmd = a.cmd[1:] if a.cmd[:1] == ["--"] else a.cmd
            if not cmd:
                ap.error("run needs a command")
            return run(con, " ".join(cmd), a.timeout)
        return poweroff(con, a.timeout)
    except EOFError as err:
        print(f"qemu-console: {err}", file=sys.stderr)
        return 125


if __name__ == "__main__":
    sys.exit(main())
