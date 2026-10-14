#!/usr/bin/env python3
"""Linux-only, loopback-only ProFTPD HiddenStores / Xray reset experiment.

Prerequisites (Ubuntu): proftpd-core, openssl, python3; two Linux Xray binaries.
Run as root so ProFTPD can use an isolated AuthUserFile and chroot:
  sudo python3 proftpd_rst_repro.py --before /abs/xray-before \
    --after /abs/xray-after --artifacts /tmp/proftpd-reset-evidence

No system users/configuration are modified. Only child process groups started
by this script are terminated. All test files and logs stay in --artifacts.
The FTP command channel stays direct; only the independent DATA connection
passes through SOCKS, isolating the failure under investigation.
"""

import argparse
import contextlib
import ftplib
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import struct
import subprocess
import time


ORIGINAL = b"ORIGINAL-COMPLETE-FILE\n" * 1024
PREFIX = b"PARTIAL-REPLACEMENT\n" * 256
PASSWORD = "loopback-test-only"


def unused_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_for(predicate, description, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.02)
    raise TimeoutError(description)


def reachable(port, process):
    if process.poll() is not None:
        raise RuntimeError(f"Child exited with {process.returncode}; inspect its log")
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.2):
            return True
    except OSError:
        return False


@contextlib.contextmanager
def child(command, logfile):
    with logfile.open("wb") as output:
        process = subprocess.Popen(
            command, stdout=output, stderr=subprocess.STDOUT, start_new_session=True
        )
        try:
            yield process
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)


def receive_exact(sock, count):
    result = bytearray()
    while len(result) < count:
        part = sock.recv(count - len(result))
        if not part:
            raise EOFError("SOCKS handshake ended early")
        result.extend(part)
    return bytes(result)


def data_connection(target_port, proxy_port):
    sock = socket.create_connection(
        ("127.0.0.1", proxy_port or target_port), timeout=15
    )
    if proxy_port is None:
        return sock
    try:
        sock.sendall(b"\x05\x01\x00")
        assert receive_exact(sock, 2) == b"\x05\x00"
        sock.sendall(
            b"\x05\x01\x00\x01"
            + socket.inet_aton("127.0.0.1")
            + struct.pack("!H", target_port)
        )
        header = receive_exact(sock, 4)
        assert header[:3] == b"\x05\x00\x00", header.hex()
        if header[3] == 1:
            receive_exact(sock, 6)
        elif header[3] == 4:
            receive_exact(sock, 18)
        elif header[3] == 3:
            receive_exact(sock, receive_exact(sock, 1)[0] + 2)
        else:
            raise AssertionError(f"Invalid SOCKS address type {header[3]}")
        return sock
    except BaseException:
        sock.close()
        raise


def file_state(path):
    contents = path.read_bytes() if path.exists() else None
    return {
        "exists": contents is not None,
        "size": len(contents) if contents is not None else None,
        "sha256": hashlib.sha256(contents).hexdigest() if contents is not None else None,
        "is_original": contents == ORIGINAL,
        "is_partial_replacement": contents == PREFIX,
    }


def run_case(ftp_port, home, label, closure, proxy_port, uid, gid):
    filename = f"{label}-{closure}.bin"
    final = home / filename
    hidden = home / f".in.{filename}."
    final.write_bytes(ORIGINAL)
    os.chown(final, uid, gid)
    with ftplib.FTP() as ftp:
        ftp.connect("127.0.0.1", ftp_port, timeout=15)
        ftp.login("resetprobe", PASSWORD)
        ftp.voidcmd("TYPE I")
        host, port = ftp.makepasv()
        assert host == "127.0.0.1", host
        data = data_connection(port, proxy_port)
        try:
            start_reply = ftp.sendcmd(f"STOR {filename}")
            assert start_reply.startswith(("125", "150")), start_reply
            data.sendall(PREFIX)
            wait_for(
                lambda: hidden.exists() and hidden.stat().st_size == len(PREFIX),
                "ProFTPD must consume the entire prefix before injecting closure",
            )
            before = {"final": file_state(final), "hidden": file_state(hidden)}
            assert before["final"]["is_original"]
            assert before["hidden"]["is_partial_replacement"]
            if closure == "rst":
                data.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            else:
                data.shutdown(socket.SHUT_WR)
        finally:
            data.close()
        try:
            reply = ftp.voidresp()
        except ftplib.Error as exc:
            reply = str(exc)
        wait_for(lambda: not hidden.exists(), "ProFTPD must finish HiddenStores cleanup")
        result = {
            "route": label,
            "closure": closure,
            "start_reply": start_reply,
            "completion_reply": reply,
            "before_close": before,
            "after_close": {"final": file_state(final), "hidden": file_state(hidden)},
        }
        print(json.dumps(result), flush=True)
        return result


@contextlib.contextmanager
def xray(binary, artifacts, label):
    port = unused_port()
    config = {
        "log": {"loglevel": "debug"},
        "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "socks",
                      "settings": {"auth": "noauth", "udp": False}}],
        "outbounds": [{"protocol": "freedom", "settings": {
            "finalRules": [{"action": "allow"}]}}],
        "policy": {"levels": {"0": {"connIdle": 20, "uplinkOnly": 1, "downlinkOnly": 1}}},
    }
    path = artifacts / f"xray-{label}.json"
    path.write_text(json.dumps(config, indent=2))
    with child([str(binary), "run", "-config", str(path)], artifacts / f"xray-{label}.log") as proc:
        wait_for(lambda: reachable(port, proc), f"Xray {label} listen")
        yield port


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--before", type=Path, required=True)
    parser.add_argument("--after", type=Path, required=True)
    parser.add_argument("--artifacts", type=Path, required=True)
    args = parser.parse_args()
    if os.name != "posix" or os.geteuid() != 0:
        parser.error("Run on Linux as root; no system account changes are performed")
    proftpd = shutil.which("proftpd")
    if not proftpd:
        parser.error("Install proftpd-core first")
    args.before = args.before.resolve(strict=True)
    args.after = args.after.resolve(strict=True)
    artifacts = args.artifacts.resolve()
    artifacts.mkdir(parents=True, exist_ok=False)
    artifacts.chmod(0o755)
    uid = int(os.environ.get("SUDO_UID", "65534")) or 65534
    gid = int(os.environ.get("SUDO_GID", "65534")) or 65534
    home = artifacts / "home"
    home.mkdir(mode=0o755)
    os.chown(home, uid, gid)
    hashed = subprocess.check_output(
        ["openssl", "passwd", "-6", "-stdin"], input=PASSWORD.encode() + b"\n"
    ).decode().strip()
    auth = artifacts / "users.passwd"
    auth.write_text(f"resetprobe:{hashed}:{uid}:{gid}:Reset probe:{home}:/bin/false\n")
    auth.chmod(0o600)
    ftp_port = unused_port()
    config = artifacts / "proftpd.conf"
    config.write_text(f'''ServerName "Isolated reset regression"
ServerType standalone
DefaultServer on
DefaultAddress 127.0.0.1
SocketBindTight on
Port {ftp_port}
UseIPv6 off
UseReverseDNS off
User nobody
Group nogroup
RequireValidShell off
AuthOrder mod_auth_file.c
AuthUserFile "{auth}"
DefaultRoot ~
AllowOverwrite on
HiddenStores on
DeleteAbortedStores on
MaxInstances 10
TimeoutIdle 30
TimeoutNoTransfer 30
TimeoutStalled 30
PidFile "{artifacts / 'proftpd.pid'}"
ScoreboardFile "{artifacts / 'proftpd.scoreboard'}"
SystemLog "{artifacts / 'proftpd-system.log'}"
TransferLog "{artifacts / 'proftpd-transfer.log'}"
''')
    versions = {
        "proftpd": subprocess.check_output([proftpd, "-v"], stderr=subprocess.STDOUT).decode(),
        "before": subprocess.check_output([str(args.before), "version"]).decode(),
        "after": subprocess.check_output([str(args.after), "version"]).decode(),
        "before_sha256": hashlib.sha256(args.before.read_bytes()).hexdigest(),
        "after_sha256": hashlib.sha256(args.after.read_bytes()).hexdigest(),
    }
    (artifacts / "versions.json").write_text(json.dumps(versions, indent=2))
    subprocess.run([proftpd, "-t", "-c", str(config)], check=True)
    results = []
    with child([proftpd, "-n", "-c", str(config)], artifacts / "proftpd-console.log") as proc:
        wait_for(lambda: reachable(ftp_port, proc), "ProFTPD listen")
        for closure in ("fin", "rst"):
            results.append(run_case(ftp_port, home, "direct", closure, None, uid, gid))
        for label, binary in (("before", args.before), ("after", args.after)):
            with xray(binary, artifacts, label) as proxy_port:
                for closure in ("fin", "rst"):
                    results.append(run_case(ftp_port, home, label, closure, proxy_port, uid, gid))
    (artifacts / "results.json").write_text(json.dumps(results, indent=2))
    failures = []
    for result in results:
        should_commit = result["closure"] == "fin" or result["route"] == "before"
        final = result["after_close"]["final"]
        code = result["completion_reply"][:3]
        expected = (code == "226" and final["is_partial_replacement"]) if should_commit else (
            code.startswith(("4", "5")) and final["is_original"]
        )
        if not expected:
            failures.append(f"Unexpected outcome: {result['route']}/{result['closure']}")
    summary = {"all_expected": not failures, "failures": failures, "cases": len(results)}
    (artifacts / "summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary), flush=True)
    return bool(failures)


if __name__ == "__main__":
    raise SystemExit(main())
