#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Automated functional test for mcchat.py, intended to run inside the Ubuntu VM.

It starts several local nodes (same host, same multicast group) and exercises:
  1. join / discovery / member list
  2. multicast text to multiple receivers
  3. multicast file transfer + byte-for-byte verification
  4. kick = key rotation, kicked node receives ciphertext but cannot decrypt
  5. /leave: the node stops receiving but can still send
  6. /join: rejoin and receive again
  7. periodic key rotation (short interval) and epoch change
"""

import hashlib
import math
import shutil
import struct
import subprocess
import sys
import threading
import time
import wave
from pathlib import Path

BASE = Path(__file__).resolve().parent
PY = sys.executable
APP = BASE / "mcchat.py"


class Proc:
    def __init__(self, name, extra):
        self.name = name
        self.lines = []
        self.lock = threading.Lock()
        cmd = [PY, str(APP), "--name", name, "--base-dir", str(BASE),
               "--pace", "1"] + extra
        self.p = subprocess.Popen(
            cmd, cwd=str(BASE), stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1,
        )
        threading.Thread(target=self._reader, daemon=True).start()

    def _reader(self):
        for line in self.p.stdout:
            line = line.rstrip()
            with self.lock:
                self.lines.append(line)
            print(f"[{self.name}] {line}", flush=True)

    def send(self, text):
        print(f">>> {self.name}: {text}", flush=True)
        self.p.stdin.write(text + "\n")
        self.p.stdin.flush()

    def wait(self, needle, timeout=15.0):
        t0 = time.time()
        while time.time() - t0 < timeout:
            with self.lock:
                if any(needle in line for line in self.lines):
                    return True
            time.sleep(0.1)
        return False

    def has(self, needle):
        with self.lock:
            return any(needle in line for line in self.lines)

    def stop(self):
        try:
            self.send("/quit")
        except Exception:
            pass
        try:
            self.p.wait(timeout=6)
        except Exception:
            self.p.kill()

    def dump_new(self, start):
        with self.lock:
            return "\n".join(self.lines[start:])


def check(cond, message):
    if cond:
        print(f"PASS: {message}", flush=True)
    else:
        print(f"FAIL: {message}", flush=True)
        raise AssertionError(message)


def clean(name=None):
    names = [name] if name else ["Alice", "Bob", "Carol"]
    for n in names:
        shutil.rmtree(BASE / "state" / n, ignore_errors=True)
        shutil.rmtree(BASE / "downloads" / n, ignore_errors=True)
    if not name:
        shutil.rmtree(BASE / "logs", ignore_errors=True)


def make_wav(path: Path):
    if path.exists():
        return
    rate = 44100
    seconds = 4
    with wave.open(str(path), "wb") as w:
        w.setnchannels(2)
        w.setsampwidth(2)
        w.setframerate(rate)
        buf = bytearray()
        for i in range(rate * seconds):
            v = int(12000 * math.sin(2 * math.pi * 440 * i / rate))
            buf += struct.pack("<hh", v, v)
        w.writeframes(bytes(buf))


def phase_basic():
    print("\n========== BASIC: 3 nodes, chat/file/kick/leave/join ==========",
          flush=True)
    clean()
    make_wav(BASE / "test.wav")

    alice = Proc("Alice", ["--rekey", "300", "--validity", "600"])
    check(alice.wait("[KEY] created group key epoch 1", 10),
          "Alice founds the group and creates epoch 1")
    time.sleep(1)

    bob = Proc("Bob", ["--rekey", "300", "--validity", "600"])
    carol = Proc("Carol", ["--rekey", "300", "--validity", "600"])
    check(bob.wait("[KEY] epoch 1 installed", 15), "Bob receives epoch 1 key")
    check(carol.wait("[KEY] epoch 1 installed", 15), "Carol receives epoch 1 key")
    time.sleep(2)

    for p in (alice, bob, carol):
        p.send("/members")
    time.sleep(1.5)
    check("Bob" in alice.dump_new(0) and "Carol" in alice.dump_new(0),
          "Alice's member list contains Bob and Carol")
    check("Alice" in carol.dump_new(0), "Carol's member list contains Alice")

    alice.send("hello multicast")
    check(bob.wait("[Alice] hello multicast", 8), "Bob receives Alice's text")
    check(carol.wait("[Alice] hello multicast", 8),
          "Carol receives Alice's text (1-N)")

    bob.send("reply from bob")
    check(alice.wait("[Bob] reply from bob", 8), "Alice receives Bob's reply")
    check(carol.wait("[Bob] reply from bob", 8), "Carol receives Bob's reply")

    # File transfer
    src = BASE / "test.wav"
    src_hash = hashlib.sha256(src.read_bytes()).hexdigest()
    t0 = time.time()
    alice.send(f"/file {src}")
    check(bob.wait("[RECV] file=test.wav", 40), "Bob finishes receiving test.wav")
    check(carol.wait("[RECV] file=test.wav", 40),
          "Carol finishes receiving test.wav")
    time.sleep(1)
    for name in ("Bob", "Carol"):
        dst = BASE / "downloads" / name / "test.wav"
        check(dst.exists(), f"{name} file exists: {dst}")
        check(hashlib.sha256(dst.read_bytes()).hexdigest() == src_hash,
              f"{name} received the file byte-for-byte")
    print(f"FILE_TRANSFER_WALL_SECONDS={time.time() - t0:.3f}", flush=True)

    # Kick Carol: rotate key, Carol must be excluded
    alice.send("/kick Carol")
    check(carol.wait("[KICK] YOU were removed", 10),
          "Carol sees the kick notice")
    check(bob.wait("[KICK] Carol removed", 10), "Bob sees the kick notice")
    time.sleep(1.5)
    alice.send("message after kick")
    check(bob.wait("[Alice] message after kick", 8),
          "Bob still decrypts the new epoch")
    check(not carol.has("[Alice] message after kick"),
          "Carol cannot read the post-kick message")
    check(carol.wait("[LOCKED]", 8),
          "Carol sees ciphertext but reports LOCKED (no key)")

    carol.send("carol was here")
    time.sleep(2)
    check(not alice.has("[Carol] carol was here"),
          "Alice ignores the kicked member's messages")
    check(not bob.has("[Carol] carol was here"),
          "Bob ignores the kicked member's messages")

    # Leave: stop receiving, but keep sending
    bob.send("/leave")
    check(bob.wait("[LEAVE] left the multicast group", 6),
          "Bob leaves the multicast group")
    alice.send("while bob is out")
    time.sleep(2)
    check(not bob.has("while bob is out"),
          "Bob no longer receives while he is out of the group")
    bob.send("bob left but can still send")
    check(alice.wait("[Bob] bob left but can still send", 8),
          "Alice receives Bob's message after he left")

    # Rejoin
    bob.send("/join")
    check(bob.wait("[JOIN] joined", 6), "Bob rejoins the group")
    time.sleep(2.5)
    bob.send("bob is back")
    check(alice.wait("[Bob] bob is back", 8),
          "Alice receives Bob's message after rejoin")
    alice.send("welcome back bob")
    check(bob.wait("[Alice] welcome back bob", 8),
          "Bob receives again after rejoining")

    for p in (alice, bob, carol):
        p.stop()
    print("BASIC_PHASE_DONE", flush=True)


def phase_rotation():
    print("\n========== ROTATION: 2 nodes, short rekey interval ==========",
          flush=True)
    clean()
    alice = Proc("Alice", ["--rekey", "12", "--validity", "30"])
    check(alice.wait("[KEY] created group key epoch 1", 10),
          "Alice creates epoch 1")
    time.sleep(1)
    bob = Proc("Bob", ["--rekey", "12", "--validity", "30"])
    check(bob.wait("[KEY] epoch 1 installed", 15), "Bob installs epoch 1")
    time.sleep(15)
    alice.send("/keyinfo")
    bob.send("/keyinfo")
    time.sleep(1.5)
    check("epoch=2" in alice.dump_new(0), "Alice rotated to epoch 2")
    check("epoch=2" in bob.dump_new(0), "Bob installed epoch 2")
    alice.send("after rotation")
    check(bob.wait("[Alice] after rotation", 8),
          "Chat still works after key rotation")
    for p in (alice, bob):
        p.stop()
    print("ROTATION_PHASE_DONE", flush=True)


def main():
    print(f"BASE={BASE}", flush=True)
    print(f"PY={PY}", flush=True)
    phase_basic()
    phase_rotation()
    print("\nALL TESTS PASSED", flush=True)


if __name__ == "__main__":
    main()
