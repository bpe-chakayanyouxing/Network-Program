#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MCChat: a decentralized multicast 1-N chat and file-transfer tool.

Design goals (course lab):
  * Data plane: chat text and file chunks are sent directly to a multicast
    group. There is no server, no relay, and no central message store.
  * Only receivers join the group (IP_ADD_MEMBERSHIP). The sender socket is
    never joined, so "send without joining" is true at the socket level.
  * Members are discovered with periodic HELLO beacons (name, host, MAC,
    public key, epoch). `/members` prints the local view.
  * Group content is encrypted with a short-lived AES-256-GCM group key.
    The key is distributed per member with RSA-2048-OAEP (hybrid crypto).
  * A kicked member is not physically removed from the IP multicast group;
    instead the group key is rotated and the new key is NOT sent to that
    member. The kicked member can still see packets but cannot decrypt them.
  * No retransmission / ACK / error recovery, per lab requirements.

Python 3.8+ and the `cryptography` package are required.

Tested on two platforms with this exact file (no source changes):
  * Ubuntu 22.04 (Python 3.10, cryptography 3.4.8): developed here; the
    33-check automated test (test_driver.py) and the tcpdump/IGMP evidence
    were collected in this environment. `demo.sh` / `shots.sh` /
    `shot_tcpdump2.sh` drive those sessions.
  * Windows 10/11 (Python 3.12, cryptography 49.x): launched via `run.bat`
    on two hosts over a direct Ethernet link. The only platform-specific
    behaviour is `--open` playback: it calls `xdg-open`, so on Windows the
    received file is simply left in `downloads/<name>/` for manual playback.
    On a direct link (no router) pass `--iface` explicitly, because the
    default-route auto-detection may pick the wrong NIC.
"""

import argparse
import base64
import hashlib
import json
import os
import re
import socket
import struct
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---------------------------------------------------------------------------
# Protocol constants
# ---------------------------------------------------------------------------

MAGIC = b"MCH1"
HEADER_FMT = "!4sBIQ16s16sI12sI"
HEADER_LEN = struct.calcsize(HEADER_FMT)          # 69 bytes
ZERO16 = b"\x00" * 16
ZERO12 = b"\x00" * 12

T_HELLO = 1
T_BYE = 2
T_CHAT = 3
T_FILE_START = 4
T_FILE_CHUNK = 5
T_FILE_END = 6
T_JOIN = 7
T_EPOCH = 8
T_KICK = 9
T_KEY_REQ = 10
T_KEY_GRANT = 11

TYPE_NAMES = {
    T_HELLO: "HELLO", T_BYE: "BYE", T_CHAT: "CHAT",
    T_FILE_START: "FILE_START", T_FILE_CHUNK: "FILE_CHUNK",
    T_FILE_END: "FILE_END", T_JOIN: "JOIN", T_EPOCH: "EPOCH",
    T_KICK: "KICK", T_KEY_REQ: "KEY_REQ", T_KEY_GRANT: "KEY_GRANT",
}

DEFAULT_GROUP = "239.255.42.99"
DEFAULT_PORT = 50000
CHUNK = 1024

HELLO_INTERVAL = 2.0       # seconds
MEMBER_TIMEOUT = 6.0       # 3 x HELLO interval
KEY_REQ_MIN_INTERVAL = 3.0
KEY_GRACE = 10.0

SIG_PADDING = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
OAEP_PADDING = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)

# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def now():
    return time.time()


def hhmmss():
    return time.strftime("%H:%M:%S")


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def canon(obj) -> bytes:
    """Canonical JSON used for signatures (stable key order, no spaces)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def safe_name(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", name) or "node"


def detect_iface() -> str:
    """Best-effort local IP used for multicast egress (no packet is sent)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "0.0.0.0"
    finally:
        s.close()


def format_mac(node: int) -> str:
    raw = node.to_bytes(6, "big")
    return ":".join(f"{b:02x}" for b in raw)


def pack_header(mtype, epoch, seq, sender, file_id=ZERO16, chunk=0,
                nonce=ZERO12, payload_len=0):
    return struct.pack(HEADER_FMT, MAGIC, mtype, epoch, seq, sender,
                       file_id, chunk, nonce, payload_len)


def unpack_header(data):
    if len(data) < HEADER_LEN:
        return None
    fields = struct.unpack(HEADER_FMT, data[:HEADER_LEN])
    magic, mtype, epoch, seq, sender, file_id, chunk, nonce, plen = fields
    if magic != MAGIC or len(data) < HEADER_LEN + plen:
        return None
    return mtype, epoch, seq, sender, file_id, chunk, nonce, plen


def aad_for(mtype, epoch, seq, sender, file_id, chunk):
    return struct.pack("!4sBIQ16s16sI", MAGIC, mtype, epoch, seq,
                       sender, file_id, chunk)


def id_from_pub_b64(pub_b64: str) -> bytes:
    der = b64d(pub_b64)
    return hashlib.sha256(der).digest()[:16]


def load_pub(pub_b64: str):
    return serialization.load_der_public_key(b64d(pub_b64))


# ---------------------------------------------------------------------------
# Identity (long-term RSA key)
# ---------------------------------------------------------------------------


class Identity:
    def __init__(self, state_dir: Path):
        path = state_dir / "identity.pem"
        if path.exists():
            self.priv = serialization.load_pem_private_key(path.read_bytes(), None)
        else:
            self.priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            path.write_bytes(self.priv.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ))
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
        self.pub = self.priv.public_key()
        self.der = self.pub.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.id = hashlib.sha256(self.der).digest()[:16]
        self.id_hex = self.id.hex()
        self.pub_b64 = b64e(self.der)

    def sign(self, data: bytes) -> bytes:
        return self.priv.sign(data, SIG_PADDING, hashes.SHA256())

    def decrypt(self, data: bytes) -> bytes:
        return self.priv.decrypt(data, OAEP_PADDING)


# ---------------------------------------------------------------------------
# Node
# ---------------------------------------------------------------------------


class Node:
    def __init__(self, args):
        self.args = args
        self.debug = bool(getattr(args, "debug", False))
        self.name = args.name
        self.group = args.group
        self.port = args.port
        self.iface = args.iface or detect_iface()
        self.ttl = args.ttl
        self.pace = max(0.0, args.pace / 1000.0)
        self.auto_open = args.open
        self.rekey_interval = float(args.rekey)
        self.key_validity = float(args.validity)
        self.base = Path(args.base_dir or ".").resolve()

        safe = safe_name(self.name)
        self.state_dir = Path(args.state_dir) if args.state_dir else self.base / "state" / safe
        self.download_dir = Path(args.download_dir) if args.download_dir else self.base / "downloads" / safe
        self.log_dir = self.base / "logs"
        for d in (self.state_dir, self.download_dir, self.log_dir):
            d.mkdir(parents=True, exist_ok=True)
        self.log_path = self.log_dir / f"{safe}.log"

        self.identity = Identity(self.state_dir)
        self.host = socket.gethostname()
        self.mac = format_mac(uuid.getnode())
        self.self_entry = {
            "id": self.identity.id_hex,
            "name": self.name,
            "host": self.host,
            "mac": self.mac,
            "ip": self.iface,
            "port": self.port,
            "ctrl_port": 0,          # filled after ctrl socket creation
            "epoch": 0,
            "last_seen": now(),
            "pubkey": self.identity.pub_b64,
            "self": True,
        }
        self.members = {self.identity.id_hex: self.self_entry}
        self.known_names = {self.identity.id_hex: self.name}
        self.banned = {}
        self._load_banned()

        self.keys = {}                # epoch -> AES key bytes
        self.valid = {}               # epoch -> (valid_from, valid_to)
        self.key_source = {}          # epoch -> distributor id hex
        self.current_epoch = None
        self.min_epoch = 0
        self.pending_epochs = {}      # epoch -> distributor id hex

        self.seq = 0
        self.nonce_prefix = os.urandom(4)
        self.nonce_ctr = 0
        self.send_lock = threading.Lock()
        self.state_lock = threading.RLock()
        self.print_lock = threading.Lock()

        self.files = {}               # file_id bytes -> record
        self.last_key_req = {}        # peer key -> last request time
        self.requested_from = set()   # peer id hex we asked
        self.locked_log = {}          # throttle [LOCKED] messages

        self.joined = False
        self.kicked = False
        self.running = True
        self.state_dirty = False
        self.recv_sock = None
        self.recv_thread = None
        self.ctrl_sock = None
        self.ctrl_thread = None

        self.send_sock = self._make_send_socket()
        self.ctrl_sock = self._make_ctrl_socket()
        self.ctrl_port = self.ctrl_sock.getsockname()[1]
        self.self_entry["ctrl_port"] = self.ctrl_port

        self.start_time = now()
        self.last_rekey = 0.0

        self.out("=" * 68)
        self.out(f"MCChat node name={self.name} id={self.identity.id_hex[:16]}")
        self.out(f"group={self.group}:{self.port} iface={self.iface} "
                 f"ttl={self.ttl} ctrl_port={self.ctrl_port}")
        self.out(f"state={self.state_dir} downloads={self.download_dir}")
        self.out("commands: /members /file <path> /kick <name> /leave /join "
                 "/keyinfo /help /quit")
        self.out("=" * 68)

    # -- sockets ------------------------------------------------------------

    def _make_send_socket(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, self.ttl)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
                     socket.inet_aton(self.iface))
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1 << 20)
        except OSError:
            pass
        return s

    def _make_recv_socket(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
        except OSError:
            pass
        s.bind(("", self.port))
        mreq = socket.inet_aton(self.group) + socket.inet_aton(self.iface)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
        s.settimeout(1.0)
        return s

    def _make_ctrl_socket(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        s.bind(("", 0))
        s.settimeout(1.0)
        return s

    def _mreq(self):
        return socket.inet_aton(self.group) + socket.inet_aton(self.iface)

    # -- logging / state ----------------------------------------------------

    def out(self, text):
        line = f"[{hhmmss()}] {text}"
        with self.print_lock:
            print(line, flush=True)
            try:
                with open(self.log_path, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
            except OSError:
                pass

    def dbg(self, text):
        if self.debug:
            self.out(f"[DBG] {text}")

    def _load_banned(self):
        path = self.state_dir / "banned.json"
        if path.exists():
            try:
                self.banned = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                self.banned = {}

    def save_state(self):
        with self.state_lock:
            members = list(self.members.values())
            banned = dict(self.banned)
            self.state_dirty = False
        try:
            tmp = self.state_dir / "members.json.tmp"
            tmp.write_text(json.dumps(members, ensure_ascii=False, indent=2),
                           encoding="utf-8")
            os.replace(tmp, self.state_dir / "members.json")
            tmp = self.state_dir / "banned.json.tmp"
            tmp.write_text(json.dumps(banned, ensure_ascii=False, indent=2),
                           encoding="utf-8")
            os.replace(tmp, self.state_dir / "banned.json")
        except OSError as e:
            self.out(f"[WARN] save state: {e}")

    # -- membership helpers -------------------------------------------------

    def online_peers(self):
        t = now()
        with self.state_lock:
            return [
                m for rid, m in self.members.items()
                if not m.get("self")
                and rid not in self.banned
                and t - m.get("last_seen", 0) <= MEMBER_TIMEOUT
            ]

    def online_ids(self, exclude=None):
        ids = [m["id"] for m in self.online_peers() if m["id"] != exclude]
        if self.joined and self.identity.id_hex != exclude:
            ids.append(self.identity.id_hex)
        return ids

    def min_online_id(self):
        ids = self.online_ids()
        return min(ids) if ids else self.identity.id_hex

    def name_of(self, rid_hex):
        with self.state_lock:
            m = self.members.get(rid_hex)
            if m:
                return m["name"]
            if rid_hex in self.banned:
                return self.banned[rid_hex].get("name", rid_hex[:8])
            return self.known_names.get(rid_hex, rid_hex[:8])

    def update_member(self, rid_hex, obj, ip):
        with self.state_lock:
            old = self.members.get(rid_hex)
            m = {
                "id": rid_hex,
                "name": str(obj.get("name", "?")),
                "host": str(obj.get("host", "")),
                "mac": str(obj.get("mac", "")),
                "ip": ip,
                "port": int(obj.get("port", self.port)),
                "ctrl_port": int(obj.get("ctrl_port", self.port)),
                "epoch": int(obj.get("epoch", 0)),
                "last_seen": now(),
                "pubkey": obj["pubkey"],
                "self": False,
            }
            self.members[rid_hex] = m
            self.known_names[rid_hex] = m["name"]
            self.state_dirty = True
        if old is None:
            self.out(f"[MEMBER] {m['name']} joined from {ip}:{m['ctrl_port']}")
        return m

    def prune_members(self):
        t = now()
        gone = []
        with self.state_lock:
            for rid, m in list(self.members.items()):
                if m.get("self"):
                    continue
                if t - m.get("last_seen", 0) > MEMBER_TIMEOUT:
                    gone.append((rid, m.get("name", rid[:8])))
                    del self.members[rid]
                    self.state_dirty = True
        for rid, name in gone:
            self.out(f"[MEMBER] {name} left (timeout)")

    # -- multicast lifecycle ------------------------------------------------

    def join(self):
        if self.joined:
            return
        try:
            self.recv_sock = self._make_recv_socket()
        except OSError as e:
            self.out(f"[ERR] cannot join multicast group: {e}")
            return
        self.joined = True
        self.self_entry["last_seen"] = now()
        self.recv_thread = threading.Thread(
            target=self.recv_loop, args=(self.recv_sock,), daemon=True)
        self.recv_thread.start()
        self.send_hello()
        self.send_join_req()
        self.out(f"[JOIN] joined {self.group}:{self.port} on {self.iface} "
                 f"(ctrl :{self.ctrl_port})")

    def leave(self):
        if not self.joined:
            return
        self.send_bye()
        self.joined = False
        sock, self.recv_sock = self.recv_sock, None
        if sock is not None:
            try:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP,
                                self._mreq())
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass
        self.out("[LEAVE] left the multicast group; sending still works")

    def shutdown(self):
        if not self.running:
            return
        self.running = False
        try:
            if self.joined:
                self.leave()   # sends BYE + IP_DROP_MEMBERSHIP
        except Exception:
            pass
        self.save_state()
        for s in (self.ctrl_sock, self.send_sock):
            try:
                s.close()
            except OSError:
                pass
        self.out("bye")

    # -- packet I/O ---------------------------------------------------------

    def send_raw(self, pkt, dst=None):
        try:
            self.send_sock.sendto(pkt, dst or (self.group, self.port))
        except OSError as e:
            self.out(f"[ERR] send: {e}")

    def sign_and_send(self, mtype, obj, epoch=None, dst=None):
        obj = dict(obj)
        obj.pop("sig", None)
        obj["sig"] = b64e(self.identity.sign(canon(obj)))
        payload = canon(obj)
        with self.send_lock:
            self.seq += 1
            seq = self.seq
        hdr = pack_header(mtype, int(epoch or 0), seq, self.identity.id,
                          payload_len=len(payload))
        self.send_raw(hdr + payload, dst)

    def seal(self, mtype, plaintext, epoch, file_id=ZERO16, chunk=0):
        with self.state_lock:
            key = self.keys.get(epoch)
            vf, vt = self.valid.get(epoch, (0, 0))
        if key is None:
            raise RuntimeError("no key for epoch")
        if now() > vt:
            raise RuntimeError("key expired")
        with self.send_lock:
            self.seq += 1
            seq = self.seq
            nonce = self.nonce_prefix + struct.pack("!Q", self.nonce_ctr)
            self.nonce_ctr += 1
        aad = aad_for(mtype, epoch, seq, self.identity.id, file_id, chunk)
        ct = AESGCM(key).encrypt(nonce, plaintext, aad)
        hdr = pack_header(mtype, epoch, seq, self.identity.id, file_id,
                          chunk, nonce, len(ct))
        return hdr + ct

    def recv_loop(self, sock):
        while self.running and self.joined and self.recv_sock is sock:
            try:
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                self.handle_packet(data, addr)
            except Exception as e:
                self.out(f"[ERR] packet: {e}")

    def ctrl_loop(self):
        while self.running:
            try:
                data, addr = self.ctrl_sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                h = unpack_header(data)
                if not h:
                    continue
                if h[0] in (T_KEY_GRANT, T_KEY_REQ):
                    self.dbg(f"ctrl recv type={h[0]} from {addr} len={len(data)}")
                    self.handle_packet(data, addr)
            except Exception as e:
                self.out(f"[ERR] ctrl: {e}")

    def handle_packet(self, data, addr):
        h = unpack_header(data)
        if not h:
            return
        mtype, epoch, seq, sender, file_id, chunk, nonce, plen = h
        payload = data[HEADER_LEN:HEADER_LEN + plen]
        if sender == self.identity.id:
            return  # ignore our own multicast loopback
        if mtype in (T_HELLO, T_BYE, T_JOIN, T_EPOCH, T_KICK,
                     T_KEY_REQ, T_KEY_GRANT):
            self.handle_control(mtype, epoch, sender, payload, addr)
        else:
            self.handle_data(mtype, epoch, seq, sender, file_id, chunk,
                             nonce, payload, addr)

    # -- control messages ---------------------------------------------------

    def verify_obj(self, obj, pub_b64):
        sig = b64d(obj.get("sig", ""))
        body = {k: v for k, v in obj.items() if k != "sig"}
        load_pub(pub_b64).verify(sig, canon(body), SIG_PADDING, hashes.SHA256())

    def handle_control(self, mtype, epoch, sender, payload, addr):
        if mtype == T_KEY_GRANT:
            # KEY_GRANT is a compact binary payload, not JSON.
            self.handle_key_grant(sender, payload, addr)
            return

        try:
            obj = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return

        if mtype in (T_HELLO, T_JOIN, T_BYE):
            pub = obj.get("pubkey")
            if not isinstance(pub, str):
                return
            try:
                rid = id_from_pub_b64(pub)
            except Exception:
                return
            if rid != sender:
                return
            rid_hex = rid.hex()
            if rid_hex in self.banned:
                return
            try:
                self.verify_obj(obj, pub)
            except (InvalidSignature, ValueError, TypeError):
                self.out(f"[WARN] bad signature on {TYPE_NAMES[mtype]} from {addr[0]}")
                return
            if mtype == T_BYE:
                with self.state_lock:
                    if rid_hex in self.members:
                        name = self.members[rid_hex].get("name", rid_hex[:8])
                        del self.members[rid_hex]
                        self.state_dirty = True
                    else:
                        name = obj.get("name", rid_hex[:8])
                self.out(f"[MEMBER] {name} left (BYE)")
                return

            m = self.update_member(rid_hex, obj, addr[0])
            if mtype == T_JOIN:
                self.out(f"[MEMBER] {m['name']} requested the group key")
                if (self.joined and self.current_epoch is not None
                        and self.identity.id_hex == min(
                            self.online_ids(exclude=rid_hex) or
                            [self.identity.id_hex])):
                    self.send_key_grant(
                        addr[0], m["ctrl_port"], m["pubkey"], self.current_epoch)
            else:  # HELLO
                if (self.joined and self.current_epoch is not None
                        and int(obj.get("epoch", 0)) > self.current_epoch):
                    self.request_key(addr[0], m["ctrl_port"], m["pubkey"],
                                     int(obj.get("epoch", 0)))
            return

        if mtype in (T_EPOCH, T_KICK):
            pub = obj.get("pubkey")
            dist = obj.get("distributor")
            if not isinstance(pub, str) or not isinstance(dist, str):
                return
            try:
                did = bytes.fromhex(dist)
            except ValueError:
                return
            if did != sender or id_from_pub_b64(pub) != did:
                return
            if dist in self.banned:
                return
            with self.state_lock:
                known = dist in self.members or dist == self.identity.id_hex
            if not known:
                return
            try:
                self.verify_obj(obj, pub)
            except (InvalidSignature, ValueError, TypeError):
                self.out(f"[WARN] bad signature on {TYPE_NAMES[mtype]}")
                return
            try:
                e = int(obj.get("epoch", 0))
            except (TypeError, ValueError):
                return
            if e <= 0:
                return
            self.pending_epochs[e] = dist
            with self.state_lock:
                self.min_epoch = max(self.min_epoch, e)
                self.state_dirty = True
            if mtype == T_KICK:
                target = str(obj.get("target", ""))
                tname = str(obj.get("target_name", target[:8]))
                with self.state_lock:
                    self.banned[target] = {
                        "name": tname, "ts": now(), "by": dist}
                    self.members.pop(target, None)
                    self.state_dirty = True
                if target == self.identity.id_hex:
                    self.kicked = True
                    self.out(f"[KICK] YOU were removed by {self.name_of(dist)}; "
                             f"you may still see traffic but cannot decrypt epoch {e}")
                else:
                    self.out(f"[KICK] {tname} removed by {self.name_of(dist)} "
                             f"(epoch {e})")
                self.save_state()
            else:
                self.out(f"[EPOCH] epoch {e} announced by {self.name_of(dist)}")
            if (not self.kicked and e not in self.keys and
                    e > (self.current_epoch or 0)):
                ctrl = int(obj.get("ctrl_port", self.port))
                self.request_key(addr[0], ctrl, pub, e)
            return

        if mtype == T_KEY_REQ:
            pub = obj.get("pubkey")
            if not isinstance(pub, str):
                return
            try:
                rid = id_from_pub_b64(pub)
            except Exception:
                return
            if rid != sender or rid.hex() in self.banned:
                return
            try:
                self.verify_obj(obj, pub)
            except (InvalidSignature, ValueError, TypeError):
                return
            with self.state_lock:
                known = rid.hex() in self.members
            if not known:
                self.out(f"[KEY] ignored request from unknown member {rid.hex()[:8]}")
                return
            if self.current_epoch is None:
                return
            ctrl = int(obj.get("ctrl_port", self.port)) or self.port
            self.send_key_grant(addr[0], ctrl, pub, self.current_epoch)
            self.out(f"[KEY] granted epoch {self.current_epoch} to "
                     f"{obj.get('name', rid.hex()[:8])}")
            return

        if mtype == T_KEY_GRANT:
            self.handle_key_grant(sender, payload, addr)
            return

    # -- keys ---------------------------------------------------------------

    def send_key_grant(self, ip, ctrl_port, peer_pub_b64, epoch):
        with self.state_lock:
            key = self.keys.get(epoch)
            vf, vt = self.valid.get(epoch, (0, 0))
        if key is None:
            return
        try:
            rid = id_from_pub_b64(peer_pub_b64)
            inner = struct.pack("!I32sdd16s16s", int(epoch), key,
                                float(vf), float(vt),
                                rid, self.identity.id)
            sig = self.identity.sign(inner)
            ct = load_pub(peer_pub_b64).encrypt(inner, OAEP_PADDING)
        except Exception as e:
            self.out(f"[WARN] grant build failed: {e}")
            return
        body = (self.identity.id
                + struct.pack("!H", len(ct)) + ct
                + struct.pack("!H", len(sig)) + sig)
        with self.send_lock:
            self.seq += 1
            seq = self.seq
        hdr = pack_header(T_KEY_GRANT, int(epoch), seq, self.identity.id,
                          payload_len=len(body))
        self.send_raw(hdr + body, (ip, int(ctrl_port) or self.port))
        self.out(f"[KEY] sent epoch {epoch} to {rid.hex()[:8]} at "
                 f"{ip}:{int(ctrl_port) or self.port}")

    def handle_key_grant(self, sender, payload, addr):
        self.dbg(f"grant recv sender={sender.hex()[:8]} payload={len(payload)}")
        try:
            if len(payload) < 20:
                self.dbg("grant reject: too short")
                return
            did = payload[:16]
            clen = struct.unpack("!H", payload[16:18])[0]
            if len(payload) < 20 + clen:
                self.dbg("grant reject: ct truncated")
                return
            ct = payload[18:18 + clen]
            slen = struct.unpack("!H", payload[18 + clen:20 + clen])[0]
            sig = payload[20 + clen:20 + clen + slen]
            if len(sig) != slen or did != sender:
                self.dbg(f"grant reject: sig_len={slen} did_match={did == sender}")
                return
            dist_hex = did.hex()
            if dist_hex in self.banned:
                self.out("[KEY] rejected grant from banned member")
                return
            with self.state_lock:
                m = self.members.get(dist_hex)
            if not m:
                self.dbg(f"grant from unknown member {dist_hex[:8]}")
                if dist_hex in self.requested_from:
                    self.out(f"[KEY] rejected grant from unknown member {dist_hex[:8]}")
                return
            pub_b64 = m["pubkey"]
            inner = self.identity.decrypt(ct)
            load_pub(pub_b64).verify(sig, inner, SIG_PADDING, hashes.SHA256())
            epoch, key, vf, vt, rid, inner_dist = struct.unpack(
                "!I32sdd16s16s", inner)
            if rid != self.identity.id or inner_dist != did:
                self.dbg(f"grant reject: rid_match={rid == self.identity.id} "
                         f"dist_match={inner_dist == did}")
                return
            if vt <= now():
                self.out(f"[KEY] rejected expired epoch {epoch}")
                return
            if epoch < self.min_epoch:
                self.out(f"[KEY] ignored stale epoch {epoch}")
                return
        except (ValueError, InvalidSignature, TypeError, struct.error) as e:
            self.out(f"[KEY] bad grant from {addr[0]}: {e}")
            return
        except Exception as e:
            self.out(f"[KEY] cannot decrypt grant from {addr[0]}: {e}")
            return

        with self.state_lock:
            self.keys[epoch] = key
            self.valid[epoch] = (vf, vt)
            self.key_source[epoch] = dist_hex
            if epoch > (self.current_epoch or 0):
                self.current_epoch = epoch
            self.min_epoch = max(self.min_epoch, epoch)
            self.self_entry["epoch"] = self.current_epoch or 0
            self.last_rekey = now()
            self.state_dirty = True
        self.out(f"[KEY] epoch {epoch} installed from {self.name_of(dist_hex)} "
                 f"(valid {max(0, vt - now()):.0f}s)")

    def request_key(self, ip, ctrl_port, peer_pub_b64, epoch_hint=0):
        try:
            rid_hex = id_from_pub_b64(peer_pub_b64).hex()
        except Exception:
            return
        key = f"{ip}:{ctrl_port}:{rid_hex}"
        if now() - self.last_key_req.get(key, 0) < KEY_REQ_MIN_INTERVAL:
            return
        self.last_key_req[key] = now()
        self.requested_from.add(rid_hex)
        obj = {
            "v": 1, "name": self.name, "host": self.host, "mac": self.mac,
            "port": self.port, "ctrl_port": self.ctrl_port,
            "pubkey": self.identity.pub_b64,
            "epoch_hint": int(epoch_hint), "ts": int(now() * 1000),
        }
        self.sign_and_send(T_KEY_REQ, obj, epoch=self.current_epoch or 0,
                           dst=(ip, int(ctrl_port) or self.port))
        self.out(f"[KEY] requesting epoch {epoch_hint or 'current'} from "
                 f"{self.name_of(rid_hex)}")

    def create_key(self, epoch):
        key = os.urandom(32)
        vf, vt = now() - 5.0, now() + self.key_validity
        with self.state_lock:
            self.keys[epoch] = key
            self.valid[epoch] = (vf, vt)
            self.key_source[epoch] = self.identity.id_hex
            self.current_epoch = epoch
            self.min_epoch = max(self.min_epoch, epoch)
            self.self_entry["epoch"] = epoch
            self.last_rekey = now()
            self.state_dirty = True
        self.out(f"[KEY] created group key epoch {epoch} "
                 f"(valid {self.key_validity:.0f}s)")

    def maybe_founder(self):
        if not self.joined or self.kicked or self.current_epoch is not None:
            return
        if now() - self.start_time < 2.0:
            return
        peers = self.online_peers()
        if not peers:
            # Nobody else is visible: this node starts the group.
            self.create_key(1)
            return
        # A late joiner must not create a competing epoch-1 key; ask a member
        # that already has a key (highest epoch wins, then lowest id).
        with_key = [m for m in peers if int(m.get("epoch", 0)) > 0]
        if with_key:
            peer = sorted(with_key,
                          key=lambda m: (-int(m.get("epoch", 0)), m["id"]))[0]
            self.request_key(peer["ip"], peer.get("ctrl_port", self.port),
                             peer["pubkey"], 0)
            return
        # Nobody has a key yet (simultaneous start): the lowest ID creates
        # epoch 1 and the others request it.  This avoids a request deadlock.
        ids = [self.identity.id_hex] + [m["id"] for m in peers]
        if self.identity.id_hex == min(ids):
            self.create_key(1)
            return
        peer = min(peers, key=lambda m: m["id"])
        self.request_key(peer["ip"], peer.get("ctrl_port", self.port),
                         peer["pubkey"], 0)

    def maybe_rotate(self):
        if not self.joined or self.kicked or self.current_epoch is None:
            return
        if self.identity.id_hex != self.min_online_id():
            return
        if now() - self.last_rekey < self.rekey_interval:
            return
        new_epoch = self.current_epoch + 1
        self.create_key(new_epoch)
        for m in self.online_peers():
            self.send_key_grant(m["ip"], m.get("ctrl_port", self.port),
                                m["pubkey"], new_epoch)
        self.send_epoch_notice(new_epoch)

    def send_epoch_notice(self, epoch):
        obj = {
            "v": 1, "name": self.name, "host": self.host, "mac": self.mac,
            "port": self.port, "ctrl_port": self.ctrl_port,
            "pubkey": self.identity.pub_b64,
            "epoch": int(epoch), "distributor": self.identity.id_hex,
            "ts": int(now() * 1000),
        }
        self.sign_and_send(T_EPOCH, obj, epoch=epoch)

    # -- kick ---------------------------------------------------------------

    def resolve_member(self, token):
        token = token.strip()
        with self.state_lock:
            members = list(self.members.values())
        exact = [m for m in members if m["id"] == token.lower()]
        if exact:
            return exact[0]
        prefixes = [m for m in members if not m.get("self")
                    and m["id"].startswith(token.lower())]
        if len(prefixes) == 1:
            return prefixes[0]
        names = [m for m in members if not m.get("self")
                 and m["name"] == token]
        if len(names) == 1:
            return names[0]
        if len(names) > 1:
            self.out(f"[KICK] name '{token}' is ambiguous: use an id prefix")
            for m in names:
                self.out(f"  {m['id'][:8]}  {m['name']}")
            return None
        if len(prefixes) > 1:
            self.out(f"[KICK] id prefix '{token}' is ambiguous")
            return None
        return None

    def kick(self, token):
        if self.current_epoch is None:
            self.out("[KICK] no group key yet")
            return
        m = self.resolve_member(token)
        if not m:
            self.out(f"[KICK] member '{token}' not found")
            return
        if m.get("self") or m["id"] == self.identity.id_hex:
            self.out("[KICK] cannot kick yourself")
            return
        target = m["id"]
        new_epoch = max([self.current_epoch] + list(self.keys.keys())) + 1
        key = os.urandom(32)
        vf, vt = now() - 5.0, now() + self.key_validity
        with self.state_lock:
            self.keys[new_epoch] = key
            self.valid[new_epoch] = (vf, vt)
            self.key_source[new_epoch] = self.identity.id_hex
            self.current_epoch = new_epoch
            self.min_epoch = max(self.min_epoch, new_epoch)
            self.self_entry["epoch"] = new_epoch
            self.last_rekey = now()
            self.pending_epochs[new_epoch] = self.identity.id_hex
            self.state_dirty = True
        grants = 0
        for peer in self.online_peers():
            if peer["id"] == target:
                continue
            self.send_key_grant(peer["ip"], peer.get("ctrl_port", self.port),
                                peer["pubkey"], new_epoch)
            grants += 1
        with self.state_lock:
            self.banned[target] = {
                "name": m["name"], "ts": now(),
                "by": self.identity.id_hex}
            self.members.pop(target, None)
            self.state_dirty = True
        obj = {
            "v": 1, "name": self.name, "host": self.host, "mac": self.mac,
            "port": self.port, "ctrl_port": self.ctrl_port,
            "pubkey": self.identity.pub_b64,
            "target": target, "target_name": m["name"],
            "epoch": new_epoch, "distributor": self.identity.id_hex,
            "ts": int(now() * 1000),
        }
        self.sign_and_send(T_KICK, obj, epoch=new_epoch)
        self.save_state()
        self.out(f"[KICK] {m['name']} removed; rotated to epoch {new_epoch} "
                 f"and sent new keys to {grants} member(s); target is banned")

    # -- data plane ---------------------------------------------------------

    def name_for_sender(self, sender_hex):
        return self.name_of(sender_hex)

    def handle_data(self, mtype, epoch, seq, sender, file_id, chunk, nonce,
                    payload, addr):
        sender_hex = sender.hex()
        if sender_hex in self.banned:
            return
        if epoch < self.min_epoch:
            return
        with self.state_lock:
            key = self.keys.get(epoch)
            _, vt = self.valid.get(epoch, (0, 0))
        if key is None or now() > vt:
            label = TYPE_NAMES.get(mtype, str(mtype))
            sender_name = self.name_for_sender(sender_hex)
            if self.kicked:
                lk = f"{sender_hex}:{epoch}:{mtype}"
                if now() - self.locked_log.get(lk, 0) > 3:
                    self.locked_log[lk] = now()
                    self.out(f"[LOCKED] {label} epoch {epoch} from "
                             f"{sender_name}: no key (removed from group)")
            elif self.joined:
                with self.state_lock:
                    m = self.members.get(sender_hex)
                if m:
                    self.request_key(m["ip"], m.get("ctrl_port", self.port),
                                     m["pubkey"], epoch)
            return
        aad = aad_for(mtype, epoch, seq, sender, file_id, chunk)
        try:
            plain = AESGCM(key).decrypt(nonce, payload, aad)
        except InvalidTag:
            self.out(f"[DROP] cannot decrypt {TYPE_NAMES.get(mtype, mtype)} "
                     f"from {self.name_for_sender(sender_hex)} (epoch {epoch})")
            return

        if mtype == T_CHAT:
            try:
                text = plain.decode("utf-8")
            except UnicodeDecodeError:
                return
            line = f"[{hhmmss()}] [{self.name_for_sender(sender_hex)}] {text}"
            with self.print_lock:
                print(line, flush=True)
                try:
                    with open(self.log_path, "a", encoding="utf-8") as f:
                        f.write(f"[{hhmmss()}] [CHAT] "
                                f"{self.name_for_sender(sender_hex)}: {text}\n")
                except OSError:
                    pass
            return

        if mtype == T_FILE_START:
            try:
                meta = json.loads(plain.decode("utf-8"))
                name = os.path.basename(str(meta.get("name", "file.bin")))
                size = int(meta["size"])
                nchunks = int(meta["nchunks"])
                t0 = float(meta.get("t0", now()))
            except (ValueError, KeyError, TypeError):
                return
            if name in ("", ".", ".."):
                name = "file.bin"
            path = self.download_dir / name
            if path.exists():
                path = self.download_dir / f"{path.stem}-{file_id.hex()[:8]}{path.suffix}"
            try:
                fh = open(path, "wb")
                fh.truncate(size)
            except OSError as e:
                self.out(f"[FILE] cannot create {path}: {e}")
                return
            self.files[file_id] = {
                "name": name, "path": path, "fh": fh, "size": size,
                "nchunks": max(1, nchunks), "got": set(), "t0": t0,
                "t_first": now(), "next_pct": 0,
                "sender": self.name_for_sender(sender_hex),
            }
            self.out(f"[FILE] receiving '{name}' ({size} bytes, {nchunks} "
                     f"chunks) from {self.name_for_sender(sender_hex)}")
            return

        if mtype == T_FILE_CHUNK:
            rec = self.files.get(file_id)
            if not rec:
                return
            try:
                rec["fh"].seek(chunk * CHUNK)
                rec["fh"].write(plain)
            except OSError:
                return
            rec["got"].add(chunk)
            pct = int(100 * len(rec["got"]) / rec["nchunks"])
            if pct >= rec["next_pct"]:
                self.out(f"[FILE] {rec['name']} {pct}% "
                         f"({len(rec['got'])}/{rec['nchunks']})")
                rec["next_pct"] = (pct // 10 + 1) * 10
            return

        if mtype == T_FILE_END:
            rec = self.files.pop(file_id, None)
            if not rec:
                return
            try:
                rec["fh"].close()
            except OSError:
                pass
            t_end = now()
            got = len(rec["got"])
            total = rec["nchunks"]
            dur = t_end - rec["t_first"]
            e2e = t_end - rec["t0"]
            self.out(f"[RECV] file={rec['name']} size={rec['size']} "
                     f"chunks={total} got={got}/{total} "
                     f"dur={dur:.3f}s e2e={e2e:.3f}s")
            self.out(f"[RECV] saved to {rec['path']}")
            if got < total:
                self.out(f"[RECV] WARNING incomplete: missing {total - got} chunk(s)")
            elif self.auto_open:
                try:
                    subprocess.Popen(["xdg-open", str(rec["path"])],
                                     stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL)
                except OSError as e:
                    self.out(f"[FILE] cannot open player: {e}")
            return

    def send_chat(self, text):
        if not text:
            return
        if self.current_epoch is None:
            self.out("[CHAT] no group key yet; wait for key distribution")
            return
        raw = text.encode("utf-8")
        if len(raw) > 1000:
            self.out("[CHAT] message too long (max 1000 bytes)")
            return
        if self.kicked:
            self.out("[CHAT] you are kicked; this message will be ignored")
        try:
            pkt = self.seal(T_CHAT, raw, self.current_epoch)
        except RuntimeError as e:
            self.out(f"[CHAT] {e}")
            return
        self.send_raw(pkt)
        self.out(f"[me] {text}")

    def send_file(self, path_text):
        path = Path(path_text.strip().strip('"').strip("'")).expanduser()
        if not path.is_file():
            self.out(f"[FILE] not found: {path}")
            return
        if self.current_epoch is None:
            self.out("[FILE] no group key yet")
            return
        size = path.stat().st_size
        nchunks = max(1, (size + CHUNK - 1) // CHUNK) if size else 0
        file_id = os.urandom(16)
        t0 = now()
        meta = {"name": path.name, "size": size, "nchunks": nchunks, "t0": t0}
        try:
            pkt = self.seal(T_FILE_START, json.dumps(meta).encode("utf-8"),
                            self.current_epoch, file_id, 0)
        except RuntimeError as e:
            self.out(f"[FILE] {e}")
            return
        self.send_raw(pkt)
        self.out(f"[SEND] file={path.name} size={size} chunks={nchunks} "
                 f"t0={t0:.3f}")
        step = max(1, nchunks // 10) if nchunks else 1
        with open(path, "rb") as f:
            for i in range(nchunks):
                if not self.running:
                    return
                data = f.read(CHUNK)
                try:
                    pkt = self.seal(T_FILE_CHUNK, data, self.current_epoch,
                                    file_id, i)
                except RuntimeError as e:
                    self.out(f"[FILE] stopped at chunk {i}: {e}")
                    return
                self.send_raw(pkt)
                if (i + 1) % step == 0 or i + 1 == nchunks:
                    self.out(f"[SEND] {path.name} "
                             f"{int(100 * (i + 1) / nchunks)}% "
                             f"({i + 1}/{nchunks})")
                if self.pace:
                    time.sleep(self.pace)
        t1 = now()
        end = {"nchunks": nchunks, "size": size, "t1": t1}
        try:
            pkt = self.seal(T_FILE_END, json.dumps(end).encode("utf-8"),
                            self.current_epoch, file_id, 0)
            self.send_raw(pkt)
        except RuntimeError as e:
            self.out(f"[FILE] end packet failed: {e}")
            return
        self.out(f"[SEND] file={path.name} size={size} chunks={nchunks} "
                 f"t0={t0:.3f} t1={t1:.3f} dur={t1 - t0:.3f}s")

    # -- HELLO / lifecycle loops --------------------------------------------

    def send_hello(self):
        obj = {
            "v": 1, "name": self.name, "host": self.host, "mac": self.mac,
            "port": self.port, "ctrl_port": self.ctrl_port,
            "pubkey": self.identity.pub_b64,
            "epoch": self.current_epoch or 0, "ts": int(now() * 1000),
        }
        self.sign_and_send(T_HELLO, obj, epoch=self.current_epoch or 0)

    def send_join_req(self):
        obj = {
            "v": 1, "name": self.name, "host": self.host, "mac": self.mac,
            "port": self.port, "ctrl_port": self.ctrl_port,
            "pubkey": self.identity.pub_b64,
            "epoch": self.current_epoch or 0, "ts": int(now() * 1000),
        }
        self.sign_and_send(T_JOIN, obj, epoch=self.current_epoch or 0)

    def send_bye(self):
        obj = {
            "v": 1, "name": self.name, "host": self.host, "mac": self.mac,
            "port": self.port, "ctrl_port": self.ctrl_port,
            "pubkey": self.identity.pub_b64, "ts": int(now() * 1000),
        }
        self.sign_and_send(T_BYE, obj, epoch=self.current_epoch or 0)

    def hello_loop(self):
        while self.running:
            time.sleep(HELLO_INTERVAL)
            if not self.running:
                break
            if not self.joined or self.kicked:
                continue
            try:
                self.send_hello()
                self.prune_members()
                self.maybe_founder()
                self.maybe_rotate()
                if self.state_dirty:
                    self.save_state()
            except Exception as e:
                self.out(f"[ERR] hello loop: {e}")

    # -- display ------------------------------------------------------------

    def print_members(self):
        rows = []
        with self.state_lock:
            if self.joined:
                rows.append(dict(self.self_entry, _age=0.0, _self=True))
            for rid, m in self.members.items():
                if m.get("self"):
                    continue
                age = now() - m.get("last_seen", 0)
                if age <= MEMBER_TIMEOUT and rid not in self.banned:
                    rows.append(dict(m, _age=age, _self=False))
        if not rows:
            self.out("[MEMBERS] no members online (not joined?)")
            return
        self.out(f"[MEMBERS] {len(rows)} online")
        for m in sorted(rows, key=lambda x: x["id"]):
            mark = "*" if m["_self"] else " "
            self.out(f" {mark}{m['id'][:8]}  {m['name'][:10]:10}  "
                     f"{m['ip']:15}  epoch={m.get('epoch', 0)}  "
                     f"last={m['_age']:.1f}s")
            self.out(f"    host={m.get('host', '')}  mac={m.get('mac', '')}")

    def print_keyinfo(self):
        with self.state_lock:
            cur = self.current_epoch
            keys = sorted(self.keys)
            if cur is None:
                self.out("[KEY] no group key yet")
                return
            key = self.keys.get(cur)
            fp = hashlib.sha256(key).hexdigest()[:16] if key else "-"
            vf, vt = self.valid.get(cur, (0, 0))
            src = self.key_source.get(cur, "?")
        self.out(f"[KEY] name={self.name} id={self.identity.id_hex[:16]} "
                 f"group={self.group}:{self.port} iface={self.iface}")
        self.out(f"[KEY] epoch={cur} fingerprint={fp} keys={keys} "
                 f"expires_in={max(0, vt - now()):.1f}s source={src[:8]}")
        self.out(f"[KEY] joined={self.joined} kicked={self.kicked} "
                 f"banned={list(self.banned.keys())}")

    def help(self):
        self.out("commands:")
        self.out("  <text>            send a multicast chat message")
        self.out("  /file <path>      send a file in 1024-byte chunks over multicast")
        self.out("  /members          show current multicast members (HELLO view)")
        self.out("  /kick <name|id>   rotate group key and exclude that member")
        self.out("  /leave            leave the multicast group (sending still works)")
        self.out("  /join             rejoin the multicast group")
        self.out("  /keyinfo          show epoch, key fingerprint, expiry")
        self.out("  /whoami           show my identity and network parameters")
        self.out("  /quit             exit")

    # -- CLI ----------------------------------------------------------------

    def run(self):
        self.ctrl_thread = threading.Thread(target=self.ctrl_loop, daemon=True)
        self.ctrl_thread.start()
        self.join()
        threading.Thread(target=self.hello_loop, daemon=True).start()
        try:
            while self.running:
                try:
                    line = input("> ")
                except (EOFError, KeyboardInterrupt):
                    break
                line = line.strip()
                if not line:
                    continue
                if not line.startswith("/"):
                    self.send_chat(line)
                    continue
                parts = line.split(None, 1)
                cmd = parts[0].lower()
                arg = parts[1] if len(parts) > 1 else ""
                if cmd == "/help":
                    self.help()
                elif cmd == "/members":
                    self.print_members()
                elif cmd == "/file":
                    if not arg:
                        self.out("usage: /file <path>")
                    else:
                        threading.Thread(target=self.send_file, args=(arg,),
                                         daemon=True).start()
                elif cmd == "/kick":
                    if not arg:
                        self.out("usage: /kick <name|id>")
                    else:
                        self.kick(arg)
                elif cmd == "/leave":
                    self.leave()
                elif cmd == "/join":
                    self.join()
                elif cmd == "/keyinfo":
                    self.print_keyinfo()
                elif cmd == "/whoami":
                    self.out(f"name={self.name} id={self.identity.id_hex} "
                             f"ip={self.iface} ctrl={self.ctrl_port} "
                             f"joined={self.joined}")
                elif cmd == "/quit":
                    break
                else:
                    self.out(f"unknown command {cmd}; try /help")
        finally:
            self.shutdown()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def parse_args():
    p = argparse.ArgumentParser(
        description="Decentralized multicast chat + file transfer")
    p.add_argument("--name", required=True, help="display name, e.g. Alice")
    p.add_argument("--group", default=DEFAULT_GROUP, help="IPv4 multicast group")
    p.add_argument("--port", type=int, default=DEFAULT_PORT, help="UDP port")
    p.add_argument("--iface", default="", help="local interface IP (default: auto)")
    p.add_argument("--ttl", type=int, default=1, help="multicast TTL (LAN=1)")
    p.add_argument("--pace", type=int, default=1,
                   help="milliseconds between file chunks (default 1)")
    p.add_argument("--open", action="store_true",
                   help="open received files with xdg-open")
    p.add_argument("--rekey", type=float, default=60.0,
                   help="seconds between group-key rotations (default 60)")
    p.add_argument("--validity", type=float, default=120.0,
                   help="group-key validity in seconds (default 120)")
    p.add_argument("--base-dir", default=".",
                   help="base directory for state/logs/downloads")
    p.add_argument("--state-dir", default="", help="override state directory")
    p.add_argument("--download-dir", default="", help="override download directory")
    p.add_argument("--debug", action="store_true",
                   help="verbose key/control diagnostics")
    return p.parse_args()


def main():
    args = parse_args()
    node = Node(args)
    node.run()


if __name__ == "__main__":
    main()
