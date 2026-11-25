"""Wspólny kod protokołu onion v3: relay.py, client.py i dest_server.py używają tych samych funkcji.

KOMÓRKA (514 B):   circuit_id(4, LE) | cmd(1) | payload(509)
  CREATE  payload = wersja(1) | głębokość(1) | E(32)        E = efemeryczny klucz klienta
  CREATED payload = R(32) | MAC(32)                          R = efemeryczny klucz relaya
  RELAY   payload = warstwa(S_d) | losowe dopełnienie        S_d = 509 - 28*d, d = głębokość relaya
  DESTROY jawne, bez odpowiedzi; jako odpowiedź na CREATE z obcą wersją: payload[0] = wersja relaya

WARSTWA = nonce(12) | AES-256-GCM(tekst) | tag(16), AAD = kierunek (0 w przód, 1 wstecz).
  Każdy hop dokłada/zdejmuje 28 B, więc rozmiar warstwy zależy tylko od głębokości hopa
  i relay zna go bez żadnych pól długości.

TEKST OSTATNIEGO HOPA (to, co widzi relay, który nie ma następnego hopa):
  EXTEND      0x10 | ip(4) | port(2) | wersja(1) | E(32)
  DATA        0x12 | ip(4) | port(2) | długość(2) | dane
  EXTENDED    0x11 | R(32) | MAC(32)                      (odpowiedź na EXTEND)
  DATA_REPLY  0x13 | status(1) | nonce_żądania(12) | długość(2) | odpowiedź celu
  (wszystko little-endian, dopełnione zerami do rozmiaru warstwy)
Warstwy środkowe nie niosą adresów: relay przekazuje je według stanu obwodu (circuit id).
"""
import secrets
import socket
import struct

from cryptography.exceptions import InvalidTag  # noqa: F401  (re-export)
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat, PublicFormat)

VERSION = 3
CELL_SIZE, CELL_PAYLOAD = 514, 509
CMD_CREATE, CMD_CREATED, CMD_RELAY, CMD_DESTROY = 1, 2, 3, 4
T_EXTEND, T_EXTENDED, T_DATA, T_DATA_REPLY = 0x10, 0x11, 0x12, 0x13
FORWARD, BACKWARD = b"\x00", b"\x01"
NONCE, TAG = 12, 16
LAYER_OVERHEAD = NONCE + TAG
PUB, MAC, KEY = 32, 32, 32
MAX_HOPS = 8
STATUS_OK, STATUS_FAILED = 0, 1
DATA_HEADER, REPLY_HEADER = 9, 16


# ---------- rozmiary ----------
def layer_size(depth):
    """Rozmiar warstwy odbieranej przez relay na głębokości `depth` (0 = entry)."""
    return CELL_PAYLOAD - depth * LAYER_OVERHEAD


def terminal_size(hops):
    """Rozmiar tekstu widzianego przez ostatni hop obwodu o `hops` hopach."""
    return layer_size(hops - 1) - LAYER_OVERHEAD


def max_payload(hops):
    """Ile bajtów danych (po ewentualnym szyfrowaniu e2e) zmieści jedna wiadomość DATA."""
    return terminal_size(hops) - DATA_HEADER


def max_response(hops):
    """Ile bajtów odpowiedzi celu zmieści jedna odpowiedź."""
    return terminal_size(hops) - REPLY_HEADER


# ---------- komórki ----------
def make_cell(cid, cmd, payload):
    """Składa komórkę; resztę payloadu wypełnia losowymi bajtami."""
    assert len(payload) <= CELL_PAYLOAD
    return struct.pack("<IB", cid, cmd) + payload + secrets.token_bytes(CELL_PAYLOAD - len(payload))


def parse_cell(raw):
    """Zwraca (circuit_id, cmd, payload)."""
    cid, cmd = struct.unpack_from("<IB", raw)
    return cid, cmd, raw[5:]


def ip_to_int(ip):
    return struct.unpack(">I", socket.inet_aton(ip))[0]


def ip_from_int(value):
    return socket.inet_ntoa(struct.pack(">I", value))


# ---------- warstwy ----------
def encrypt_layer(key, direction, plain):
    """Szyfruje tekst: zwraca nonce | szyfrogram | tag (o 28 B dłuższe niż tekst)."""
    nonce = secrets.token_bytes(NONCE)
    return nonce + AESGCM(key).encrypt(nonce, plain, direction)


def decrypt_layer(key, direction, blob):
    """Odwrotność encrypt_layer. Rzuca InvalidTag, gdy warstwa została zmieniona."""
    return AESGCM(key).decrypt(blob[:NONCE], blob[NONCE:], direction)


# ---------- handshake hopa ----------
def pub_bytes(priv):
    return priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def priv_bytes(priv):
    return priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())


def dh(priv, peer_pub):
    """X25519; odrzuca wynik zerowy (punkt o małym rzędzie)."""
    shared = priv.exchange(X25519PublicKey.from_public_bytes(peer_pub))
    if shared == bytes(32):
        raise ValueError("degenerate DH result")
    return shared


def _hop_key(version, dh_eph, dh_static):
    return HKDF(hashes.SHA256(), KEY, None, b"onion-hop" + bytes([version])).derive(dh_eph + dh_static)


def hmac_sha256(key, data):
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()


def client_start():
    """Klient: losuje parę efemeryczną. Zwraca (priv, E)."""
    priv = X25519PrivateKey.generate()
    return priv, pub_bytes(priv)


def client_finish(version, e_priv, E, S, R, mac):
    """Klient: z odpowiedzi relaya (R, mac) i jego klucza statycznego S wylicza klucz hopa.
    Rzuca ValueError, gdy odpowiada ktoś, kto nie zna klucza prywatnego odpowiadającego S."""
    key = _hop_key(version, dh(e_priv, R), dh(e_priv, S))
    if not secrets.compare_digest(hmac_sha256(key, E + R + S), mac):
        raise ValueError("handshake MAC mismatch (wrong static key?)")
    return key


def server_handshake(version, E, static_priv):
    """Relay: z E klienta liczy (R, mac, klucz hopa). Rzuca ValueError przy złym E."""
    r = X25519PrivateKey.generate()
    R, S = pub_bytes(r), pub_bytes(static_priv)
    key = _hop_key(version, dh(r, E), dh(static_priv, E))
    return R, hmac_sha256(key, E + R + S), key


# ---------- szyfrowanie end-to-end do celu ----------
class E2eKeys:
    """Klucze jednej wymiany żądanie/odpowiedź między klientem a celem (exit ich nie zna)."""
    def __init__(self, okm):
        self.req_key, self.req_nonce = okm[0:32], okm[32:44]
        self.resp_key, self.resp_nonce = okm[44:76], okm[76:88]


def _e2e_keys(ss, E, D):
    info = b"onion-e2e" + bytes([VERSION]) + E + D
    return E2eKeys(HKDF(hashes.SHA256(), 88, None, info).derive(ss))


E2E_REQUEST_OVERHEAD, E2E_RESPONSE_OVERHEAD = PUB + TAG, TAG


def e2e_seal_request(dest_pub, data):
    """Klient: szyfruje żądanie dla celu o kluczu publicznym dest_pub. Zwraca (E | szyfrogram | tag, klucze)."""
    e = X25519PrivateKey.generate()
    E = pub_bytes(e)
    keys = _e2e_keys(dh(e, dest_pub), E, dest_pub)
    return E + AESGCM(keys.req_key).encrypt(keys.req_nonce, data, None), keys


def e2e_open_response(keys, blob):
    """Klient: odszyfrowuje odpowiedź celu. Rzuca InvalidTag przy podróbce."""
    return AESGCM(keys.resp_key).decrypt(keys.resp_nonce, blob, None)


def e2e_open_request(dest_priv, blob):
    """Cel: odszyfrowuje żądanie. Zwraca (dane, klucze do odpowiedzi)."""
    E, body = blob[:PUB], blob[PUB:]
    keys = _e2e_keys(dh(dest_priv, E), E, pub_bytes(dest_priv))
    return AESGCM(keys.req_key).decrypt(keys.req_nonce, body, None), keys


def e2e_seal_response(keys, data):
    """Cel: szyfruje odpowiedź (jedna odpowiedź na żądanie)."""
    return AESGCM(keys.resp_key).encrypt(keys.resp_nonce, data, None)
