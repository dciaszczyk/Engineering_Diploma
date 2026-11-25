"""Generuje statyczny klucz X25519 relaya lub celu:  python3 keygen.py
priv -> zmienna RELAY_STATIC_KEY / DEST_KEY (nie do repozytorium), pub -> wpis "pub" w katalogu."""
from onion_common import X25519PrivateKey, priv_bytes, pub_bytes

k = X25519PrivateKey.generate()
print("priv =", priv_bytes(k).hex())
print("pub  =", pub_bytes(k).hex())
