"""
ShadowDAG Python SDK — portable wallet primitives for backends & exchanges.

Pure standard-library (no third-party deps): hashlib/hmac for the hashes and a
self-contained RFC 8032 Ed25519 implementation, so the whole address +
transaction chain is reproducible anywhere Python runs.

It re-implements the chain's EXACT derivation so addresses, mnemonics, and
signatures match `shadowdag-wallet` / the WASM SDK byte-for-byte (verified by the
reference vectors at the bottom — run `python shadowdag_sdk.py` to self-test).

Chain (mirrors the node):
  mnemonic --PBKDF2-HMAC-SHA256--> 64B seed
  seed     --HMAC-SHA256("ShadowDAG/44'/999'/{a}'/{c}/{i}")[:32]--> Ed25519 key
  pubkey   --SHA256("ShadowDAG_Addr_v1" || pubkey)[:20]--> SD1.. address
  tx id    = SHA256("SHADOW_TX_ID_V1"  || chain_id || 2u32 || canonical_bytes)
  sign msg = SHA256("SHADOW_TX_SIGN_V1" || chain_id || ...)
  sig      = Ed25519(sign msg)
"""

import hashlib
import hmac as _hmac
import json
import struct

# ─────────────────────────── Ed25519 (RFC 8032 reference) ───────────────────
b = 256
q = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493


def _H(m):
    return hashlib.sha512(m).digest()


def _expmod(bb, e, m):
    return pow(bb, e, m)


def _inv(x):
    return _expmod(x, q - 2, q)


d = -121665 * _inv(121666) % q
I = _expmod(2, (q - 1) // 4, q)


def _xrecover(y):
    xx = (y * y - 1) * _inv(d * y * y + 1)
    x = _expmod(xx, (q + 3) // 8, q)
    if (x * x - xx) % q != 0:
        x = (x * I) % q
    if x % 2 != 0:
        x = q - x
    return x


_By = 4 * _inv(5) % q
_Bx = _xrecover(_By)
B = [_Bx % q, _By % q]


def _edwards(P, Q):
    x1, y1 = P
    x2, y2 = Q
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + d * x1 * x2 * y1 * y2)
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - d * x1 * x2 * y1 * y2)
    return [x3 % q, y3 % q]


def _scalarmult(P, e):
    if e == 0:
        return [0, 1]
    Q = _scalarmult(P, e // 2)
    Q = _edwards(Q, Q)
    if e & 1:
        Q = _edwards(Q, P)
    return Q


def _encodeint(y):
    bits = [(y >> i) & 1 for i in range(b)]
    return bytes(sum(bits[i * 8 + j] << j for j in range(8)) for i in range(b // 8))


def _encodepoint(P):
    x, y = P
    bits = [(y >> i) & 1 for i in range(b - 1)] + [x & 1]
    return bytes(sum(bits[i * 8 + j] << j for j in range(8)) for i in range(b // 8))


def _bit(h, i):
    return (h[i // 8] >> (i % 8)) & 1


def ed25519_publickey(sk):
    """32-byte seed -> 32-byte Ed25519 public key (matches ed25519-dalek)."""
    h = _H(sk)
    a = 2 ** (b - 2) + sum(2 ** i * _bit(h, i) for i in range(3, b - 2))
    A = _scalarmult(B, a)
    return _encodepoint(A)


def _Hint(m):
    h = _H(m)
    return sum(2 ** i * _bit(h, i) for i in range(2 * b))


def ed25519_sign(msg, sk, pk):
    """64-byte Ed25519 signature over msg (matches ed25519-dalek sign)."""
    h = _H(sk)
    a = 2 ** (b - 2) + sum(2 ** i * _bit(h, i) for i in range(3, b - 2))
    r = _Hint(bytes(h[b // 8:b // 4]) + msg)
    R = _scalarmult(B, r)
    S = (r + _Hint(_encodepoint(R) + pk + msg) * a) % L
    return _encodepoint(R) + _encodeint(S)


# ─────────────────────────────── Addresses ─────────────────────────────────
_CONSONANTS = b"bcdfghjklmnprstvwxyz"
_VOWELS = b"aeiou"


def _prefix(network):
    return {"mainnet": "SD1", "testnet": "ST1", "regtest": "SR1"}.get(network, "SD1")


def address_from_public_key(pubkey_bytes, network="mainnet"):
    h = hashlib.sha256(b"ShadowDAG_Addr_v1" + pubkey_bytes).digest()
    return _prefix(network) + h[:20].hex()


def validate_address(addr):
    if not (addr.startswith("SD1") or addr.startswith("ST1") or addr.startswith("SR1")):
        return False
    if len(addr) <= 3:
        return False
    prefix_len = 4 if addr[3] in ("s", "k", "h") else 3
    if len(addr) != prefix_len + 40:
        return False
    try:
        int(addr[prefix_len:], 16)
        return True
    except ValueError:
        return False


# ─────────────────────────────── Mnemonics ─────────────────────────────────
def _wordlist():
    words, seen = [], set()
    for i in range(8192):
        h = hashlib.sha256(b"ShadowDAG_BIP39_WordGen_v1" + struct.pack("<I", i)).digest()
        word_len = 3 + (h[0] % 5)
        w = []
        for j in range(word_len):
            byte = h[(j + 1) % 32]
            w.append(chr(_CONSONANTS[byte % len(_CONSONANTS)]) if j % 2 == 0
                     else chr(_VOWELS[byte % len(_VOWELS)]))
        word = "".join(w)
        if len(word) >= 3 and word not in seen:
            seen.add(word)
            words.append(word)
            if len(words) >= 2048:
                break
    return words


def entropy_to_mnemonic(entropy):
    wl = _wordlist()
    h = hashlib.sha3_256(entropy).digest()
    bits = [(byte >> bit) & 1 for byte in h for bit in range(7, -1, -1)]
    out = []
    for i in range(12):
        idx = 0
        for bpos in range(11):
            if i * 11 + bpos < len(bits):
                idx = (idx << 1) | bits[i * 11 + bpos]
        out.append(wl[idx % 2048])
    return " ".join(out)


def mnemonic_to_seed(mnemonic, passphrase=""):
    salt = ("ShadowDAG" + passphrase).encode()
    return hashlib.pbkdf2_hmac("sha256", mnemonic.encode(), salt, 2048, dklen=64)


def derive_key(seed, account=0, index=0, change=False):
    """64B seed -> 32B Ed25519 private key (matches wallet.rs::derive_key)."""
    path = "ShadowDAG/44'/999'/%d'/%d/%d" % (account, 1 if change else 0, index)
    return _hmac.new(seed, path.encode(), hashlib.sha256).digest()[:32]


def address_from_mnemonic(mnemonic, passphrase="", network="mainnet"):
    seed = mnemonic_to_seed(mnemonic, passphrase)
    sk = derive_key(seed, 0, 0, False)
    return address_from_public_key(ed25519_publickey(sk), network)


# ────────────────────────── Transactions (transparent) ─────────────────────
_CHAIN_ID = {"mainnet": 0xDA0C0001, "testnet": 0xDA0C0002, "regtest": 0xDA0C0003}
_TX_HASH_VERSION = 2


def _lp(bs):  # length-prefixed bytes (u32 LE len + bytes)
    return struct.pack("<I", len(bs)) + bs


def _sorted_inputs(inputs):
    return sorted(inputs, key=lambda i: (i["txid"], i["index"]))


def _canonical_bytes(inputs, pubkey_hex, outputs, fee, timestamp, payload_hash):
    out = bytearray()
    out += b"\x00"  # tx_type Transfer
    out += b"\x00"  # is_coinbase false
    out += struct.pack("<Q", timestamp)
    out += struct.pack("<Q", fee)
    si = _sorted_inputs(inputs)
    out += struct.pack("<I", len(inputs))
    for inp in si:
        out += _lp(inp["txid"].encode())
        out += struct.pack("<I", inp["index"])
        out += _lp(inp["owner"].encode())
        out += _lp(pubkey_hex.encode())
        out += b"\x00\x00\x00\x00\x00"  # key_image/ring_members/ring_sig/ring_commit/pseudo
    out += struct.pack("<I", len(outputs))
    for o in outputs:
        out += _lp(o["address"].encode())
        out += struct.pack("<Q", o["amount"])
        out += b"\x00\x00\x00\x00\x00"  # commitment/range_proof/eph/otk/enc_amount
    if payload_hash:
        out += b"\x01" + _lp(payload_hash.encode())
    else:
        out += b"\x00"
    out += b"\x00\x00\x00\x00\x00"  # gas_limit/deploy_code/calldata/contract_addr/vm_version
    return bytes(out)


def _tx_id_hash(canonical, chain_id):
    h = hashlib.sha256()
    h.update(b"SHADOW_TX_ID_V1")
    h.update(struct.pack("<I", chain_id))
    h.update(struct.pack("<I", _TX_HASH_VERSION))
    h.update(canonical)
    return h.hexdigest()


def _signing_message(hash_hex, inputs, outputs, fee, timestamp, payload_hash, chain_id):
    h = hashlib.sha256()
    h.update(b"SHADOW_TX_SIGN_V1")
    h.update(struct.pack("<I", chain_id))
    h.update(_lp(hash_hex.encode()))
    h.update(struct.pack("<Q", timestamp))
    h.update(struct.pack("<Q", fee))
    h.update(struct.pack("<I", len(outputs)))
    for o in outputs:
        h.update(_lp(o["address"].encode()))
        h.update(struct.pack("<Q", o["amount"]))
    h.update(struct.pack("<I", len(inputs)))
    for inp in _sorted_inputs(inputs):
        h.update(_lp(inp["txid"].encode()))
        h.update(struct.pack("<I", inp["index"]))
    if payload_hash:
        h.update(b"\x01" + _lp(payload_hash.encode()))
    else:
        h.update(b"\x00")
    return h.digest()


def build_signed_transfer(inputs, outputs, fee, timestamp, private_key_hex,
                          public_key_hex, network="mainnet", anchor=None):
    """Build + sign a transparent transfer. Returns a dict ready for JSON / RPC.

    inputs:  [{"txid": hex, "index": int, "owner": "SD1.."}, ...]
    outputs: [{"address": "SD1..", "amount": int}, ...]
    """
    chain_id = _CHAIN_ID.get(network, _CHAIN_ID["mainnet"])
    canonical = _canonical_bytes(inputs, public_key_hex, outputs, fee, timestamp, anchor)
    tx_hash = _tx_id_hash(canonical, chain_id)
    msg = _signing_message(tx_hash, inputs, outputs, fee, timestamp, anchor, chain_id)
    sk = bytes.fromhex(private_key_hex)
    pk = bytes.fromhex(public_key_hex)
    sig = ed25519_sign(msg, sk, pk).hex()
    tx = {
        "hash": tx_hash,
        "inputs": [{"txid": i["txid"], "index": i["index"], "owner": i["owner"],
                    "signature": sig, "pub_key": public_key_hex} for i in inputs],
        "outputs": [{"address": o["address"], "amount": o["amount"]} for o in outputs],
        "fee": fee, "timestamp": timestamp, "is_coinbase": False, "tx_type": "Transfer",
    }
    if anchor:
        tx["payload_hash"] = anchor
    return tx


def sendrawtransaction_body(tx, req_id=1):
    # The node expects the tx as a JSON STRING in params[0] (it calls
    # params[0].as_str() then serde_json::from_str), not a nested object.
    return {"jsonrpc": "2.0", "id": req_id, "method": "sendrawtransaction",
            "params": [json.dumps(tx)]}


# ───────────────────────────── Self-test (reference vectors) ────────────────
if __name__ == "__main__":
    # Vectors captured from the main crate (wallet.rs + tx_builder.rs tests).
    assert address_from_public_key(bytes([1] * 32), "mainnet") == \
        "SD1723695fe652da72b39aa12f17e6a81c7379ba05b"
    sk2 = derive_key(bytes([2] * 64), 0, 0, False)
    assert ed25519_publickey(sk2).hex() == \
        "384d0633d25725798cb3fa2b349dff39d1ff2d623e8a5d79fcd632e91740c2c1"
    assert address_from_public_key(ed25519_publickey(sk2), "mainnet") == \
        "SD1f28fa3d42b184f0ce7e84809e89efde6637bd597"
    V3 = "lumecad gova gureri debedi rida kapa buliham gel pozesu zireke wozaga tit"
    assert entropy_to_mnemonic(bytes([3] * 32)) == V3
    assert mnemonic_to_seed(V3, "").hex() == \
        "ef8510cce605655da029f274d9920e69ac342a9b4ce492b138b847bc7d2ca5ec" \
        "04a20a45cfc95e00843634d522762cfa7239dd310cfae5e1765a3d82c663c3b2"
    assert address_from_mnemonic(V3, "", "mainnet") == \
        "SD1b28a5f7b7efee64a334f32f0fb72e736276a3bd9"

    # Transaction vector.
    sk7 = bytes([7] * 32)
    pk7 = ed25519_publickey(sk7).hex()
    assert pk7 == "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c"
    owner = address_from_public_key(bytes.fromhex(pk7), "mainnet")
    assert owner == "SD15733ef1109c71b28d117680dde4417876ea6bca5"
    tx = build_signed_transfer(
        [{"txid": "aa" * 32, "index": 0, "owner": owner}],
        [{"address": "SD1" + "11" * 20, "amount": 1000}],
        10, 1_700_000_000, sk7.hex(), pk7, "mainnet")
    assert tx["hash"] == "4f7c71d635fcd3cedae89cf56baf4f8f85ff96104df1f6356b5b10c70fd46169"
    assert tx["inputs"][0]["signature"] == \
        "6fd6fd09c2f64c8f6267f0467cff2757cb47fed22497ad05cef355b5878148b8" \
        "575356ba2942c0ae8e24602f2331369b7b98979c7a38d4b67268d42290f6150c"
    assert validate_address(owner) and not validate_address("SD1bad")
    print("shadowdag_sdk self-test: ALL reference vectors match the chain [OK]")
