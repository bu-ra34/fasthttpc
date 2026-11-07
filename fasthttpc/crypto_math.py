import hashlib
import hmac
import os
import struct

                                                                              
                                                                             
                                                                          
                                                                            
                                                                       
if "CRYPTOGRAPHY_OPENSSL_NO_LEGACY" not in os.environ:
    os.environ["CRYPTOGRAPHY_OPENSSL_NO_LEGACY"] = "1"

                                                                            
                                                                        
                                                                             
                                                                     
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
    from cryptography.hazmat.primitives.asymmetric import x25519 as _ossl_x25519
    from cryptography.hazmat.primitives import serialization as _ossl_ser
    _OPENSSL_AVAILABLE = True
except Exception as _import_err:                                  
    _OPENSSL_AVAILABLE = False
    _OPENSSL_IMPORT_ERROR = _import_err


class FastAESGCM:
    """OpenSSL (AES-NI) tabanlı AES-GCM. PureAESGCM ile aynı arayüz (drop-in)."""
    def __init__(self, key: bytes):
        self._aead = AESGCM(key)

    def encrypt_gcm(self, iv: bytes, plaintext: bytes, aad: bytes = b'') -> tuple:
        out = self._aead.encrypt(iv, plaintext, aad)
        return out[:-16], out[-16:]

    def decrypt_gcm(self, iv: bytes, ciphertext: bytes, aad: bytes, auth_tag: bytes) -> bytes:
        try:
            return self._aead.decrypt(iv, ciphertext + auth_tag, aad)
        except Exception as e:
            raise ValueError(
                "GCM authentication tag mismatch: veri bozulmuş veya değiştirilmiş olabilir (olası MITM/tampering)."
            ) from e


class FastChaCha20Poly1305:
    """OpenSSL tabanlı ChaCha20-Poly1305. PureChaCha20Poly1305 ile aynı arayüz (drop-in)."""
    def __init__(self, key: bytes):
        self._aead = ChaCha20Poly1305(key)

    def encrypt_aead(self, nonce: bytes, plaintext: bytes, aad: bytes = b'') -> tuple:
        out = self._aead.encrypt(nonce, plaintext, aad)
        return out[:-16], out[-16:]

    def decrypt_aead(self, nonce: bytes, ciphertext: bytes, aad: bytes, auth_tag: bytes) -> bytes:
        try:
            return self._aead.decrypt(nonce, ciphertext + auth_tag, aad)
        except Exception as e:
            raise ValueError(
                "Poly1305 authentication tag mismatch: veri bozulmuş veya değiştirilmiş olabilir (olası MITM/tampering)."
            ) from e


class PureAESGCM:
    SBOX = (
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    )
    RCON = (0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36)

    def __init__(self, key: bytes):
        self.key = key
        self.key_size = len(key)
        if self.key_size not in (16, 32):
            raise ValueError(
                f"PureAESGCM yalnızca AES-128 ve AES-256 destekler "
                f"(verilen anahtar {self.key_size} byte). AES-192 için tur sayısı 12'dir "
                f"ve bu implementasyonda key expansion'ı yazılmamıştır."
            )
        self.rounds = 10 if self.key_size == 16 else 14
        self.w = self._key_expansion(key)

    def _sub_word(self, word):
        return (self.SBOX[(word >> 24) & 0xFF] << 24 | self.SBOX[(word >> 16) & 0xFF] << 16 |
                self.SBOX[(word >> 8) & 0xFF] << 8 | self.SBOX[word & 0xFF])

    def _rot_word(self, word):
        return ((word << 8) & 0xFFFFFFFF) | (word >> 24)

    def _key_expansion(self, key):
        if self.key_size == 16:
            w = list(struct.unpack('>4I', key))
            for i in range(4, 44):
                temp = w[i - 1]
                if i % 4 == 0:
                    temp = self._sub_word(self._rot_word(temp)) ^ (self.RCON[i // 4] << 24)
                w.append(w[i - 4] ^ temp)
        else:
            w = list(struct.unpack('>8I', key))
            for i in range(8, 60):
                temp = w[i - 1]
                if i % 8 == 0:
                    temp = self._sub_word(self._rot_word(temp)) ^ (self.RCON[i // 8] << 24)
                elif i % 8 == 4:
                    temp = self._sub_word(temp)
                w.append(w[i - 8] ^ temp)
        return w

    def _aes_encrypt_block(self, plaintext: bytes) -> bytes:
        state = list(plaintext)
        def add_round_key(s, round_idx):
            for c in range(4):
                word = self.w[round_idx * 4 + c]
                s[c*4]   ^= (word >> 24) & 0xFF; s[c*4+1] ^= (word >> 16) & 0xFF
                s[c*4+2] ^= (word >> 8) & 0xFF; s[c*4+3] ^= word & 0xFF
        def sub_bytes(s):
            for i in range(16): s[i] = self.SBOX[s[i]]
        def shift_rows(s):
            s[1], s[5], s[9], s[13] = s[5], s[9], s[13], s[1]
            s[2], s[6], s[10], s[14] = s[10], s[14], s[2], s[6]
            s[3], s[7], s[11], s[15] = s[15], s[3], s[7], s[11]
        def xtime(a): return (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)
        def mix_columns(s):
            for c in range(4):
                idx = c * 4
                a0, a1, a2, a3 = s[idx], s[idx+1], s[idx+2], s[idx+3]
                s[idx]   = xtime(a0^a1) ^ a1 ^ a2 ^ a3
                s[idx+1] = xtime(a1^a2) ^ a0 ^ a2 ^ a3
                s[idx+2] = xtime(a2^a3) ^ a0 ^ a1 ^ a3
                s[idx+3] = xtime(a3^a0) ^ a0 ^ a1 ^ a2
        add_round_key(state, 0)
        for r in range(1, self.rounds):
            sub_bytes(state); shift_rows(state); mix_columns(state); add_round_key(state, r)
        sub_bytes(state); shift_rows(state); add_round_key(state, self.rounds)
        return bytes(state)

    @staticmethod
    def _gf_mult(x: int, y: int) -> int:
        z = 0; v = x
        for i in range(128):
            if (y & (1 << (127 - i))): z ^= v
            if (v & 1): v = (v >> 1) ^ 0xe1000000000000000000000000000000
            else: v >>= 1
        return z

    def _ghash(self, h, data):
        y = 0
        for i in range(0, len(data), 16):
            y = self._gf_mult(y ^ int.from_bytes(data[i:i+16], 'big'), h)
        return y

    def encrypt_gcm(self, iv: bytes, plaintext: bytes, aad: bytes = b'') -> tuple:
        H = int.from_bytes(self._aes_encrypt_block(b'\x00' * 16), 'big')
        j0 = int.from_bytes(iv + b'\x00\x00\x00\x01', 'big')
        ciphertext = b''; counter = j0
        for i in range(0, len(plaintext), 16):
            counter = (counter & 0xFFFFFFFFFFFFFFFFFFFFFFFF00000000) | ((counter + 1) & 0xFFFFFFFF)
            cb = self._aes_encrypt_block(counter.to_bytes(16, 'big'))
            ciphertext += bytes(a ^ b for a, b in zip(plaintext[i:i+16], cb))
        def pad_16(d): return d + b'\x00'*((16 - len(d)%16)%16)
        ghash_in = pad_16(aad) + pad_16(ciphertext) + (len(aad)*8).to_bytes(8, 'big') + (len(ciphertext)*8).to_bytes(8, 'big')
        S = self._ghash(H, ghash_in)
        E_j0 = int.from_bytes(self._aes_encrypt_block(j0.to_bytes(16, 'big')), 'big')
        return ciphertext, (S ^ E_j0).to_bytes(16, 'big')

    def decrypt_gcm(self, iv: bytes, ciphertext: bytes, aad: bytes, auth_tag: bytes) -> bytes:
        H = int.from_bytes(self._aes_encrypt_block(b'\x00' * 16), 'big')
        j0 = int.from_bytes(iv + b'\x00\x00\x00\x01', 'big')

        def pad_16(d): return d + b'\x00' * ((16 - len(d) % 16) % 16)
        ghash_in = pad_16(aad) + pad_16(ciphertext) + (len(aad) * 8).to_bytes(8, 'big') + (len(ciphertext) * 8).to_bytes(8, 'big')
        S = self._ghash(H, ghash_in)
        E_j0 = int.from_bytes(self._aes_encrypt_block(j0.to_bytes(16, 'big')), 'big')
        expected_tag = (S ^ E_j0).to_bytes(16, 'big')

        if not hmac.compare_digest(expected_tag, auth_tag):
            raise ValueError("GCM authentication tag mismatch: veri bozulmuş veya değiştirilmiş olabilir (olası MITM/tampering).")

        plaintext = b''; counter = j0
        for i in range(0, len(ciphertext), 16):
            counter = (counter & 0xFFFFFFFFFFFFFFFFFFFFFFFF00000000) | ((counter + 1) & 0xFFFFFFFF)
            cb = self._aes_encrypt_block(counter.to_bytes(16, 'big'))
            plaintext += bytes(a ^ b for a, b in zip(ciphertext[i:i+16], cb))
        return plaintext

class PureChaCha20Poly1305:
    def __init__(self, key: bytes):
        self.key = key

    def chacha20_block(self, counter: int, nonce: bytes) -> bytes:
        constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
        k = list(struct.unpack('<8I', self.key))
        n = list(struct.unpack('<3I', nonce))
        state = constants + k + [counter] + n
        working_state = list(state)
        def ROTL(a, b): return (((a << b) & 0xFFFFFFFF) | (a >> (32 - b)))
        def quarter_round(x, a, b, c, d):
            x[a] = (x[a] + x[b]) & 0xFFFFFFFF; x[d] = ROTL(x[d] ^ x[a], 16)
            x[c] = (x[c] + x[d]) & 0xFFFFFFFF; x[b] = ROTL(x[b] ^ x[c], 12)
            x[a] = (x[a] + x[b]) & 0xFFFFFFFF; x[d] = ROTL(x[d] ^ x[a], 8)
            x[c] = (x[c] + x[d]) & 0xFFFFFFFF; x[b] = ROTL(x[b] ^ x[c], 7)
        for _ in range(10):
            quarter_round(working_state, 0, 4, 8, 12); quarter_round(working_state, 1, 5, 9, 13)
            quarter_round(working_state, 2, 6, 10, 14); quarter_round(working_state, 3, 7, 11, 15)
            quarter_round(working_state, 0, 5, 10, 15); quarter_round(working_state, 1, 6, 11, 12)
            quarter_round(working_state, 2, 7, 8, 13); quarter_round(working_state, 3, 4, 9, 14)
        out = bytearray(64)
        for i in range(16):
            struct.pack_into('<I', out, i * 4, (state[i] + working_state[i]) & 0xFFFFFFFF)
        return bytes(out)

    def _poly1305_mac(self, key: bytes, msg: bytes) -> bytes:
        r = int.from_bytes(key[0:16], 'little') & 0x0ffffffc0ffffffc0ffffffc0fffffff
        s = int.from_bytes(key[16:32], 'little')
        a = 0; p = (1 << 130) - 5
        for i in range(0, len(msg), 16):
            a = ((a + int.from_bytes(msg[i:i+16] + b'\x01', 'little')) * r) % p
        return ((a + s) & 0xffffffffffffffffffffffffffffffff).to_bytes(16, 'little')

    def encrypt_aead(self, nonce: bytes, plaintext: bytes, aad: bytes = b'') -> tuple:
        otk = self.chacha20_block(0, nonce)[:32]
        ciphertext = b''
        for i in range(0, len(plaintext), 64):
            block = self.chacha20_block((i // 64) + 1, nonce)
            ciphertext += bytes(a ^ b for a, b in zip(plaintext[i:i+64], block))
        def pad16(d): return d + b'\x00' * ((16 - len(d) % 16) % 16)
        mac_data = pad16(aad) + pad16(ciphertext) + struct.pack('<QQ', len(aad), len(ciphertext))
        return ciphertext, self._poly1305_mac(otk, mac_data)

    def decrypt_aead(self, nonce: bytes, ciphertext: bytes, aad: bytes, auth_tag: bytes) -> bytes:
        otk = self.chacha20_block(0, nonce)[:32]
        def pad16(d): return d + b'\x00' * ((16 - len(d) % 16) % 16)
        mac_data = pad16(aad) + pad16(ciphertext) + struct.pack('<QQ', len(aad), len(ciphertext))
        expected_tag = self._poly1305_mac(otk, mac_data)

        if not hmac.compare_digest(expected_tag, auth_tag):
            raise ValueError("Poly1305 authentication tag mismatch: veri bozulmuş veya değiştirilmiş olabilir (olası MITM/tampering).")

        plaintext = b''
        for i in range(0, len(ciphertext), 64):
            block = self.chacha20_block((i // 64) + 1, nonce)
            plaintext += bytes(a ^ b for a, b in zip(ciphertext[i:i+64], block))
        return plaintext

class PureCryptoEngine:
    P = 2**255 - 19
    A24 = 121665
    
                                       
    @classmethod
    def prf_tls12(cls, secret: bytes, label: bytes, seed: bytes, length: int) -> bytes:
        def p_hash(s, d, l):
            a = d; out = b''
            while len(out) < l:
                a = hmac.new(s, a, hashlib.sha256).digest()
                out += hmac.new(s, a + d, hashlib.sha256).digest()
            return out[:l]
        return p_hash(secret, label + seed, length)

    @classmethod
    def derive_tls12_keys(cls, pre_master_secret: bytes, client_random: bytes, server_random: bytes):
        master_secret = cls.prf_tls12(pre_master_secret, b"master secret", client_random + server_random, 48)
        key_block = cls.prf_tls12(master_secret, b"key expansion", server_random + client_random, 40)
        return master_secret, key_block[0:16], key_block[32:36], key_block[16:32], key_block[36:40]

    @classmethod
    def generate_tls12_finished(cls, master_secret: bytes, handshake_messages: bytes, is_client=True) -> bytes:
        label = b"client finished" if is_client else b"server finished"
        return cls.prf_tls12(master_secret, label, hashlib.sha256(handshake_messages).digest(), 12)

                                        
    @classmethod
    def hkdf_extract(cls, salt: bytes, input_key_material: bytes, hash_alg=hashlib.sha256) -> bytes:
        if not salt:
            salt = b"\x00" * hash_alg().digest_size
        return hmac.new(salt, input_key_material, hash_alg).digest()

    @classmethod
    def hkdf_expand(cls, prk: bytes, info: bytes, length: int, hash_alg=hashlib.sha256) -> bytes:
        hash_len = hash_alg().digest_size
        if length > 255 * hash_len:
            raise ValueError(f"HKDF-Expand en fazla {255 * hash_len} byte üretebilir.")
        t = b""
        okm = b""
        i = 1
        while len(okm) < length:
            t = hmac.new(prk, t + info + bytes([i]), hash_alg).digest()
            okm += t
            i += 1
        return okm[:length]

    @staticmethod
    def tls13_hkdf_expand_label(
        secret: bytes, label: str, context: bytes, length: int, hash_alg=hashlib.sha256
    ) -> bytes:
        """RFC 8446 §7.1 HKDF-Expand-Label.

        hash_alg, müzakere edilen cipher suite'in hash'i olmalıdır:
        TLS_AES_128_GCM_SHA256 / TLS_CHACHA20_POLY1305_SHA256 -> SHA-256,
        TLS_AES_256_GCM_SHA384 -> SHA-384. Sabit SHA-256 kullanmak
        SHA-384 suite'lerinde sessizce YANLIŞ anahtar üretir.
        """
        full_label = b"tls13 " + label.encode("ascii")
        hkdf_label = (
            length.to_bytes(2, "big")
            + len(full_label).to_bytes(1, "big")
            + full_label
            + len(context).to_bytes(1, "big")
            + context
        )
        return PureCryptoEngine.hkdf_expand(secret, hkdf_label, length, hash_alg=hash_alg)

    @staticmethod
    def _inv(x: int) -> int: return pow(x, PureCryptoEngine.P - 2, PureCryptoEngine.P)

    @classmethod
    def _x25519_pure(cls, k_bytes: bytes, u_bytes: bytes) -> bytes:
        k = int.from_bytes(k_bytes, 'little')
        k &= (1 << 254) - 8; k |= (1 << 254)
        u = int.from_bytes(u_bytes, 'little')
        x1 = u; x2, z2 = 1, 0; x3, z3 = u, 1; swap = 0
        for t in reversed(range(255)):
            k_t = (k >> t) & 1; swap ^= k_t
            if swap: x2, x3 = x3, x2; z2, z3 = z3, z2
            swap = k_t
            A_val = (x2 + z2) % cls.P; AA = (A_val * A_val) % cls.P
            B_val = (x2 - z2) % cls.P; BB = (B_val * B_val) % cls.P
            E = (AA - BB) % cls.P; C_val = (x3 + z3) % cls.P; D = (x3 - z3) % cls.P
            DA = (D * A_val) % cls.P; CB = (C_val * B_val) % cls.P
            x3 = ((DA + CB) ** 2) % cls.P; z3 = (x1 * ((DA - CB) ** 2)) % cls.P
            x2 = (AA * BB) % cls.P; z2 = (E * (AA + cls.A24 * E)) % cls.P 
        if swap: x2, x3 = x3, x2; z2, z3 = z3, z2
        return ((x2 * cls._inv(z2)) % cls.P).to_bytes(32, 'little')

    @classmethod
    def x25519(cls, k_bytes: bytes, u_bytes: bytes) -> bytes:
        """OpenSSL (cryptography) tabanlı hızlı X25519 — aynı çıktı formatı (32 byte, little-endian).
        cryptography/OpenSSL kullanılamıyorsa (bkz. _OPENSSL_AVAILABLE) otomatik olarak
        saf Python implementasyonuna düşer — yavaş ama her ortamda çalışır."""
        if not _OPENSSL_AVAILABLE:
            return cls._x25519_pure(k_bytes, u_bytes)
        if u_bytes == (9).to_bytes(32, 'little'):
            priv = _ossl_x25519.X25519PrivateKey.from_private_bytes(k_bytes)
            return priv.public_key().public_bytes(
                encoding=_ossl_ser.Encoding.Raw, format=_ossl_ser.PublicFormat.Raw,
            )
        priv = _ossl_x25519.X25519PrivateKey.from_private_bytes(k_bytes)
        peer_pub = _ossl_x25519.X25519PublicKey.from_public_bytes(u_bytes)
        return priv.exchange(peer_pub)

    @classmethod
    def generate_keypair(cls):
        priv = os.urandom(32)
        return priv, cls.x25519(priv, (9).to_bytes(32, 'little'))

    @classmethod
    def derive_tls13_keys(cls, shared_secret: bytes, handshake_hash: bytes, key_len: int,
                          hash_alg=hashlib.sha256):
        """Handshake trafik anahtarlarını türetir.

        Döner: (handshake_secret, c_key, c_iv, s_key, s_iv, c_hts, s_hts)
        s_hts, sunucunun Finished mesajını doğrulamak için gereklidir.
        """
        hash_len = hash_alg().digest_size
        empty_hash = hash_alg(b"").digest()

        early_secret = cls.hkdf_extract(b"\x00" * hash_len, b"\x00" * hash_len, hash_alg=hash_alg)
        derived_early = cls.tls13_hkdf_expand_label(
            early_secret, "derived", empty_hash, hash_len, hash_alg=hash_alg
        )
        hs_secret = cls.hkdf_extract(derived_early, shared_secret, hash_alg=hash_alg)

        c_hts = cls.tls13_hkdf_expand_label(hs_secret, "c hs traffic", handshake_hash, hash_len, hash_alg=hash_alg)
        s_hts = cls.tls13_hkdf_expand_label(hs_secret, "s hs traffic", handshake_hash, hash_len, hash_alg=hash_alg)

        c_key = cls.tls13_hkdf_expand_label(c_hts, "key", b"", key_len, hash_alg=hash_alg)
        c_iv  = cls.tls13_hkdf_expand_label(c_hts, "iv",  b"", 12,      hash_alg=hash_alg)
        s_key = cls.tls13_hkdf_expand_label(s_hts, "key", b"", key_len, hash_alg=hash_alg)
        s_iv  = cls.tls13_hkdf_expand_label(s_hts, "iv",  b"", 12,      hash_alg=hash_alg)

        return hs_secret, c_key, c_iv, s_key, s_iv, c_hts, s_hts

    @classmethod
    def derive_application_keys(cls, hs_secret: bytes, transcript_hash: bytes, key_len: int,
                                hash_alg=hashlib.sha256):
        hash_len = hash_alg().digest_size
        empty_hash = hash_alg(b"").digest()

        derived_hs = cls.tls13_hkdf_expand_label(
            hs_secret, "derived", empty_hash, hash_len, hash_alg=hash_alg
        )
        master_secret = cls.hkdf_extract(derived_hs, b"\x00" * hash_len, hash_alg=hash_alg)

        c_ats = cls.tls13_hkdf_expand_label(master_secret, "c ap traffic", transcript_hash, hash_len, hash_alg=hash_alg)
        s_ats = cls.tls13_hkdf_expand_label(master_secret, "s ap traffic", transcript_hash, hash_len, hash_alg=hash_alg)

        c_key = cls.tls13_hkdf_expand_label(c_ats, "key", b"", key_len, hash_alg=hash_alg)
        c_iv  = cls.tls13_hkdf_expand_label(c_ats, "iv",  b"", 12,      hash_alg=hash_alg)
        s_key = cls.tls13_hkdf_expand_label(s_ats, "key", b"", key_len, hash_alg=hash_alg)
        s_iv  = cls.tls13_hkdf_expand_label(s_ats, "iv",  b"", 12,      hash_alg=hash_alg)

        return c_key, c_iv, s_key, s_iv


# ---------------------------------------------------------------------------
# OpenSSL yoksa saf Python motoruna düş. Aynı arayüzü sunan sınıflar takas
# edilir; çağıran kod (tls_adapter) hangi motorun aktif olduğunu bilmez.
# ---------------------------------------------------------------------------
if not _OPENSSL_AVAILABLE:
    import sys as _sys
    print(
        f"[fasthttpc] UYARI: cryptography/OpenSSL yüklenemedi ({_OPENSSL_IMPORT_ERROR!r}). "
        f"Saf Python şifreleme motoruna düşülüyor — çalışır ama belirgin şekilde "
        f"YAVAŞTIR. Ayrıca sertifika imza doğrulaması (CertificateVerify) "
        f"'cryptography' olmadan YAPILAMAZ; bu modda bağlantılar reddedilir. "
        f"`pip install --upgrade cryptography` kalıcı çözümdür.",
        file=_sys.stderr,
    )
    FastAESGCM = PureAESGCM
    FastChaCha20Poly1305 = PureChaCha20Poly1305
