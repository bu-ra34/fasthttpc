import hashlib
import hmac
import os

                                                                              
                                                                             
                                                                          
                                                                            
                                                                       
if "CRYPTOGRAPHY_OPENSSL_NO_LEGACY" not in os.environ:
    os.environ["CRYPTOGRAPHY_OPENSSL_NO_LEGACY"] = "1"

                                                                            
                                                                        
                                                                             
                                                                     
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
    from cryptography.hazmat.primitives.asymmetric import x25519 as _ossl_x25519
    from cryptography.hazmat.primitives import serialization as _ossl_ser
    from cryptography.exceptions import InvalidTag as _InvalidTag
except ImportError as _import_err:
    raise ImportError(
        "fasthttpc 'cryptography' paketini ZORUNLU olarak gerektirir (AEAD, X25519 ve "
        "sertifika imza doğrulaması için). Saf Python şifreleme yedeği kaldırıldı. "
        "Kurulum: `pip install --upgrade cryptography`. "
        f"Asıl hata: {_import_err!r}"
    ) from _import_err


class FastAESGCM:
    """OpenSSL (AES-NI) tabanlı AES-GCM. encrypt_gcm/decrypt_gcm arayüzü."""
    def __init__(self, key: bytes):
        self._aead = AESGCM(key)

    def encrypt_gcm(self, iv: bytes, plaintext: bytes, aad: bytes = b'') -> tuple:
        out = self._aead.encrypt(iv, plaintext, aad)
        return out[:-16], out[-16:]

    def decrypt_gcm(self, iv: bytes, ciphertext: bytes, aad: bytes, auth_tag: bytes) -> bytes:
        try:
            return self._aead.decrypt(iv, ciphertext + auth_tag, aad)
        except _InvalidTag as e:
            raise ValueError(
                "GCM authentication tag mismatch: veri bozulmuş veya değiştirilmiş olabilir (olası MITM/tampering)."
            ) from e

    # Record katmanının sıcak yolu: ct||tag tek parça (bölüp yeniden birleştirmek iki
    # gereksiz kopya demekti). Doğrulama aynıdır: tag tutmazsa ValueError.
    def seal(self, iv: bytes, plaintext: bytes, aad: bytes = b'') -> bytes:
        """ciphertext || tag (16 bayt) döner."""
        return self._aead.encrypt(iv, plaintext, aad)

    def open(self, iv: bytes, ciphertext_and_tag: bytes, aad: bytes) -> bytes:
        """ciphertext || tag'i doğrular ve çözer; tag tutmazsa ValueError."""
        try:
            return self._aead.decrypt(iv, ciphertext_and_tag, aad)
        except _InvalidTag as e:
            raise ValueError(
                "GCM authentication tag mismatch: veri bozulmuş veya değiştirilmiş olabilir (olası MITM/tampering)."
            ) from e


class FastChaCha20Poly1305:
    """OpenSSL tabanlı ChaCha20-Poly1305. encrypt_aead/decrypt_aead arayüzü."""
    def __init__(self, key: bytes):
        self._aead = ChaCha20Poly1305(key)

    def encrypt_aead(self, nonce: bytes, plaintext: bytes, aad: bytes = b'') -> tuple:
        out = self._aead.encrypt(nonce, plaintext, aad)
        return out[:-16], out[-16:]

    def decrypt_aead(self, nonce: bytes, ciphertext: bytes, aad: bytes, auth_tag: bytes) -> bytes:
        try:
            return self._aead.decrypt(nonce, ciphertext + auth_tag, aad)
        except _InvalidTag as e:
            raise ValueError(
                "Poly1305 authentication tag mismatch: veri bozulmuş veya değiştirilmiş olabilir (olası MITM/tampering)."
            ) from e

    def seal(self, nonce: bytes, plaintext: bytes, aad: bytes = b'') -> bytes:
        """ciphertext || tag (16 bayt) döner."""
        return self._aead.encrypt(nonce, plaintext, aad)

    def open(self, nonce: bytes, ciphertext_and_tag: bytes, aad: bytes) -> bytes:
        """ciphertext || tag'i doğrular ve çözer; tag tutmazsa ValueError."""
        try:
            return self._aead.decrypt(nonce, ciphertext_and_tag, aad)
        except _InvalidTag as e:
            raise ValueError(
                "Poly1305 authentication tag mismatch: veri bozulmuş veya değiştirilmiş olabilir (olası MITM/tampering)."
            ) from e


class PureCryptoEngine:
    
                                       
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

    @classmethod
    def x25519(cls, k_bytes: bytes, u_bytes: bytes) -> bytes:
        """OpenSSL (cryptography) tabanlı X25519 — 32 byte, little-endian."""
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
        """Application trafik anahtarlarını türetir.

        Döner: (c_key, c_iv, s_key, s_iv, c_ats, s_ats)
        c_ats/s_ats (application traffic secret) KeyUpdate (RFC 8446 §7.2)
        için saklanmalıdır.
        """
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

        return c_key, c_iv, s_key, s_iv, c_ats, s_ats
