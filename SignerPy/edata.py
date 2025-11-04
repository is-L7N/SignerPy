import base64
import json
from struct import pack, unpack
from typing import Generator
from os import urandom
import hashlib
import hmac
import time
import string
import os
from datetime import datetime
from enum import Enum
import zlib
import SignerPy
import pickle
import secrets
from dataclasses import dataclass
from threading import Lock
import logging

#L7N 🇮🇶 
#https://github.com/is-L7N
class EncryptionMode(Enum):
    STANDARD = 1
    SECURE = 2
    ULTRA_SECURE = 3

@dataclass
class CryptoConfig:
    mode: EncryptionMode
    key_derivation_iterations: int
    enable_authentication: bool
    compression_enabled: bool
    max_attempts: int

class AdvancedChaCha20:
    def __init__(self, key: bytes, nonce: bytes, counter: int = 0, rounds: int = 20):
        if len(key) not in [16, 24, 32]:
            raise ValueError("Key must be 16, 24, or 32 bytes")
        if len(nonce) != 12:
            raise ValueError("Nonce must be 12 bytes")
        self.key = key
        self.nonce = nonce
        self.counter = counter
        self.rounds = rounds
        self._keystream_cache = {}
        self._cache_lock = Lock()
        self._performance_metrics = {
            'blocks_generated': 0,
            'bytes_processed': 0,
            'start_time': time.time()
        }

    @staticmethod
    def _rotl32(x: int, n: int) -> int:
        return ((x << n) & 0xFFFFFFFF) | (x >> (32 - n))

    @staticmethod
    def _quarter_round(s, a, b, c, d):
        s[a] = (s[a] + s[b]) & 0xFFFFFFFF
        s[d] ^= s[a]
        s[d] = AdvancedChaCha20._rotl32(s[d], 16)
        s[c] = (s[c] + s[d]) & 0xFFFFFFFF
        s[b] ^= s[c]
        s[b] = AdvancedChaCha20._rotl32(s[b], 12)
        s[a] = (s[a] + s[b]) & 0xFFFFFFFF
        s[d] ^= s[a]
        s[d] = AdvancedChaCha20._rotl32(s[d], 8)
        s[c] = (s[c] + s[d]) & 0xFFFFFFFF
        s[b] ^= s[c]
        s[b] = AdvancedChaCha20._rotl32(s[b], 7)

    def _chacha20_block(self, counter: int) -> bytes:
        cache_key = (counter, self.rounds)
        with self._cache_lock:
            if cache_key in self._keystream_cache:
                return self._keystream_cache[cache_key]

        s = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
        s += [unpack("<I", self.key[i*4:(i+1)*4])[0] for i in range(8)]
        s.append(counter & 0xFFFFFFFF)
        s += [unpack("<I", self.nonce[i*4:(i+1)*4])[0] for i in range(3)]
        w = s[:]
        
        round_pairs = self.rounds // 2
        for _ in range(round_pairs):
            self._quarter_round(w, 0, 4, 8, 12)
            self._quarter_round(w, 1, 5, 9, 13)
            self._quarter_round(w, 2, 6, 10, 14)
            self._quarter_round(w, 3, 7, 11, 15)
            self._quarter_round(w, 0, 5, 10, 15)
            self._quarter_round(w, 1, 6, 11, 12)
            self._quarter_round(w, 2, 7, 8, 13)
            self._quarter_round(w, 3, 4, 9, 14)

        result = b''.join(pack("<I", (w[i] + s[i]) & 0xFFFFFFFF) for i in range(16))
        
        with self._cache_lock:
            self._keystream_cache[cache_key] = result
            self._performance_metrics['blocks_generated'] += 1
            
        return result

    def keystream(self) -> Generator[int, None, None]:
        counter = self.counter
        while True:
            block = self._chacha20_block(counter)
            counter = (counter + 1) & 0xFFFFFFFF
            for b in block:
                yield b

    def process(self, data: bytes) -> bytes:
        ks = self.keystream()
        result = bytes([b ^ next(ks) for b in data])
        self._performance_metrics['bytes_processed'] += len(data)
        return result

    def get_performance_metrics(self):
        elapsed = time.time() - self._performance_metrics['start_time']
        return {
            'blocks_generated': self._performance_metrics['blocks_generated'],
            'bytes_processed': self._performance_metrics['bytes_processed'],
            'elapsed_time': elapsed,
            'bytes_per_second': self._performance_metrics['bytes_processed'] / elapsed if elapsed > 0 else 0
        }

class KeyDerivation:
    @staticmethod
    def pbkdf2_hmac_sha256(password: bytes, salt: bytes, iterations: int = 100000, dklen: int = 32) -> bytes:
        return hashlib.pbkdf2_hmac('sha256', password, salt, iterations, dklen)

    @staticmethod
    def generate_salt(length: int = 16) -> bytes:
        return urandom(length)

    @staticmethod
    def argon2id_derive(password: bytes, salt: bytes, time_cost: int = 3, memory_cost: int = 65536, parallelism: int = 4, dklen: int = 32) -> bytes:
        try:
            import argon2
            ph = argon2.PasswordHasher(time_cost=time_cost, memory_cost=memory_cost, parallelism=parallelism, hash_len=dklen, salt_len=len(salt))
            return ph.hash(password, salt=salt).encode()
        except ImportError:
            return KeyDerivation.pbkdf2_hmac_sha256(password, salt, 100000, dklen)

class SecureRandom:
    @staticmethod
    def generate_secure_key(length: int = 32) -> bytes:
        return secrets.token_bytes(length)

    @staticmethod
    def generate_secure_nonce(length: int = 12) -> bytes:
        return secrets.token_bytes(length)

    @staticmethod
    def generate_crypto_string(length: int = 32) -> str:
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        return ''.join(secrets.choice(chars) for _ in range(length))

class Authentication:
    @staticmethod
    def calculate_hmac(data: bytes, key: bytes) -> bytes:
        return hmac.new(key, data, hashlib.sha256).digest()

    @staticmethod
    def verify_hmac(data: bytes, key: bytes, mac: bytes) -> bool:
        return hmac.compare_digest(Authentication.calculate_hmac(data, key), mac)

class Compression:
    @staticmethod
    def compress_data(data: bytes) -> bytes:
        return zlib.compress(data, level=9)

    @staticmethod
    def decompress_data(data: bytes) -> bytes:
        return zlib.decompress(data)

class CryptoManager:
    def __init__(self, master_password: str = None):
        self.master_password = master_password
        self.config = CryptoConfig(
            mode=EncryptionMode.SECURE,
            key_derivation_iterations=100000,
            enable_authentication=True,
            compression_enabled=True,
            max_attempts=3
        )
        self.logger = self._setup_logger()
        self._session_keys = {}
        self._session_lock = Lock()

    def _setup_logger(self):
        logger = logging.getLogger('CryptoManager')
        logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        return logger

    def derive_key_from_password(self, password: str, salt: bytes = None) -> tuple[bytes, bytes]:
        if salt is None:
            salt = KeyDerivation.generate_salt()
        key = KeyDerivation.pbkdf2_hmac_sha256(password.encode(), salt, self.config.key_derivation_iterations)
        return key, salt

    def encrypt_with_password(self, plaintext: bytes, password: str) -> str:
        salt = KeyDerivation.generate_salt()
        key, _ = self.derive_key_from_password(password, salt)
        nonce = SecureRandom.generate_secure_nonce()
        
        if self.config.compression_enabled:
            plaintext = Compression.compress_data(plaintext)
        
        cipher = AdvancedChaCha20(key, nonce)
        ciphertext = cipher.process(plaintext)
        
        if self.config.enable_authentication:
            auth_key = hashlib.sha256(key + b"auth").digest()
            mac = Authentication.calculate_hmac(ciphertext, auth_key)
        else:
            mac = b''
        
        payload = {
            'version': '2.0',
            'salt': base64.b64encode(salt).decode(),
            'nonce': base64.b64encode(nonce).decode(),
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'mac': base64.b64encode(mac).decode() if mac else '',
            'iterations': self.config.key_derivation_iterations,
            'timestamp': datetime.now().isoformat(),
            'compressed': self.config.compression_enabled
        }
        
        serialized = json.dumps(payload).encode()
        return base64.b64encode(serialized).decode()

    def decrypt_with_password(self, encrypted_data: str, password: str) -> bytes:
        try:
            decoded = base64.b64decode(encrypted_data)
            payload = json.loads(decoded)
            
            salt = base64.b64decode(payload['salt'])
            nonce = base64.b64decode(payload['nonce'])
            ciphertext = base64.b64decode(payload['ciphertext'])
            mac = base64.b64decode(payload['mac']) if payload['mac'] else b''
            
            key, _ = self.derive_key_from_password(password, salt)
            
            if self.config.enable_authentication and mac:
                auth_key = hashlib.sha256(key + b"auth").digest()
                if not Authentication.verify_hmac(ciphertext, auth_key, mac):
                    raise ValueError("Authentication failed - HMAC mismatch")
            
            cipher = AdvancedChaCha20(key, nonce)
            plaintext = cipher.process(ciphertext)
            
            if payload.get('compressed', False):
                plaintext = Compression.decompress_data(plaintext)
            
            return plaintext
            
        except Exception as e:
            self.logger.error(f"Decryption failed: {e}")
            raise

class MultiLayerEncryption:
    def __init__(self, layers: int = 3):
        self.layers = layers
        self.cipher_stack = []

    def add_encryption_layer(self, key: bytes, nonce: bytes):
        cipher = AdvancedChaCha20(key, nonce)
        self.cipher_stack.append(cipher)

    def encrypt(self, plaintext: bytes) -> bytes:
        data = plaintext
        for cipher in self.cipher_stack:
            data = cipher.process(data)
        return data

    def decrypt(self, ciphertext: bytes) -> bytes:
        data = ciphertext
        for cipher in reversed(self.cipher_stack):
            data = cipher.process(data)
        return data

class CryptoUtilities:
    @staticmethod
    def generate_key_pair() -> tuple[bytes, bytes]:
        private_key = SecureRandom.generate_secure_key(32)
        public_key = hashlib.sha256(private_key).digest()
        return private_key, public_key

    @staticmethod
    def key_exchange(private_key: bytes, other_public_key: bytes) -> bytes:
        shared_secret = hashlib.sha256(private_key + other_public_key).digest()
        return shared_secret

    @staticmethod
    def create_digital_signature(data: bytes, private_key: bytes) -> bytes:
        return hmac.new(private_key, data, hashlib.sha512).digest()

    @staticmethod
    def verify_digital_signature(data: bytes, signature: bytes, public_key: bytes) -> bool:
        expected = hmac.new(public_key, data, hashlib.sha512).digest()
        return hmac.compare_digest(expected, signature)

class SecureContainer:
    def __init__(self, data: bytes = None):
        self.data = data
        self.metadata = {
            'created': datetime.now().isoformat(),
            'modified': datetime.now().isoformat(),
            'size': len(data) if data else 0,
            'checksum': hashlib.sha256(data).hexdigest() if data else ''
        }
        self.encryption_keys = []
        self.access_log = []

    def add_encryption_key(self, key: bytes):
        self.encryption_keys.append(key)
        self._log_access("KEY_ADDED")

    def encrypt_container(self, password: str) -> str:
        manager = CryptoManager(password)
        serialized = pickle.dumps(self)
        return manager.encrypt_with_password(serialized, password)

    @classmethod
    def decrypt_container(cls, encrypted_data: str, password: str) -> 'SecureContainer':
        manager = CryptoManager(password)
        decrypted = manager.decrypt_with_password(encrypted_data, password)
        return pickle.loads(decrypted)

    def _log_access(self, action: str):
        self.access_log.append({
            'timestamp': datetime.now().isoformat(),
            'action': action,
            'data_size': len(self.data) if self.data else 0
        })

class PerformanceMonitor:
    def __init__(self):
        self.metrics = {}
        self.start_time = time.time()

    def start_measurement(self, operation: str):
        self.metrics[operation] = {
            'start': time.time(),
            'end': None,
            'duration': None
        }

    def end_measurement(self, operation: str):
        if operation in self.metrics:
            self.metrics[operation]['end'] = time.time()
            self.metrics[operation]['duration'] = (
                self.metrics[operation]['end'] - self.metrics[operation]['start']
            )

    def get_report(self) -> dict:
        total_duration = time.time() - self.start_time
        return {
            'operations': self.metrics,
            'total_duration': total_duration,
            'average_operation_time': sum(
                m['duration'] for m in self.metrics.values() if m['duration']
            ) / len([m for m in self.metrics.values() if m['duration']])
        }

class ExtendedChaCha20(AdvancedChaCha20):
    def __init__(self, key: bytes, nonce: bytes, counter: int = 0, rounds: int = 20, 
                 enable_cache: bool = True, parallel_blocks: int = 4):
        super().__init__(key, nonce, counter, rounds)
        self.enable_cache = enable_cache
        self.parallel_blocks = parallel_blocks
        self._precomputed_blocks = {}
        self._precompute_threads = []

    def precompute_blocks(self, start_counter: int, count: int):
        for i in range(count):
            counter = start_counter + i
            if counter not in self._precomputed_blocks:
                self._precomputed_blocks[counter] = self._chacha20_block(counter)

    def parallel_process(self, data: bytes) -> bytes:
        block_size = 64
        total_blocks = (len(data) + block_size - 1) // block_size
        
        self.precompute_blocks(self.counter, total_blocks)
        
        result = bytearray(len(data))
        for i in range(total_blocks):
            start_idx = i * block_size
            end_idx = min(start_idx + block_size, len(data))
            block_data = data[start_idx:end_idx]
            
            counter = self.counter + i
            keystream_block = self._precomputed_blocks[counter]
            
            for j in range(len(block_data)):
                result[start_idx + j] = block_data[j] ^ keystream_block[j]
        
        self.counter += total_blocks
        return bytes(result)

class CryptoBenchmark:
    @staticmethod
    def benchmark_encryption(data_sizes: list[int] = None, iterations: int = 100):
        if data_sizes is None:
            data_sizes = [1024, 10240, 102400]
        
        results = {}
        key = SecureRandom.generate_secure_key()
        nonce = SecureRandom.generate_secure_nonce()
        
        for size in data_sizes:
            data = urandom(size)
            times = []
            
            for _ in range(iterations):
                cipher = AdvancedChaCha20(key, nonce)
                start_time = time.perf_counter()
                cipher.process(data)
                end_time = time.perf_counter()
                times.append(end_time - start_time)
            
            avg_time = sum(times) / len(times)
            throughput = size / avg_time
            results[size] = {
                'average_time': avg_time,
                'throughput_bytes_per_second': throughput,
                'throughput_mbps': (throughput * 8) / (1024 * 1024)
            }
        
        return results

class SecurityAnalyzer:
    @staticmethod
    def analyze_entropy(data: bytes) -> dict:
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        total_bytes = len(data)
        entropy = 0.0
        for count in byte_counts:
            if count > 0:
                probability = count / total_bytes
                entropy -= probability * (probability and math.log2(probability))
        
        return {
            'shannon_entropy': entropy,
            'max_entropy': 8.0,
            'entropy_ratio': entropy / 8.0,
            'byte_distribution': byte_counts
        }

    @staticmethod
    def perform_avalanche_test(key: bytes, nonce: bytes, test_data: bytes) -> dict:
        cipher = AdvancedChaCha20(key, nonce)
        original_output = cipher.process(test_data)
        
        flipped_key = bytearray(key)
        flipped_key[0] ^= 1
        cipher_flipped = AdvancedChaCha20(bytes(flipped_key), nonce)
        flipped_output = cipher_flipped.process(test_data)
        
        differing_bits = 0
        for b1, b2 in zip(original_output, flipped_output):
            differing_bits += bin(b1 ^ b2).count('1')
        
        total_bits = len(original_output) * 8
        avalanche_effect = differing_bits / total_bits
        
        return {
            'differing_bits': differing_bits,
            'total_bits': total_bits,
            'avalanche_effect': avalanche_effect,
            'avalanche_percentage': avalanche_effect * 100
        }

class CryptoProtocol:
    def __init__(self, local_private_key: bytes, remote_public_key: bytes):
        self.local_private_key = local_private_key
        self.remote_public_key = remote_public_key
        self.session_key = CryptoUtilities.key_exchange(local_private_key, remote_public_key)
        self.sequence_number = 0
        self.replay_cache = set()
        self.max_replay_window = 1000

    def encrypt_message(self, message: bytes) -> dict:
        nonce = SecureRandom.generate_secure_nonce()
        message_key = hashlib.sha256(self.session_key + pack('<Q', self.sequence_number)).digest()
        
        cipher = AdvancedChaCha20(message_key, nonce)
        ciphertext = cipher.process(message)
        
        mac_key = hashlib.sha256(message_key + b"mac").digest()
        mac = Authentication.calculate_hmac(ciphertext + nonce + pack('<Q', self.sequence_number), mac_key)
        
        packet = {
            'sequence': self.sequence_number,
            'nonce': base64.b64encode(nonce).decode(),
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'mac': base64.b64encode(mac).decode()
        }
        
        self.sequence_number += 1
        return packet

    def decrypt_message(self, packet: dict) -> bytes:
        sequence = packet['sequence']
        nonce = base64.b64decode(packet['nonce'])
        ciphertext = base64.b64decode(packet['ciphertext'])
        mac = base64.b64decode(packet['mac'])
        
        if sequence in self.replay_cache:
            raise ValueError("Replay attack detected")
        
        if self.sequence_number - sequence > self.max_replay_window:
            raise ValueError("Sequence number outside replay window")
        
        message_key = hashlib.sha256(self.session_key + pack('<Q', sequence)).digest()
        mac_key = hashlib.sha256(message_key + b"mac").digest()
        
        expected_mac = Authentication.calculate_hmac(ciphertext + nonce + pack('<Q', sequence), mac_key)
        if not hmac.compare_digest(mac, expected_mac):
            raise ValueError("MAC verification failed")
        
        cipher = AdvancedChaCha20(message_key, nonce)
        message = cipher.process(ciphertext)
        
        self.replay_cache.add(sequence)
        if len(self.replay_cache) > self.max_replay_window * 2:
            self.replay_cache = set(sorted(self.replay_cache)[-self.max_replay_window:])
        
        self.sequence_number = max(self.sequence_number, sequence + 1)
        return message

class DistributedCrypto:
    def __init__(self, nodes: list[str] = None):
        self.nodes = nodes or []
        self.node_keys = {}
        self.shared_secrets = {}
        self.quorum_size = (len(nodes) // 2) + 1 if nodes else 1

    def add_node(self, node_id: str, public_key: bytes):
        self.node_keys[node_id] = public_key
        for existing_id, existing_key in self.node_keys.items():
            if existing_id != node_id:
                private_key = SecureRandom.generate_secure_key(32)
                shared_secret = CryptoUtilities.key_exchange(private_key, public_key)
                self.shared_secrets[(existing_id, node_id)] = shared_secret

    def distributed_encrypt(self, data: bytes) -> dict:
        shares = {}
        for i, node_id in enumerate(self.node_keys.keys()):
            if len(shares) >= self.quorum_size:
                break
            share_key = SecureRandom.generate_secure_key(32)
            nonce = SecureRandom.generate_secure_nonce()
            cipher = AdvancedChaCha20(share_key, nonce)
            shares[node_id] = {
                'ciphertext': base64.b64encode(cipher.process(data)).decode(),
                'nonce': base64.b64encode(nonce).decode()
            }
        
        return {
            'shares': shares,
            'quorum_size': self.quorum_size,
            'total_nodes': len(self.node_keys)
        }

class ChaCha20Poly1305:
    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("Key must be 32 bytes")
        self.key = key

    def encrypt(self, plaintext: bytes, associated_data: bytes = b'') -> dict:
        nonce = SecureRandom.generate_secure_nonce(12)
        cipher = AdvancedChaCha20(self.key, nonce)
        ciphertext = cipher.process(plaintext)
        
        auth_key = cipher._chacha20_block(0)
        mac_data = associated_data + nonce + ciphertext
        mac = Authentication.calculate_hmac(mac_data, auth_key[:32])
        
        return {
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'nonce': base64.b64encode(nonce).decode(),
            'mac': base64.b64encode(mac).decode(),
            'associated_data': base64.b64encode(associated_data).decode()
        }

    def decrypt(self, encrypted_data: dict) -> bytes:
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        nonce = base64.b64decode(encrypted_data['nonce'])
        mac = base64.b64decode(encrypted_data['mac'])
        associated_data = base64.b64decode(encrypted_data['associated_data'])
        
        auth_key = AdvancedChaCha20(self.key, nonce)._chacha20_block(0)
        mac_data = associated_data + nonce + ciphertext
        expected_mac = Authentication.calculate_hmac(mac_data, auth_key[:32])
        
        if not hmac.compare_digest(mac, expected_mac):
            raise ValueError("Authentication failed")
        
        cipher = AdvancedChaCha20(self.key, nonce)
        return cipher.process(ciphertext)

class CryptoStorage:
    def __init__(self, storage_path: str = "crypto_vault.db"):
        self.storage_path = storage_path
        self.entries = {}
        self._load_storage()

    def _load_storage(self):
        try:
            if os.path.exists(self.storage_path):
                with open(self.storage_path, 'rb') as f:
                    self.entries = pickle.load(f)
        except Exception:
            self.entries = {}

    def _save_storage(self):
        try:
            with open(self.storage_path, 'wb') as f:
                pickle.dump(self.entries, f)
        except Exception as e:
            logging.error(f"Failed to save storage: {e}")

    def store_encrypted_data(self, identifier: str, encrypted_data: str, metadata: dict = None):
        self.entries[identifier] = {
            'data': encrypted_data,
            'metadata': metadata or {},
            'created': datetime.now().isoformat(),
            'last_accessed': datetime.now().isoformat()
        }
        self._save_storage()

    def retrieve_encrypted_data(self, identifier: str) -> dict:
        if identifier in self.entries:
            entry = self.entries[identifier]
            entry['last_accessed'] = datetime.now().isoformat()
            self._save_storage()
            return entry
        raise KeyError(f"Identifier not found: {identifier}")

    def list_entries(self) -> list:
        return list(self.entries.keys())

class AdvancedCryptoFactory:
    @staticmethod
    def create_cipher_suite(mode: EncryptionMode = EncryptionMode.SECURE) -> AdvancedChaCha20:
        key = SecureRandom.generate_secure_key()
        nonce = SecureRandom.generate_secure_nonce()
        
        if mode == EncryptionMode.STANDARD:
            return AdvancedChaCha20(key, nonce, rounds=12)
        elif mode == EncryptionMode.SECURE:
            return AdvancedChaCha20(key, nonce, rounds=20)
        elif mode == EncryptionMode.ULTRA_SECURE:
            return ExtendedChaCha20(key, nonce, rounds=32, parallel_blocks=8)
        else:
            raise ValueError(f"Unknown encryption mode: {mode}")

    @staticmethod
    def create_secure_container(data: bytes, password: str) -> SecureContainer:
        container = SecureContainer(data)
        encrypted = container.encrypt_container(password)
        return encrypted

class CryptoMiddleware:
    def __init__(self, crypto_manager: CryptoManager):
        self.crypto_manager = crypto_manager
        self.cache = {}
        self.stats = {
            'encryption_operations': 0,
            'decryption_operations': 0,
            'cache_hits': 0,
            'cache_misses': 0
        }

    def encrypt_with_cache(self, plaintext: bytes, password: str, cache_key: str = None) -> str:
        if cache_key and cache_key in self.cache:
            self.stats['cache_hits'] += 1
            return self.cache[cache_key]
        
        self.stats['cache_misses'] += 1
        self.stats['encryption_operations'] += 1
        result = self.crypto_manager.encrypt_with_password(plaintext, password)
        
        if cache_key:
            self.cache[cache_key] = result
            
        return result

    def decrypt_with_cache(self, encrypted_data: str, password: str, cache_key: str = None) -> bytes:
        if cache_key and cache_key in self.cache:
            self.stats['cache_hits'] += 1
            return self.cache[cache_key]
        
        self.stats['cache_misses'] += 1
        self.stats['decryption_operations'] += 1
        result = self.crypto_manager.decrypt_with_password(encrypted_data, password)
        
        if cache_key:
            self.cache[cache_key] = result
            
        return result

    def get_statistics(self) -> dict:
        total_operations = self.stats['cache_hits'] + self.stats['cache_misses']
        hit_ratio = self.stats['cache_hits'] / total_operations if total_operations > 0 else 0
        return {**self.stats, 'cache_hit_ratio': hit_ratio}

def decrypt(edata: str, start_counter: int = 0) -> bytes:
    raw = base64.b64decode(edata)
    if len(raw) < 1 + 32 + 12:
        raise ValueError("edata too short")
    key = raw[1:1+32]
    nonce = raw[1+32:1+32+12]
    ciphertext = raw[1+32+12:]
    cipher = ChaCha20(key, nonce, start_counter)
    return cipher.process(ciphertext).decode('utf-8')

def encrypt(edata, key=urandom(32), nonce=urandom(12), start_counter: int = 0) -> str:
    cipher = ChaCha20(key, nonce, start_counter)
    ciphertext = cipher.process(edata)
    flag = b'\x01'
    raw = flag + key + nonce + ciphertext
    return base64.b64encode(raw).decode()

def pretty_print_json(data: bytes):
    try:
        obj = json.loads(data)
        print(json.dumps(obj, indent=4, ensure_ascii=False))
    except Exception:
        print(data.decode(errors='replace'))

class ChaCha20:
    def __init__(self, key: bytes, nonce: bytes, counter: int = 0):
        if len(key) != 32 or len(nonce) != 12:
            raise ValueError("Key must be 32 bytes and nonce must be 12 bytes")
        self.key = key
        self.nonce = nonce
        self.counter = counter

    @staticmethod
    def _rotl32(x: int, n: int) -> int:
        return ((x << n) & 0xFFFFFFFF) | (x >> (32 - n))

    @staticmethod
    def _quarter_round(s, a, b, c, d):
        s[a] = (s[a] + s[b]) & 0xFFFFFFFF
        s[d] ^= s[a]
        s[d] = ChaCha20._rotl32(s[d], 16)
        s[c] = (s[c] + s[d]) & 0xFFFFFFFF
        s[b] ^= s[c]
        s[b] = ChaCha20._rotl32(s[b], 12)
        s[a] = (s[a] + s[b]) & 0xFFFFFFFF
        s[d] ^= s[a]
        s[d] = ChaCha20._rotl32(s[d], 8)
        s[c] = (s[c] + s[d]) & 0xFFFFFFFF
        s[b] ^= s[c]
        s[b] = ChaCha20._rotl32(s[b], 7)

    def _chacha20_block(self, counter: int) -> bytes:
        s = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
        s += [unpack("<I", self.key[i*4:(i+1)*4])[0] for i in range(8)]
        s.append(counter & 0xFFFFFFFF)
        s += [unpack("<I", self.nonce[i*4:(i+1)*4])[0] for i in range(3)]
        w = s[:]
        for _ in range(10):
            self._quarter_round(w, 0, 4, 8, 12)
            self._quarter_round(w, 1, 5, 9, 13)
            self._quarter_round(w, 2, 6, 10, 14)
            self._quarter_round(w, 3, 7, 11, 15)
            self._quarter_round(w, 0, 5, 10, 15)
            self._quarter_round(w, 1, 6, 11, 12)
            self._quarter_round(w, 2, 7, 8, 13)
            self._quarter_round(w, 3, 4, 9, 14)
        return b''.join(pack("<I", (w[i] + s[i]) & 0xFFFFFFFF) for i in range(16))
    
    def keystream(self) -> Generator[int, None, None]:
        counter = self.counter
        while True:
            block = self._chacha20_block(counter)
            counter = (counter + 1) & 0xFFFFFFFF
            for b in block:
                yield b

    def process(self, data: bytes) -> bytes:
        ks = self.keystream()
        return bytes([b ^ next(ks) for b in data])
