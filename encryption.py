import os
import struct
import hashlib
import base64
import zlib
import concurrent.futures
import requests
from io import BytesIO
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from dotenv import load_dotenv

load_dotenv()

# --- CUSTOM EXCEPTIONS (For APP & OS Error Handling) ---
class AegisError(Exception):
    """Base exception for Aegis Vault"""
    pass

class IntegrityError(AegisError):
    """Raised when SHA-256 verification fails (Data Integrity)"""
    pass

class DecryptionError(AegisError):
    """Raised when password/token is invalid (Security Fault)"""
    pass

# --- MULTI-THREADED ENCRYPTION ENGINE ---
class AegisEngine:
    def __init__(self, chunk_size=64 * 1024):
        self.chunk_size = chunk_size
        self.iterations = 480000
        self.salt_size = 16
        self.hash_size = 32
        
        # --- FIX: Load IPFS Gateway from .env with a fallback default ---
        self.pinata_jwt = os.getenv("PINATA_JWT")
        self.pinata_gateway = os.getenv("PINATA_GATEWAY", "https://gateway.pinata.cloud/ipfs/")

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Internal helper for key derivation using PBKDF2-HMAC-SHA256"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.iterations,
        )
        # Fernet requires a URL-safe base64 encoded 32-byte key
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def _encrypt_chunk(self, chunk, fernet):
        """Helper function for ThreadPool worker threads"""
        return fernet.encrypt(chunk)

    def encrypt(self, file_data: bytes, password: str) -> bytes:
        """
        Parallel Data Processing: 
        Splits data into chunks and processes them across CPU threads.
        """
        salt = os.urandom(self.salt_size)
        file_hash = hashlib.sha256(file_data).digest()
        compressed = zlib.compress(file_data)
        
        key = self._derive_key(password, salt)
        fernet = Fernet(key)
        
        # Divide data into segments for parallel processing
        chunks = [compressed[i:i + self.chunk_size] for i in range(0, len(compressed), self.chunk_size)]
        
        # Utilize ThreadPool for OS-level concurrency
        with concurrent.futures.ThreadPoolExecutor() as executor:
            encrypted_chunks = list(executor.map(lambda c: self._encrypt_chunk(c, fernet), chunks))
        
        output_io = BytesIO()
        output_io.write(salt)
        output_io.write(file_hash)
        
        # Structure the binary file: [Header][ChunkSize][EncryptedData]...
        for enc_chunk in encrypted_chunks:
            output_io.write(struct.pack(">I", len(enc_chunk)))
            output_io.write(enc_chunk)
            
        return output_io.getvalue()

    def decrypt(self, encrypted_data: bytes, password: str) -> bytes:
        """
        Streaming Decryption: Reassembles chunks and verifies integrity.
        """
        if len(encrypted_data) < (self.salt_size + self.hash_size):
            raise AegisError("Invalid payload: Missing metadata header.")

        input_io = BytesIO(encrypted_data)
        salt = input_io.read(self.salt_size)
        stored_hash = input_io.read(self.hash_size)
        
        key = self._derive_key(password, salt)
        fernet = Fernet(key)
        decomp_io = BytesIO()
        
        try:
            while True:
                size_bytes = input_io.read(4)
                if not size_bytes: break
                
                chunk_len = struct.unpack(">I", size_bytes)[0]
                enc_chunk = input_io.read(chunk_len)
                decomp_io.write(fernet.decrypt(enc_chunk))
        except Exception:
            raise DecryptionError("Decryption failed: Incorrect password.")
            
        try:
            final_data = zlib.decompress(decomp_io.getvalue())
        except zlib.error:
            raise AegisError("Decompression failed: Data corruption.")

        # Data Integrity Check (OS/Security)
        if hashlib.sha256(final_data).digest() != stored_hash:
            raise IntegrityError("CRITICAL: File integrity mismatch.")
            
        return final_data

    # --- IPFS UTILITIES ---

    def upload_to_ipfs(self, file_data: bytes, file_name: str = "vault.aegis"):
        """Broadcasts encrypted payload to Pinata IPFS."""
        if not self.pinata_jwt:
            return None
        
        url = "https://api.pinata.cloud/pinning/pinFileToIPFS"
        headers = {"Authorization": f"Bearer {self.pinata_jwt}"}
        
        try:
            files = {'file': (file_name, file_data)}
            response = requests.post(url, files=files, headers=headers)
            response.raise_for_status()
            return response.json().get('IpfsHash')
        except Exception as e:
            print(f"IPFS Upload Error: {e}")
            return None

    def fetch_from_ipfs(self, cid: str) -> bytes:
        """Retrieves encrypted payload using the configured Gateway."""
        # Clean the CID to ensure it appends correctly to the gateway URL
        clean_cid = cid.strip()
        fetch_url = f"{self.pinata_gateway}{clean_cid}"
        
        try:
            response = requests.get(fetch_url, timeout=30)
            response.raise_for_status()
            return response.content
        except Exception as e:
            print(f"IPFS Fetch Error: {e}")
            return None