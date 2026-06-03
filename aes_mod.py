from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import math
from concurrent.futures import ProcessPoolExecutor


BLOCK_SIZE = 16


def pkcs7_pad(data: bytes) -> bytes:
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len]) * pad_len


def pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        return data
    pad_len = data[-1]
    if pad_len < 1 or pad_len > BLOCK_SIZE:
        raise ValueError("Invalid padding")
    return data[:-pad_len]


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def encrypt_cbc(plaintext: bytes, key: bytes, iv: bytes = None) -> bytes:
    if iv is None:
        iv = get_random_bytes(BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_ECB)
    padded = pkcs7_pad(plaintext)
    blocks = [padded[i:i+BLOCK_SIZE] for i in range(0, len(padded), BLOCK_SIZE)]
    prev = iv
    out = bytearray()
    for b in blocks:
        x = xor_bytes(b, prev)
        e = cipher.encrypt(x)
        out.extend(e)
        prev = e
    return iv + bytes(out)


def decrypt_cbc(ciphertext: bytes, key: bytes) -> bytes:
    iv = ciphertext[:BLOCK_SIZE]
    body = ciphertext[BLOCK_SIZE:]
    cipher = AES.new(key, AES.MODE_ECB)
    blocks = [body[i:i+BLOCK_SIZE] for i in range(0, len(body), BLOCK_SIZE)]
    prev = iv
    out = bytearray()
    for b in blocks:
        d = cipher.decrypt(b)
        out.extend(xor_bytes(d, prev))
        prev = b
    return pkcs7_unpad(bytes(out))


def _encrypt_ctr_chunk(args):
    # worker-level function: encrypt a chunk using manual CTR
    key, nonce, start_counter, chunk = args
    aes = AES.new(key, AES.MODE_ECB)
    out = bytearray()
    blocks = [chunk[i:i+BLOCK_SIZE] for i in range(0, len(chunk), BLOCK_SIZE)]
    for i, blk in enumerate(blocks):
        ctr = start_counter + i
        counter_block = nonce + ctr.to_bytes(8, 'big')
        ks = aes.encrypt(counter_block)
        if len(blk) < BLOCK_SIZE:
            ks = ks[:len(blk)]
        out.extend(xor_bytes(blk, ks))
    return bytes(out)


def encrypt_ctr_seq(plaintext: bytes, key: bytes, nonce: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_ECB)
    out = bytearray()
    blocks = [plaintext[i:i+BLOCK_SIZE] for i in range(0, len(plaintext), BLOCK_SIZE)]
    for i, blk in enumerate(blocks):
        ctr = i
        counter_block = nonce + ctr.to_bytes(8, 'big')
        ks = aes.encrypt(counter_block)
        if len(blk) < BLOCK_SIZE:
            ks = ks[:len(blk)]
        out.extend(xor_bytes(blk, ks))
    return bytes(out)


def encrypt_ctr_parallel(plaintext: bytes, key: bytes, nonce: bytes, workers: int = 4) -> bytes:
    if len(nonce) != 8:
        raise ValueError("Nonce must be 8 bytes for this implementation")
    # split plaintext into nearly-equal chunks, align to block size
    n = len(plaintext)
    if n == 0:
        return b""
    # compute chunk boundaries ensuring block alignment
    base = n // workers
    chunks = []
    offsets = []
    start = 0
    for i in range(workers):
        end = start + base + (1 if i < (n % workers) else 0)
        if end > n:
            end = n
        # align to block boundary except final chunk
        if end < n:
            end = (end // BLOCK_SIZE) * BLOCK_SIZE
        if end <= start:
            break
        chunks.append(plaintext[start:end])
        offsets.append(start // BLOCK_SIZE)
        start = end
    # last trailing bytes (if any) go into a final chunk
    if start < n:
        chunks.append(plaintext[start:])
        offsets.append(start // BLOCK_SIZE)

    args = [(key, nonce, offsets[i], chunks[i]) for i in range(len(chunks))]
    if len(args) == 1:
        return _encrypt_ctr_chunk(args[0])

    results = [None] * len(args)
    with ProcessPoolExecutor(max_workers=min(workers, len(args))) as ex:
        for idx, res in enumerate(ex.map(_encrypt_ctr_chunk, args)):
            results[idx] = res

    return b"".join(results)


if __name__ == "__main__":
    # small smoke test
    key = get_random_bytes(16)
    nonce = get_random_bytes(8)
    data = b"Hello World!" * 1000
    c = encrypt_ctr_parallel(data, key, nonce, workers=2)
    s = encrypt_ctr_seq(data, key, nonce)
    assert c == s
    print("aes_mod: smoke test passed")
