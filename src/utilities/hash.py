import struct, hashlib, mmh3

from typing import Union


def md5hash(data: str):
    try:
        return hashlib.md5(data.encode()).hexdigest()
    except Exception:
        raise Exception("Failed to hash browser_data")


def x64hash128(data: Union[str, bytes], seed: int = 0) -> str:
    if isinstance(data, str):
        data = data.encode()
    hash_bytes: bytes = mmh3.hash_bytes(data, seed=seed, x64arch=True)
    hash_parts: tuple[int, int] = struct.unpack("<QQ", hash_bytes)
    hash_hex_str: str = "{:016x}{:016x}".format(*hash_parts)

    return hash_hex_str