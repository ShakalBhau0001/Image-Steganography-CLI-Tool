import argparse
import os
import struct
import secrets
import base64
from PIL import Image
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet


# Crypto helpers


def derive_fernet_key_from_password(
    password: str, salt: bytes, iterations: int = 390000
) -> bytes:
    password_bytes = password.encode("utf-8")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    key = kdf.derive(password_bytes)
    return base64.urlsafe_b64encode(key)


# LSB helpers


def bytes_to_bits(data: bytes):
    for byte in data:
        for i in range(7, -1, -1):
            yield (byte >> i) & 1


def embed_payload_in_image(input_image: str, payload: bytes, output_image: str):
    img = Image.open(input_image)

    if img.mode not in ("RGB", "RGBA"):
        img = img.convert("RGBA")
    else:
        img = img.convert("RGBA")

    width, height = img.size
    total_channels = width * height * 3
    bits_needed = len(payload) * 8

    if bits_needed > total_channels:
        raise ValueError(
            f"Payload too large: needs {bits_needed} bits, image supports {total_channels} bits"
        )

    pixels = list(img.getdata())
    bit_iter = bytes_to_bits(payload)

    new_pixels = []
    for r, g, b, a in pixels:
        rgb = [r, g, b]
        for i in range(3):
            try:
                bit = next(bit_iter)
                rgb[i] = (rgb[i] & ~1) | bit
            except StopIteration:
                pass
        new_pixels.append((rgb[0], rgb[1], rgb[2], a))

    out = Image.new("RGBA", img.size)
    out.putdata(new_pixels)
    out.save(output_image, format="PNG")


def extract_payload_from_image(stego_image: str, length_bytes: int) -> bytes:
    img = Image.open(stego_image).convert("RGBA")
    pixels = list(img.getdata())

    bits = []
    for r, g, b, a in pixels:
        bits.extend([r & 1, g & 1, b & 1])

    required_bits = length_bytes * 8
    if required_bits > len(bits):
        raise ValueError("Not enough embedded data")

    out = bytearray()
    for i in range(0, required_bits, 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i + j]
        out.append(byte)

    return bytes(out)


# Payload format

MAGIC = b"STEG"


def make_payload(encrypted: bytes, salt: bytes) -> bytes:
    return MAGIC + salt + struct.pack(">I", len(encrypted)) + encrypted


def parse_payload(raw: bytes):
    if raw[:4] != MAGIC:
        raise ValueError("MAGIC header not found")

    salt = raw[4:20]
    enc_len = struct.unpack(">I", raw[20:24])[0]
    encrypted = raw[24 : 24 + enc_len]
    return salt, encrypted


# High-level operations


def encrypt_image(args):
    if not os.path.exists(args.in_image):
        raise FileNotFoundError("Input image not found")

    if args.message:
        message_bytes = args.message.encode("utf-8")
    elif args.message_file:
        with open(args.message_file, "rb") as f:
            message_bytes = f.read()
    else:
        raise ValueError("Provide --message or --message-file")

    salt = secrets.token_bytes(16)
    key = derive_fernet_key_from_password(args.password, salt)
    encrypted = Fernet(key).encrypt(message_bytes)

    payload = make_payload(encrypted, salt)
    embed_payload_in_image(args.in_image, payload, args.out_image)

    print(f"[+] Message encrypted & embedded → {args.out_image}")


def decrypt_image(args):
    if not os.path.exists(args.in_image):
        raise FileNotFoundError("Stego image not found")

    header = extract_payload_from_image(args.in_image, 24)
    if header[:4] != MAGIC:
        raise ValueError("No valid payload found")

    salt = header[4:20]
    enc_len = struct.unpack(">I", header[20:24])[0]

    full_payload = extract_payload_from_image(args.in_image, 24 + enc_len)
    salt2, encrypted = parse_payload(full_payload)

    if salt != salt2:
        raise ValueError("Payload corruption detected")

    key = derive_fernet_key_from_password(args.password, salt)
    decrypted = Fernet(key).decrypt(encrypted)

    if args.out_file:
        with open(args.out_file, "wb") as f:
            f.write(decrypted)
        print(f"[+] Message extracted → {args.out_file}")
    else:
        try:
            print(decrypted.decode("utf-8"))
        except UnicodeDecodeError:
            print(decrypted)


# CLI


def main():
    parser = argparse.ArgumentParser(description="Image Steganography CLI")
    sub = parser.add_subparsers(dest="cmd", required=True)

    enc = sub.add_parser("encrypt", help="Encrypt & embed message into image")
    enc.add_argument("--in-image", required=True)
    enc.add_argument("--out-image", required=True)
    enc.add_argument("--password", required=True)
    enc.add_argument("--message")
    enc.add_argument("--message-file")

    dec = sub.add_parser("decrypt", help="Extract & decrypt message from image")
    dec.add_argument("--in-image", required=True)
    dec.add_argument("--password", required=True)
    dec.add_argument("--out-file")

    args = parser.parse_args()

    if args.cmd == "encrypt":
        encrypt_image(args)
    elif args.cmd == "decrypt":
        decrypt_image(args)


if __name__ == "__main__":
    main()
  
