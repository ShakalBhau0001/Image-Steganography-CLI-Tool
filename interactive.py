import os
import struct
import secrets
import base64
import sys
import warnings
from PIL import Image
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet, InvalidToken
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.text import Text
from rich.rule import Rule
from rich import box
from rich.align import Align
from rich.style import Style
from rich.padding import Padding

warnings.filterwarnings(
    "ignore",
    category=DeprecationWarning,
    module="PIL",
)

console = Console()


def derive_fernet_key(password: str, salt: bytes, iterations: int = 390000) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    key = kdf.derive(password.encode("utf-8"))
    return base64.urlsafe_b64encode(key)


# LSB Helpers


def bytes_to_bits(data: bytes):
    for byte in data:
        for i in range(7, -1, -1):
            yield (byte >> i) & 1


def embed_payload(input_image: str, payload: bytes, output_image: str):
    with Image.open(input_image) as image:
        img = image.convert("RGBA")

    width, height = img.size
    total_channels = width * height * 3
    if len(payload) * 8 > total_channels:
        raise ValueError(
            f"Payload too large: needs {len(payload) * 8} bits, image has {total_channels}"
        )

    pixels = list(img.getdata())
    bit_iter = bytes_to_bits(payload)
    new_pixels = []
    finished = False

    for r, g, b, a in pixels:
        rgb = [r, g, b]

        if not finished:
            for i in range(3):
                try:
                    rgb[i] = (rgb[i] & ~1) | next(bit_iter)
                except StopIteration:
                    finished = True
                    break

        new_pixels.append((rgb[0], rgb[1], rgb[2], a))

    out = Image.new("RGBA", img.size)
    out.putdata(new_pixels)
    out.save(output_image, format="PNG")


def extract_payload(stego_image: str, length_bytes: int) -> bytes:
    with Image.open(stego_image) as image:
        img = image.convert("RGBA")

    pixels = list(img.getdata())
    required_bits = length_bytes * 8
    available_bits = len(pixels) * 3
    if required_bits > available_bits:
        raise ValueError("Not enough pixel data to extract payload")

    out = bytearray()
    byte = 0
    bit_count = 0
    extracted_bits = 0
    for r, g, b, a in pixels:
        for bit in (r & 1, g & 1, b & 1):
            byte = (byte << 1) | bit
            bit_count += 1
            extracted_bits += 1

            if bit_count == 8:
                out.append(byte)
                byte = 0
                bit_count = 0

            if extracted_bits >= required_bits:
                return bytes(out)

    return bytes(out)


# Payload Format

MAGIC = b"STEG"


def make_payload(encrypted: bytes, salt: bytes) -> bytes:
    return MAGIC + salt + struct.pack(">I", len(encrypted)) + encrypted


def parse_payload(raw: bytes):
    if len(raw) < 24:
        raise ValueError("Incomplete payload header")

    if raw[:4] != MAGIC:
        raise ValueError("MAGIC header not found — no valid steg payload")

    salt = raw[4:20]
    enc_len = struct.unpack(">I", raw[20:24])[0]
    expected_size = 24 + enc_len
    if len(raw) < expected_size:
        raise ValueError("Payload appears to be truncated or corrupted")

    encrypted = raw[24:expected_size]
    return salt, encrypted


def print_banner():
    console.clear()
    banner = Text()
    banner.append("  ░██████╗████████╗███████╗ ██████╗  \n", style="bold cyan")
    banner.append("  ██╔════╝╚══██╔══╝██╔════╝██╔════╝  \n", style="bold cyan")
    banner.append("  ╚██████╗   ██║   █████╗  ██║  ███╗ \n", style="bold blue")
    banner.append("   ╚════██╗  ██║   ██╔══╝  ██║   ██║ \n", style="bold blue")
    banner.append("  ██████╔╝  ██║   ███████╗╚██████╔╝ \n", style="bold magenta")
    banner.append("  ╚═════╝   ╚═╝   ╚══════╝ ╚═════╝  \n", style="bold magenta")
    banner.append(
        "\n  Image Steganography  •  LSB + Fernet/PBKDF2\n", style="dim white"
    )
    console.print(Panel(Align.center(banner), border_style="cyan", box=box.DOUBLE_EDGE))


def divider(title: str = ""):
    console.print(Rule(title, style="dim cyan"))


def success(msg: str):
    console.print(f"\n  [bold green]✔[/bold green]  {msg}\n")


def error(msg: str):
    console.print(f"\n  [bold red]✘[/bold red]  {msg}\n")


def info(msg: str):
    console.print(f"  [bold yellow]ℹ[/bold yellow]  {msg}")


def prompt_path(label: str, must_exist: bool = False) -> str:
    while True:
        path = Prompt.ask(f"  [cyan]{label}[/cyan]").strip()
        if must_exist and not os.path.exists(path):
            error(f"File not found: [bold]{path}[/bold]")
        else:
            return path


def prompt_password(label: str = "Password") -> str:
    return Prompt.ask(f"  [cyan]{label}[/cyan]", password=True)


def run_encrypt():
    console.print()
    divider("🔒  ENCRYPT & EMBED")
    console.print()
    in_image = prompt_path("Cover image path (input)", must_exist=True)
    with Image.open(in_image) as img:
        width, height = img.size

    capacity_bytes = (width * height * 3) // 8
    info(f"Image capacity : [bold]{capacity_bytes:,}[/bold] bytes")
    out_image = prompt_path("Output stego-image path (e.g. out.png)")
    console.print()
    console.print("  [cyan]Message source[/cyan]")
    choice = Prompt.ask(
        "  [1] Type message   [2] Load from file\n  Choice",
        choices=["1", "2"],
        default="1",
    )

    if choice == "1":
        message_bytes = Prompt.ask("\n  [cyan]Enter secret message[/cyan]").encode(
            "utf-8"
        )
    else:
        mfile = prompt_path("Message file path", must_exist=True)
        with open(mfile, "rb") as f:
            message_bytes = f.read()

        info(f"Loaded {len(message_bytes)} bytes from [bold]{mfile}[/bold]")

    password = prompt_password("Encryption password")
    console.print()
    with console.status(
        "[bold cyan]Encrypting & embedding…[/bold cyan]",
        spinner="dots",
    ):
        salt = secrets.token_bytes(16)
        key = derive_fernet_key(password, salt)
        encrypted = Fernet(key).encrypt(message_bytes)
        payload = make_payload(encrypted, salt)
        embed_payload(in_image, payload, out_image)

    success(f"Message embedded → [bold white]{out_image}[/bold white]")
    info(f"Payload size : [bold]{len(payload)}[/bold] bytes")
    info(f"Image        : [bold]{in_image}[/bold] → [bold]{out_image}[/bold]")
    console.print()


def run_decrypt():
    console.print()
    divider("🔓  EXTRACT & DECRYPT")
    console.print()
    in_image = prompt_path("Stego-image path (input)", must_exist=True)
    password = prompt_password("Decryption password")
    out_file = Prompt.ask(
        "\n  [cyan]Save to file? (Leave blank to print to terminal)[/cyan]",
        default="",
    ).strip()

    console.print()
    with console.status(
        "[bold cyan]Extracting & decrypting…[/bold cyan]",
        spinner="dots",
    ):
        header = extract_payload(in_image, 24)
        if header[:4] != MAGIC:
            error("No valid steg payload found in this image.")
            return

        salt = header[4:20]
        enc_len = struct.unpack(">I", header[20:24])[0]
        full = extract_payload(in_image, 24 + enc_len)
        salt2, encrypted = parse_payload(full)

        if salt != salt2:
            error("Payload corruption detected — aborting.")
            return

        key = derive_fernet_key(password, salt)

        try:
            decrypted = Fernet(key).decrypt(encrypted)
        except InvalidToken:
            error("Incorrect password or corrupted image.")
            return

    if out_file:
        with open(out_file, "wb") as f:
            f.write(decrypted)

        success(f"Decrypted content saved → [bold white]{out_file}[/bold white]")

    else:
        console.print()
        divider("Decrypted Message")

        try:
            console.print(
                Padding(
                    decrypted.decode("utf-8"),
                    (1, 4),
                ),
                style="bold white",
            )
        except UnicodeDecodeError:
            console.print(
                Padding(repr(decrypted), (1, 4)),
                style="bold white",
            )

        divider()
        console.print()


def show_about():
    console.print()
    table = Table(
        box=box.SIMPLE_HEAVY, border_style="cyan", show_header=False, padding=(0, 2)
    )
    table.add_column(style="bold cyan", width=22)
    table.add_column(style="white")
    table.add_row("Encryption", "Fernet (AES-128-CBC + HMAC-SHA256)")
    table.add_row("KDF", "PBKDF2-HMAC-SHA256 (390,000 iterations)")
    table.add_row("Salt", "16 bytes — random per operation")
    table.add_row("Steganography", "LSB (Least Significant Bit) — RGB channels")
    table.add_row("Payload magic", "STEG header for integrity check")
    table.add_row("Image output", "Always PNG (lossless, preserves LSBs)")
    console.print(
        Panel(table, title="[bold cyan]ℹ  About STEG[/bold cyan]", border_style="cyan")
    )
    console.print()


MENU_ITEMS = [
    ("1", "🔒  Encrypt & embed message into image"),
    ("2", "🔓  Extract & decrypt message from image"),
    ("3", "ℹ   About / Algorithm info"),
    ("0", "🚪  Exit"),
]


def draw_menu():
    table = Table(
        box=box.ROUNDED, border_style="cyan", show_header=False, padding=(0, 3)
    )
    table.add_column("key", style="bold magenta", width=4)
    table.add_column("action", style="white")

    for key, label in MENU_ITEMS:
        table.add_row(f"[{key}]", label)

    console.print(Align.center(table))


def main():
    while True:
        print_banner()
        draw_menu()
        console.print()
        choice = Prompt.ask(
            "  [bold cyan]Select option[/bold cyan]",
            choices=["0", "1", "2", "3"],
            show_choices=False,
        )
        if choice == "1":
            try:
                run_encrypt()
            except ValueError as e:
                error(str(e))
            except Exception as e:
                error(f"Unexpected error: {e}")
        elif choice == "2":
            try:
                run_decrypt()
            except ValueError as e:
                error(str(e))
            except Exception as e:
                error(f"Unexpected error: {e}")
        elif choice == "3":
            show_about()
        elif choice == "0":
            console.print()
            console.print(
                Panel(
                    Align.center(
                        Text(
                            "See You Soon ! Stay hidden, stay secure. 🕵️",
                            style="bold cyan",
                        )
                    ),
                    border_style="magenta",
                    box=box.DOUBLE_EDGE,
                )
            )
            console.print()
            sys.exit(0)
        if choice != "0":
            Prompt.ask("  [dim]Press Enter to return to menu…[/dim]", default="")


if __name__ == "__main__":
    main()
