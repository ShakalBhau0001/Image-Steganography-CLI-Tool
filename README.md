# 📸 Image-Steganography-CLI-Tool 🔐

A Python-based **Image Steganography Command Line Tool** that allows you to
encrypt a secret message and embed it inside an **image (PNG)** using **LSB steganography**, and later **extract & decrypt** it securely using a password.
This CLI tool is built for **terminal users**, **automation**, and **security-focused experimentation**, combining **strong cryptography with invisible data hiding.**

---

## 🧱 Project Structure

```bash
Image-Steganography-CLI-Tool/
│
├── image_steganography.py      # Image steganography CLI tool
└── README.md                   # Project documentation
```

---

## ✨ Features

### 🔐 Encryption & Embedding

- Encrypts message using **Fernet (AES-128 encryption)**
- Derives key from password using **PBKDF2-HMAC (SHA256)**
- Embeds encrypted payload into WAV audio using **LSB (Least Significant Bit)**
- Supports:
    - Direct text input
    - Message from file

### 🔓 Extraction & Decryption

- Extracts embedded payload from WAV
- Uses stored salt to regenerate the Fernet key
- Decrypts message securely
- Outputs decrypted message to:
    - Terminal or
    - File

---

## 🛠 Technologies Used

| Technology                             | Purpose                         |
| -------------------------------------- | ------------------------------- |
| **Python 3**                           | Core language                   |
| **argparse**                           | CLI argument parsing            |
| **Pillow (PIL)**                       | Image processing                |
| **cryptography (Fernet + PBKDF2HMAC)** | Secure encryption               |
| **LSB Steganography**                  | Data hiding technique           |
| **struct / secrets / base64**          | Payload & cryptographic helpers |

---

## 📌 Requirements

Make sure you install required dependencies:

```bash
pip install cryptography pillow
```

Standard libraries like `os`, `secrets`, `argparse`, `base64`, and `struct` are already included with Python.

---

## ▶️ How to Run

**1. Clone the repository:**

```bash
git clone https://github.com/ShakalBhau0001/Image-Steganography-CLI-Tool.git
```

**2. Enter the project folder:**

```bash
cd Image-Steganography-CLI-Tool
```

**3. Run the GUI:**

```bash
python image_steganography.py
```

---

## ▶️ Usage

### 🔐 Encrypt & Embed

#### 1. Text Encrypt & Embed

``` bash
python image_steganography.py encrypt --in-image cover.png --out-image stego.png --password mypass --message "secret"
```

```bash
python image_steganography.py encrypt --in-image inputfile.png --out-image outputfile.png --password yourpassword --message "Enter Your Secret Message"
```

#### 2. Text File Encrypt & Embed

``` bash
python image_steganography.py encrypt --in-image cover.png --out-image stego.png --password mypass --message-file secret.txt
```

```bash
python image_steganography.py encrypt --in-image inputfile.png --out-image outputfile.png --password yourpassword --message-file Add Your Secret txt file
```

### 🔓 Decrypt & Extract

#### 1. Text Decrypt & Extract

``` bash
python image_steganography.py decrypt --in-image stego.png --password mypass
```

```bash
python image_steganography.py decrypt --in-image outputfile.png --password yourpassword
```

#### 2. Text File Decrypt & Extract

```bash
python image_steganography.py decrypt --in-image stego.png --password mypass123 --out-file output.txt
```

```bash
python image_steganography.py decrypt --in-image outputfile.png --password yourpassword --out-file filename.txt
```

---

## 📁 Supported Formats

- **Input Image:** PNG / RGB or RGBA images
- **Output Image:** PNG (RGBA)
- **Message Type:**
  - UTF-8 text
  - Binary files (via `--message-file`)

> ⚠️ Payload size depends on image resolution. Small images may not support large messages.

---

## ⚙️ How It Works

**1️⃣ Key Derivation**

- Password → PBKDF2-HMAC(SHA256, 390k iterations) → 32-byte key → Fernet key

**2️⃣ Encryption**

- Message encrypted using Fernet
- Payload format:
  ```bash
  [STEG][16-byte salt][4-byte length][encrypted data]
  ```

**3️⃣ Embedding**

- Each bit of payload embedded into:
    - **LSB of R, G, B channels**

- Alpha channel remains untouched
- Image visually unchanged

**4️⃣ Extraction**

- Reads LSB bits
- Reconstructs payload
- Validates MAGIC header
- Regenerates key from password + salt
- Decrypts message

---

## ⚠️ Common Errors

- **Wrong password** → Fernet Decryption fails
- **Wrong image** → MAGIC header not found
- **Small image** → Payload too large
- **Corrupted stego image** → Payload integrity error

---

## 🌟 Future Enhancements

- Auto capacity detection before embedding
- Progress indicator for large images
- Support for JPEG (with DCT-based steganography)
- Multi-file embedding
- Optional compression before encryption

---

## 📦 Extended Version

This repository focuses on a **specific steganography technique** implemented
as a **command-line (CLI) learning project**.

The goal of this project is to:
- Understand how steganography works at a practical level  
- Experiment with data hiding techniques  
- Learn how CLI-based security tools are structured  

For a **more advanced and combined implementation** that includes:
- Image steganography  
- Audio steganography  
- File encryption support  

please refer to:

🔗 **[StegaVault-CLI](https://github.com/ShakalBhau0001/StegaVault-CLI) (WIP)**

---

## ⚠️ Disclaimer

This project is intended for **educational and research purposes only**.

It is **not designed for real-world secure communication**.
Steganography alone does not guarantee secrecy and should not be considered
a replacement for proper cryptographic security.

---

## 🪪 Author

> **Creator: Shakal Bhau**

> **GitHub: [ShakalBhau0001](https://github.com/ShakalBhau0001)**

---

## ⭐ Support

If you like this project, consider giving it a ⭐ on GitHub!

---
