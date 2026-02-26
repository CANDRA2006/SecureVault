## IN THE PROCESS
#  SecureVault

SecureVault adalah aplikasi enkripsi file berbasis **Hybrid C++ dan x86-64 Assembly** dengan arsitektur modular yang dirancang untuk eksplorasi sistem keamanan, optimisasi low-level, dan desain kriptografi terstruktur.

Project ini mengintegrasikan:
- C++ untuk logika tingkat tinggi
- Assembly untuk optimisasi operasi byte-level
- Dokumentasi arsitektur & threat modeling
- Simulasi serangan dan benchmark performa

> ⚠ Project ini ditujukan untuk pembelajaran dan eksperimen, bukan untuk penggunaan produksi.

---

##  Fitur Utama

-  Enkripsi & Dekripsi file berbasis password
-  Derivasi kunci (PBKDF2-style implementation)
-  HMAC untuk integritas data
-  Secure memory wiping (Assembly-level)
-  Optimisasi byte operation dengan x86-64 Assembly
-  Benchmark performa
-  Simulasi serangan (attack simulation)
-  Arsitektur modular dan terstruktur
-  uild system menggunakan CMake

---

## 🏗 Struktur Project

```
SecureVault/
│
├── build/
├── docs/
│   ├── architecture.md
│   └── threat_model.md
│
├── include/
│   ├── aes.h
│   ├── hmac.h
│   ├── pbkdf2.h
│   └── secure_memory.h
│
├── src/
│   ├── asm/
│   │   ├── aes_round.asm
│   │   ├── secure_wipe.asm
│   │   └── xor_core.asm
│   │
│   ├── crypto/
│   │   ├── aes.cpp
│   │   ├── hmac.cpp
│   │   ├── pbkdf2.cpp
│   │   └── secure_memory.cpp
│   │
│   ├── attack_simulation.cpp
│   ├── benchmark.cpp
│   ├── cli.cpp
│   └── main.cpp
│
├── tests/
├── .gitignore
├── CMakeLists.txt
└── README.md
```

---

## ⚙️ Cara Build (Windows + MSYS2 MinGW)

### 1️⃣ Masuk ke folder project

```bash
cd SecureVault
mkdir build
cd build
```

### 2️⃣ Generate Makefile

```bash
cmake -G "MinGW Makefiles" ..
```

### 3️⃣ Compile

```bash
mingw32-make
```

Jika berhasil, akan menghasilkan:

```
securevault.exe
```

---

## ▶️ Cara Menjalankan

### 🔐 Enkripsi File

```bash
./securevault enc test.txt mypassword
```

Output:
```
Encrypted.
```

---

### 🔓 Dekripsi File

```bash
./securevault dec test.txt mypassword
```

Output:
```
Decrypted.
```

---

## AUTHOR
CANDRA
