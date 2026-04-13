# NanoSatoshi-71 ⚡
**A high-performance Bitcoin Puzzle #71 solver tailored for the ESP32-WROOM.**

NanoSatoshi-71 is a lightweight, dual-core brute-force tool designed to tackle the famous Bitcoin "Puzzle" challenges (specifically range #71). It squeezes every bit of performance out of the ESP32 by using hardware-accelerated hashing and optimized elliptic curve operations.

---

## 🚀 Key Features
* **Dual-Core Parallelism:** Utilizes both ESP32 cores (Core 0 and Core 1) simultaneously for maximum key throughput.
* **ECC Point Addition Optimization:** Instead of performing costly full Scalar Multiplication ($d \cdot G$) for every key, the solver uses **Point Addition** ($Q + G$) to derive the next public key in the sequence.
* **Hardware Acceleration:** Leverages the ESP32's built-in hardware engine for **SHA256** computations.
* **Custom RIPEMD160:** Includes a manual, highly efficient implementation of RIPEMD160 to ensure compatibility across all ESP32 mbedTLS versions.
* **Zero-Stutter Statistics:** Real-time speed (Keys/s) and uptime monitoring via the Serial interface without blocking the solver tasks.

---

## 🛠️ Technical Specifications
| Feature | Implementation |
| :--- | :--- |
| **Architecture** | ESP32-WROOM (Dual-Core @ 240MHz) |
| **Curve** | SECP256K1 |
| **Hashing Chain** | Public Key (Compressed) → SHA256 → RIPEMD160 |
| **Target Range** | Puzzle #71 ($2^{70}$ to $2^{71}-1$) |
| **Framework** | Arduino ESP32 Core + mbedTLS |

---

## 📥 Installation

1.  **Prerequisites:**
    * [Arduino IDE](https://www.arduino.cc/en/software) or [PlatformIO](https://platformio.org/).
    * ESP32 Board Support installed.
2.  **Configuration:**
    * Open `bitcoin_puzzle.ino`.
    * Verify the `TARGET_HASH` matches the puzzle address you are targeting.
    * Set your CPU frequency to **240MHz** in your IDE settings for peak performance.
3.  **Flash:**
    * Connect your ESP32 and hit **Upload**.
    * Open the Serial Monitor at **115200 Baud**.

---

## 📈 Performance
The solver typically achieves a significant performance boost over standard implementations by avoiding redundant BigInt-to-String conversions in the hot loop.

> **Note:** Actual Keys/s may vary depending on your specific ESP32 silicon and compiler optimization settings (`-Ofast` recommended).

---

## ⚠️ Disclaimer
*This project is for **educational and research purposes only**. Brute-forcing Bitcoin private keys is statistically near-impossible for high-entropy ranges. This tool is designed to explore the limits of low-power microcontrollers in cryptographic applications. Use it responsibly.*

---

## 📄 License
MIT License - feel free to fork, modify, and improve!
