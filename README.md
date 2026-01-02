<div align="center">

# CERBERUS

*Unleash Stealth, Master Resilience, Defy Detection Effortlessly*

[![Last Commit](https://img.shields.io/github/last-commit/yourusername/cerberus?style=flat-square&color=blue)](https://github.com/yourusername/cerberus)
[![Code Coverage](https://img.shields.io/badge/coverage-100.0%25-brightgreen?style=flat-square)](https://github.com/yourusername/cerberus)
[![Languages](https://img.shields.io/badge/languages-1-orange?style=flat-square)](https://github.com/yourusername/cerberus)

</div>

<br>

<div align="center">

### Built with the tools and technologies:

![Markdown](https://img.shields.io/badge/Markdown-000000?style=for-the-badge&logo=markdown&logoColor=white)
![C](https://img.shields.io/badge/C-00599C?style=for-the-badge&logo=c&logoColor=white)

</div>

---

<br>

## 🎯 Project Overview


**Cerberus** is a sophisticated C based framework for generating highly evasive Windows reverse shell payloads. With over 40 sophisticated evasion techniques, it represents the cutting edge in payload obfuscation and anti-detection technology. This project is designed as an educational tool for cybersecurity researchers, red teamers, and students to study and understand advanced offensive security techniques and modern evasion tactics used to bypass endpoint security solutions.

---

### ⚠️ Disclaimer

This tool is intended for **educational and research purposes only**. The techniques and code are meant to be studied in controlled lab environments to better understand how malware operates and how to build better defenses. **Do not** use this tool for any illegal or malicious activities. The author is not responsible for any misuse or damage caused by this program.

---

## 🚀 Core Features

This framework layers multiple state-of-the-art evasion techniques to create a payload that is resilient to both static and dynamic analysis.

#### 🛡️ **Advanced Evasion Techniques**
- **ETW Patching**: Neutralizes Event Tracing for Windows telemetry

- **AMSI Bypass**: Defeats Anti-Malware Scan Interface in memory

- **SmartScreen Bypass**: Multi-technique approach to bypass Windows reputation checks

- **API Hashing**: Resolves Windows APIs dynamically to avoid static detection

- **Direct Syscalls**: Uses direct system calls to bypass user-mode hooks

- **Process Hiding**: Conceals console window and masquerades as legitimate processes.

### 🔍 **Comprehensive Anti-Sandbox Detection**
- **Mouse Movement Analysis** - Distinguishes human vs automated input patterns
- **Memory Forensics** - Detects sandbox memory configurations
- **CPU & Hardware Profiling** - Identifies virtualized environments through:
  - CPU vendor checks (VMware, VirtualBox, Hyper-V, KVM)
  - Core count analysis
  - RDTSC timing discrepancies
  - Firmware table inspection (ACPI/SMBIOS)
- **Environmental Analysis**:
  - Disk space verification
  - RAM size validation
  - Screen resolution checks
  - Power status monitoring
  - Network adapter MAC analysis

### 🎭 **Stealth & Obfuscation**
- **Multi-layer Encryption** - XOR + custom encryption + Base64 encoding
- **Randomized Naming** - Dynamic function/variable name generation
- **Timestamp Stomping** - Anti-forensics file timestamp manipulation
- **Heap Debugger Detection** - Identifies analysis environments via heap flags
- **Parent Process Spoofing** - Validates legitimate parent processes

### ⏱️ **Behavioral Evasion**
- **Timing Analysis** - Statistical timing checks to detect accelerated environments
- **Sleep Acceleration Detection** - Identifies sped-up sandbox timers
- **User Activity Monitoring** - Checks for human interaction patterns
- **Session Analysis** - Distinguishes between user and service sessions

### 🔧 **Technical Capabilities**
- **Dynamic Shellcode Generation** - Custom reverse shell with configurable IP/port
- **Memory Protection Bypass** - Proper memory allocation and execution rights
- **Fallback Execution Methods** - Multiple techniques for reliable payload execution
- **Comprehensive Logging** - Detailed debugging and error tracking
- **Cross-Platform Compatibility** - Windows-focused with portable design elements

---

## 🚀 **Quick Start**

### Prerequisites
- Windows OS
- MinGW GCC Compiler
- Basic C compilation environment

### Usage
1. Clone the repository
2. Compile the generator
3. Run the executable
4. Enter target IP and port
5. Generate and deploy the payload

```bash
# Start your listener
nc -lvnp [the port you use to generate payload]

# Execute the generated payload
final_file.exe
```
---

## 📊 **Feature Breakdown**

| Category | Features Count | Key Technologies |
|----------|----------------|------------------|
| **Evasion** | 12+ | ETW, AMSI, SmartScreen, API Hashing |
| **Anti-Sandbox** | 15+ | Mouse, Memory, CPU, Timing, Environmental |
| **Stealth** | 8+ | Encryption, Obfuscation, Anti-forensics |
| **Execution** | 7+ | Shellcode, Memory Management, Fallbacks |

---
## 🔒 **Legal & Ethical Use**

- ✅ Use only on systems you own
- ✅ Authorized penetration testing
- ✅ Educational and research purposes
- ✅ Red team exercises with proper authorization

- ❌ Unauthorized hacking
- ❌ Malicious activities
- ❌ Testing on systems without permission
- ❌ Any illegal activities

## 🛠️ **Technical Requirements**

- **Platform**: Windows (x64)
- **Compiler**: MinGW GCC
- **Libraries**: Windows SDK, standard C libraries
- **Permissions**: Administrative privileges recommended for full functionality

## 🤝 **Contributing**

We welcome contributions from security researchers and developers. Please ensure all contributions align with ethical security research practices.

---

## License

This project is for educational use only. You are free to fork and study the Cerberus. However, distribution of compiled binaries or use for any non-educational purpose is strictly prohibited.

---

**Cerberus** - Because sometimes you need a three-headed guard dog to protect your payloads. 🐕‍🦺🐕‍🦺🐕‍🦺

*For educational and authorized security testing purposes only.*
