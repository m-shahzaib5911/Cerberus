# Project Cerberus: Advanced Windows Payload Generator


**Cerberus** is a sophisticated C-based framework for generating highly evasive Windows reverse shell payloads. This project is designed as an educational tool for cybersecurity researchers, red teamers, and students to study and understand advanced offensive security techniques and modern evasion tactics used to bypass endpoint security solutions.

---

### ⚠️ Disclaimer

This tool is intended for **educational and research purposes only**. The techniques and code are meant to be studied in controlled lab environments to better understand how malware operates and how to build better defenses. **Do not** use this tool for any illegal or malicious activities. The author is not responsible for any misuse or damage caused by this program.

---

## 🚀 Core Features

This framework layers multiple state-of-the-art evasion techniques to create a payload that is resilient to both static and dynamic analysis.

#### 🛡️ Anti-Sandbox & Anti-Analysis
- **Hardware Checks**: Detects low CPU cores, small RAM/disk sizes common in sandboxes.
- **VM Artifacts**: Scans for VM-specific MAC addresses, processes, and CPU vendor strings (VMware, KVM, VirtualBox).
- **Timing Attacks**: Detects `Sleep()` acceleration and suspiciously fast API calls.
- **Human Interaction Simulation**: Employs advanced mouse movement analysis to distinguish between a real user and an automated sandbox by checking for:
  - Natural speed and acceleration variance.
  - Micro-movements and "jitter".
  - Non-linear movement patterns.
- **Debugger Detection**: Uses `IsDebuggerPresent()` to identify attached debuggers.

#### 👻 AV / EDR Evasion
- **Payload Encryption**: The core shellcode is encrypted with a unique, randomly generated **ChaCha20** key for each build, preventing static signature detection.
- **Runtime API Resolution (API Hashing)**: Avoids suspicious entries in the Import Address Table (IAT) by dynamically finding the memory addresses of sensitive Windows API functions at runtime using pre-computed name hashes.
- **Direct System Calls**: Bypasses user-land EDR hooks by invoking critical functions like `NtAllocateVirtualMemory` directly from `ntdll.dll`.
- **In-Memory Patching**:
  - **ETW Bypass**: Patches `EtwEventWrite` to disable Event Tracing for Windows, blinding security products that rely on it for telemetry.
  - **AMSI Bypass**: Patches `AmsiScanBuffer` to prevent the Antimalware Scan Interface from scanning the decrypted payload in memory.
- **SmartScreen Bypass**: Implements a multi-faceted strategy to circumvent Windows SmartScreen reputation checks by manipulating process policies and file zone identifiers.

#### 🎲 Obfuscation & Randomization
- **Dynamic Code Generation**: The builder creates a completely new C source file for every payload.
- **Polymorphic Naming**: All key functions and variables in the generated payload are given randomized names for each build, making signature-based detection significantly harder.

---

## 🛠️ How It Works

The project consists of a single C program (`test_filegen.c`) that acts as a builder.

1.  **Run the Builder**: Compile and execute the builder application.
2.  **Provide Input**: Enter the attacker's IP address and port for the reverse shell.
3.  **Generate Source**: The builder dynamically constructs a new C source file (`final_stager.c`), embedding the evasion logic and the encrypted, user-configured shellcode.
4.  **Compile Payload**: The builder invokes the GCC compiler to compile `final_stager.c` into a standalone executable (`final_file.exe`).
5.  **Deploy**: The resulting `final_file.exe` is the payload to be used. When executed, it will perform all evasion checks before decrypting and running the shellcode in memory.

---

## ⚙️ Getting Started

### Prerequisites
- A Windows machine.
- **MinGW-w64** installed and configured in your system's PATH. This is required for the `gcc` compiler.

### Compilation & Usage

1.  **Compile the Builder:**
    ```bash
    gcc -o builder.exe "test_filegen.c" -lws2_32 -liphlpapi -lole32 -loleaut32 -lshlwapi -lpsapi -ldbghelp -lntdll
    ```

2.  **Run the Builder:**
    ```bash
    ./builder.exe
    ```

3.  **Login:**
    The builder is password-protected.
    - Default Username: `admin`
    - Default Password: `admin`
    You will be prompted to change the password after your first successful login.

4.  **Generate the Payload:**
    - Select option `1` from the menu.
    - Enter the listener's IP address and port when prompted.
    - The builder will generate `final_stager.c` and compile it into `final_file.exe`.

5.  **Set up Listener:**
    On your attacker machine, start a Netcat listener to catch the connection.
    ```bash
    nc -lvnp <YOUR_PORT>
    ```

6.  **Execute the Payload:**
    Run `final_file.exe` on the target Windows machine.

---

## License

This project is for educational use only. You are free to fork, modify, and study the code. However, distribution of compiled binaries or use for any non-educational purpose is strictly prohibited.
