# waterjail

`waterjail` is a lightweight, surgical Seccomp-BPF dynamic sandboxing and analysis tool written in V. 

### ⚠️ Not a Firejail Replacement
`waterjail` is **not** a replacement for full-featured namespace sandboxes like `firejail`. Firejail is a massive, multi-layered sandbox utilizing mount namespaces, user namespaces, cgroups, network isolation, and chroot environments. 

Instead, `waterjail` is a specialized **complementary utility**. It focuses purely on dynamic Seccomp-BPF auditing, parameter-level system call filtering, and security hardening. You can use it as a standalone lightweight wrapper, or to dynamically generate strictly minimal Seccomp filters to supplement other virtualization or containment tools.

---

## Key Features

- **Dynamic Analysis Mode (`-A`)**: Runs your target application under `strace`, monitors its behavior, and automatically generates a copy-pasteable hardened Seccomp allowlist command.
- **Dynamic Bitmask Hardener (W^X Safety)**: Automatically analyzes memory allocation systems (`mprotect` and `mmap`) to build a unified safe bitmask. It blocks memory executions outside the application's actual dynamic JIT compiler runtime limits.
- **Safe Fallback Engine**: If any complex or unresolved system-level flag constant (like raw ioctl commands, fcntl flags, or namespace clone flags) is captured but cannot be verified, the parser automatically falls back to an unconditional allow rule for that specific system call rather than generating a broken rule that crashes the application.

---

## Prerequisites

To compile `waterjail` natively, you must first install the required Seccomp wrapper module for V:

```sh
v install --git https://github.com/tailsmails/vcomp
```

---

## Quick Start (Copy - Paste - Enter)

Install dependencies (including `strace` for analysis), fetch V-compiler, install the Seccomp library, clone `waterjail`, compile natively, and execute:

```sh
sudo apt update -y && sudo apt install -y git clang make strace && if ! command -v v >/dev/null 2>&1; then git clone --depth=1 https://github.com/vlang/v && cd v && make && sudo ./v symlink && cd ..; fi && v install --git https://github.com/tailsmails/vcomp && git clone https://github.com/tailsmails/waterjail.git && cd waterjail && v -prod example.v -o waterjail && ./waterjail --help
```

---

## How It Works (Analysis Mode)

To secure a massive, multi-threaded application like Tor Browser or any other executable, run `waterjail` in Analysis Mode (`-A`):

```sh
./waterjail -A -- /path/to/your/application [args...]
```

1. Run the target application, perform your normal operations, and close it.
2. `waterjail` parses the system log, deduplicates overlapping executions, and builds safe bitmasks.
3. It prints a clean, colorized terminal report containing the **final copy-pasteable command**.

---

## Command Syntax

### Allowlist Mode (Default)
In allowlist mode (`-t allowlist`), only specified system calls are allowed; all other system calls are immediately blocked (`SIGSYS`).

```sh
# Allow only safe execution of mkdir
./waterjail -t allowlist -a execve -a openat -a write -a mkdir -a exit_group -- mkdir test_dir
```

### Parameter Hardening Syntax
`waterjail` supports precise argument filtering:
```sh
# Format: <syscall_name>:<arg_index><op><value>
# Supported operators: ==, !=, >=, >, & (bitwise AND)

# Allow socket creation only if the domain (arg 0) is local Unix or IPv4
./waterjail -t allowlist -a socket:0==1 -a socket:0==2 ... -- target_program
```

### Advanced Bitwise Masking
To block dangerous memory protections (like `PROT_EXEC` (4)) while allowing standard ones:
```sh
./waterjail -t allowlist -e "mprotect:2&18446744073709551608" -a mprotect -- target_program
```
*(Note: Always wrap bitwise filters containing `&` in double quotes to prevent bash from backgrounding the process).*

---

## License
![License: GPL v3](https://img.shields.io/badge/License-MIT-blue.svg)
