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

## What's New in v0.0.4: Dynamic Analysis & Time-Based Sandboxing

Version 0.0.4 introduces a major shift from static rule definitions to dynamic, behavior-based syscall analysis. Instead of manually guessing which syscalls and arguments your application needs, `waterjail` can now observe the application and generate a hardened, time-aware sandbox automatically.

### How It Works

The new analyze mode (`-A`) operates in three distinct phases:

1. **Observation (strace)**: `waterjail` runs the target application under `strace` to log every syscall, its arguments, and high-precision timestamps.
2. **Dynamic Profiling**: It intelligently parses the logs to distinguish between stable arguments (e.g., `AF_INET`, flags) and dynamic ones (e.g., memory pointers, File Descriptors, PIDs). 
   - **Bitmask Unification**: For memory management syscalls (`mmap`, `mprotect`), it unifies all observed protection bitmasks into a single allowed mask and generates a block rule for the inverse mask, strictly preventing unauthorized memory permissions (like simultaneous Write+Execute).
   - **BPF Safety**: To prevent BPF compilation errors in the kernel, it automatically filters out large 64-bit negative values (such as `AT_FDCWD` converted to `u64`) and pointers, and merges multi-argument rules into single comma-separated conditions to avoid BPF filter conflicts.
3. **Time-Aware Execution**: For complex applications (like web browsers or daemons), certain syscalls are only required during the initialization phase. The analyzer detects these and flags them as `--setup-only`.

### Startup-Time vs. Runtime-Time

Complex applications often need highly privileged syscalls (like `chroot`, `vfork`, or `fchown`) to set up their environment, but should never need them again once they are running. 

- **`--setup-time <s>`**: Used during analysis mode (`-A`). It defines a threshold. Syscalls only observed within the first `<s>` seconds are categorized as setup-only.
- **`--runtime-time <s>`**: Applied during actual execution. `waterjail` uses `ptrace` to monitor the process. For the first `<s>` seconds, `setup-only` syscalls are allowed. Once the timer expires, `waterjail` dynamically intercepts and blocks them at the kernel level by altering the process registers, returning `EPERM`.

This hybrid approach (`seccomp` for static baseline + `ptrace` for time-based expiration) ensures that even if an attacker achieves Remote Code Execution (RCE) in your application after it has started, they cannot use critical syscalls to escalate privileges or spawn shellcodes.

### Race Condition Mitigation

`seccomp` operates entirely in kernel space and is immune to race conditions. However, `ptrace` operates in userspace, which introduces synchronization challenges.

To prevent a malicious process from keeping the tracer idle (e.g., waiting on network I/O) indefinitely to bypass the timer, `waterjail` v0.0.4 utilizes kernel-level `SIGALRM` via the `alarm()` syscall. This ensures that the phase transition from "allowed" to "blocked" occurs exactly on time, regardless of the target process's activity. 

*Note on TOCTOU*: While `SIGALRM` fixes the idle-bypass vulnerability, a microscopic Time-of-Check to Time-of-Use (TOCTOU) race condition inherently exists in userspace `ptrace` interception when a syscall is executed exactly as the timer expires. For 99% of use cases (preventing accidental post-startup privilege escalations), this is highly effective. If dealing with actively hostile, timing-exploit-aware targets, consider this a known architectural limitation of `ptrace`.

### Example Usage

To analyze and generate a hardened command for a complex application like the Tor Browser:

```bash
./waterjail -A --setup-time 5 -- tor-browser
```

`waterjail` will output a ready-to-use, highly restrictive command featuring dynamic argument filtering, memory bitmasking, and time-based setup-only restrictions. You can then run the generated command to launch your application in a secure, hardened sandbox.

---

## License
![License: GPL v3](https://img.shields.io/badge/License-MIT-blue.svg)
