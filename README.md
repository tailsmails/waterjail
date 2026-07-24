# waterjail

A lightweight, surgical Seccomp-BPF dynamic sandboxing and analysis tool written in V.

### ⚠️ Not a Firejail Replacement
`waterjail` is **not** a replacement for full-featured namespace sandboxes like `firejail`. Firejail is a massive, multi-layered sandbox utilizing mount namespaces, user namespaces, cgroups, network isolation, and chroot environments. 

Instead, `waterjail` is a specialized **complementary utility**. It focuses purely on dynamic Seccomp-BPF auditing, parameter-level system call filtering, and deep memory inspection. You can use it as a standalone lightweight wrapper, or to dynamically generate strictly minimal Seccomp filters to supplement other virtualization or containment tools.

---

## Core Capabilities

- **Dynamic Analysis Mode (`-A`)**: Runs your target application under `strace`, monitors its behavior, and automatically generates an executable hardened shell script containing the strict Seccomp allowlist.
- **Dynamic Bitmask Hardener (W^X Safety)**: Automatically analyzes memory allocation systems (`mprotect` and `mmap`) to build a unified safe bitmask. It blocks memory executions outside the application's actual dynamic JIT compiler runtime limits, effectively killing classic shellcode execution.
- **Safe Fallback Engine**: If any complex or unresolved system-level flag constant (like raw `ioctl` commands, `fcntl` flags, or namespace clone flags) is captured but cannot be verified, the parser automatically falls back to an unconditional allow rule for that specific syscall rather than generating a broken rule that crashes the application.

---

## The Hybrid Engine: Seccomp + ptrace

Historically, `seccomp` BPF filters could only inspect numeric syscall arguments. A syscall like `openat` takes a pointer to a string (the file path), which BPF cannot dereference. 

`waterjail` bridges this gap using a hybrid `seccomp` + `ptrace` architecture to provide deep argument inspection and time-aware execution control.

### Dynamic String Argument Filtering
1. **Analysis Mode**: When running with `-A`, `waterjail` detects string arguments in syscalls (e.g., `openat(AT_FDCWD, "/etc/hosts", ...)`). If the application uses a stable set of strings, it generates rules like `-a openat:1=="/etc/hosts"`.
2. **Execution Mode**: Because `seccomp` cannot evaluate string rules, `waterjail` automatically falls back to `ptrace` interception when string rules are present. It intercepts the syscall, reads the process memory at the argument pointer using `PTRACE_PEEKDATA`, extracts the string, and validates it against the allowlist. If it doesn't match, the syscall is blocked and `EPERM` is returned.
3. **TOCTOU Neutralization (Check-and-Undo)**: A known architectural limitation of userspace `ptrace` interception is the TOCTOU (Time-of-Check to Time-of-Use) race condition. `waterjail` mitigates this by re-validating the string at syscall exit. If a race condition is detected (the path was swapped just before the kernel executed it), `waterjail` actively neutralizes the attack: it injects a `close()` syscall to kill the illegally opened File Descriptor, or zeroes out the memory buffer before returning `EPERM` to the process. The attacker wins the race, but the payload is destroyed.

### Time-Aware Sandboxing
Complex apps often need privileged syscalls (`chroot`, `vfork`) only during setup. The analyzer detects these and flags them as `--setup-only`.
- **`--setup-time <s>`**: Used in analysis mode to categorize syscalls only observed in the first `<s>` seconds as setup-only.
- **`--runtime-time <s>`**: Uses `ptrace` to allow setup-only syscalls for `<s>` seconds, then dynamically blocks them by altering process registers.

To prevent a malicious process from keeping the tracer idle to bypass the timer, `waterjail` utilizes kernel-level `SIGALRM` via `alarm()`, ensuring phase transitions occur exactly on time regardless of process activity.

---

## Smart Profiling & Stability

Securing massive, multi-threaded applications (like web browsers) requires an analyzer that understands application behavior, rather than blindly blocking anything it hasn't seen before.

### Intelligent I/O Tracking
Event-driven I/O syscalls (like `accept4`, `bind`, `listen`, or `read` on specific sockets) might not occur during the initial observation phase. Naively categorizing these as "setup-only" causes crashes when the application later needs them to handle new network traffic.

`waterjail` tracks file descriptors returned by syscalls (e.g., sockets, pipes, event files). Any syscall that operates on these tracked FDs is dynamically identified as an I/O operation and excluded from the `--setup-only` list, ensuring event-driven applications can handle future traffic without crashing.

Additionally, syscalls that query core system information using a single pointer argument (like `uname`) are exempted from setup-only blocking, preventing crashes from unpredictable standard library queries (e.g., DNS resolution). The internal kernel mechanism `restart_syscall` is also explicitly exempted.

### Wildcard String Generation
When multiple similar strings are observed for the same argument (e.g., `prctl` setting memory names like `"jemalloc"` and `"jemalloc-decommitted"`), the analyzer finds the common prefix and generates a single wildcard rule (e.g., `-a 'prctl:4=="jemalloc*"'`). The runtime `ptrace` interceptor supports suffix wildcard matching, allowing related dynamic strings to pass the filter without disabling the rule entirely.

### Multi-threaded Architecture Fixes
- **`ptrace` State Desync Fix**: Fixed a critical issue where a `SIGALRM` interrupt during `waitpid` could desynchronize the `ptrace` syscall tracking state. The tracer now correctly preserves the entry/exit state across signal interrupts.
- **Thread Entry/Exit Tracking**: Fixed a race condition where `SIGSTOP` in running threads could cause the entry/exit state map to become corrupted, leading to invalid register reads and immediate process termination.

---

## Getting Started

### Prerequisites

To compile `waterjail` natively, you must first install the required Seccomp wrapper module for V:

```sh
v install --git https://github.com/tailsmails/vcomp
```

### Quick Start (Copy - Paste - Enter)

Install dependencies (including `strace` for analysis), fetch V-compiler, install the Seccomp library, clone `waterjail`, compile natively, and execute:

```sh
sudo apt update -y && sudo apt install -y git clang make strace && if ! command -v v >/dev/null 2>&1; then git clone --depth=1 https://github.com/vlang/v && cd v && make && sudo ./v symlink && cd ..; fi && v install --git https://github.com/tailsmails/vcomp && git clone https://github.com/tailsmails/waterjail.git && cd waterjail && v -prod waterjail.v -o waterjail && ./waterjail --help
```

---

## Usage

### Dynamic Analysis Mode
To secure a massive, multi-threaded application like Tor Browser or any other executable, run `waterjail` in Analysis Mode (`-A`):

```sh
./waterjail -A --setup-time 5 -- tor-browser
```
1. Run the target application, perform your normal operations, and close it.
2. `waterjail` parses the system log, deduplicates overlapping executions, builds safe bitmasks, and tracks I/O FDs.
3. It automatically writes the generated hardened command to an executable shell script named `<target>.sh`.

```bash
# Output: Generated hardened script: start-tor-browser.sh
./start-tor-browser.sh
```

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

## License
![License: GPL v3](https://img.shields.io/badge/License-MIT-blue.svg)
