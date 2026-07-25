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

# Usage
Here is a professional, technically accurate, and native-English README block tailored for standard GitHub documentation or a man page. It contains no emojis, promotional language, or subjective claims, focusing purely on usage and architecture.

## Table of Contents
1. [Basic Syntax](#basic-syntax)
2. [Syscall Rule Definition](#syscall-rule-definition)
3. [Global Filtering (Paths and Strings)](#global-filtering-paths-and-strings)
4. [Execution Phases and Timers](#execution-phases-and-timers)
5. [Automated Analysis Mode](#automated-analysis-mode)
6. [Command-Line Options Reference](#command-line-options-reference)

---

## Basic Syntax

The standard invocation requires specifying the filter type, the associated rules, and the target application:

```bash
waterjail [OPTIONS] -- <target_command> [args...]
```

By default, Waterjail operates in a `blocklist` mode (allowing all syscalls except those explicitly blocked). For strict sandboxing, use the `allowlist` mode (`-t allowlist`), which drops all syscalls by default unless explicitly permitted.

---

## Syscall Rule Definition

Syscall rules are passed using the `-a` (allow), `-b` (block), or `-e` (block-errno) flags. 
The format is: `<syscall_name>[:<arg_index><operator><value>]`

### 1. Numeric and Bitwise Arguments (u64)
System call arguments are evaluated as 64-bit integers. Supported operators are `==`, `!=`, `>=`, `>`, and `&` (bitwise AND). Values can be passed as decimal or hexadecimal (`0x`).

*   **Block a specific file descriptor:**
    Block the `write` syscall if the first argument (index 0) is exactly 1 (stdout).
    ```bash
    waterjail -b "write:0==1" -- my_app
    ```
*   **Evaluate bitwise flags:**
    Allow `mprotect` only if the `PROT_EXEC` flag (value `4` or `0x4`) is not set.
    ```bash
    waterjail -t allowlist -a "mprotect:2&0x4" -- my_app
    ```

### 2. String Arguments (Regex)
If the value is enclosed in double quotes and the `==` operator is used, Waterjail inspects the tracee's memory via `ptrace` and applies standard regular expressions.

*   **Restrict file access by regex:**
    Block `openat` if the path (index 1) matches a specific pattern.
    ```bash
    waterjail -b "openat:1==\"^/etc/shadow$\"" -- my_app
    ```

*Note: Waterjail implements TOCTOU (Time-Of-Check to Time-Of-Use) mitigation. If a blocked string argument is modified in memory between the syscall entry and exit, Waterjail neutralizes the operation (e.g., by injecting a `close()` or zeroing out the buffer).*

---

## Global Filtering (Paths and Strings)

Writing per-syscall rules can be verbose. Waterjail provides global flags to apply filtering rules universally across relevant syscalls.

### Path Filtering (`-P` and `-W`)
These flags apply automatically to all known path-taking syscalls (e.g., `openat`, `unlinkat`, `mkdirat`, `statx`). They use **shell globbing** syntax (e.g., `*`, `?`), which the engine translates into regex internally.

*   **Allow specific paths globally (blocks all other paths):**
    ```bash
    waterjail -W "/var/log/*.log" -W "/tmp/app_*" -- my_app
    ```

### String Filtering (`-B` and `-S`)
These flags apply to *any* syscall that accepts a string pointer (e.g., `execve`, `mount`, `chdir`, `setxattr`). They expect **raw regular expressions** rather than globs.

*   **Block any string input matching a regex pattern:**
    ```bash
    waterjail -B "^/bin/(sh|bash)$" -- my_app
    ```

---

## Execution Phases and Timers

Complex applications often require extensive system privileges during initialization (loading shared libraries, binding ports) but require minimal privileges during their main execution loop.

*   `--setup-time <seconds>`: Defines the duration of the initialization phase.
*   `--setup-only <syscall>`: Permits the specified syscall *only* during the setup time window. Once the timer expires, the syscall is blocked.
*   `--runtime-time <seconds>`: Defines an overall timeout for the sandbox execution.

**Example:**
Allow `mmap` and `mprotect` for the first 3 seconds, but block them thereafter.
```bash
waterjail -t allowlist -a "read,write,mmap,mprotect" --setup-only "mmap" --setup-only "mprotect" --setup-time 3 -- my_app
```

---

## Automated Analysis Mode

Waterjail can autonomously profile an application and generate a strict execution policy. By passing the `-A` (or `--analyze`) flag, the tool utilizes `strace` to monitor the target. 

Upon completion, Waterjail outputs a `.sh` wrapper script containing a minimal, highly specific allowlist (including exact file paths, fixed memory addresses, and numeric ranges observed during the run).

```bash
# Profile the application with a 2-second setup phase assumption
waterjail -A --setup-time 2 -- node server.js

# Output will be generated as 'node.sh' in the current directory.
```

---

## Command-Line Options Reference

| Flag | Long Flag | Description |
| :--- | :--- | :--- |
| `-b` | `--block` | Block a specific syscall. Format: `name` or `name:index<op>value`. |
| `-e` | `--block-errno` | Block a syscall and return a specific errno instead of killing the process. |
| `-a` | `--allow` | Allow a specific syscall. |
| `-t` | `--type` | Base filter type: `allowlist` or `blocklist` (default: `blocklist`). |
| | `--errno-code` | The integer error code returned when a syscall is blocked (default: 1). |
| `-A` | `--analyze` | Run in profiling mode to generate a strict allowlist script. |
| `-P` | `--block-path` | Globally block paths matching a glob pattern (applies to path syscalls). |
| `-W` | `--allow-path` | Globally allow paths matching a glob pattern, blocking all others. |
| `-B` | `--block-string`| Globally block strings matching a regex pattern (applies to all string args). |
| `-S` | `--allow-string`| Globally allow strings matching a regex pattern, blocking all others. |
| | `--setup-time` | Timer (in seconds) for the initialization phase. |
| `-s` | `--setup-only` | A syscall allowed only during the setup timer period. |
| | `--runtime-time` | Execution timeout (in seconds) for the sandboxed process. |

---

## License
![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
