# waterjail

A Seccomp-BPF and ptrace-based dynamic sandboxing and analysis tool written in V.

### Scope and Limitations
`waterjail` is not a replacement for full-featured namespace sandboxes like `firejail`. Tools like Firejail utilize mount namespaces, user namespaces, cgroups, network isolation, and chroot environments to provide broad system isolation. 

`waterjail` is a specialized utility focused on dynamic Seccomp-BPF auditing, parameter-level system call filtering, and process memory inspection. It can be used as a standalone wrapper or to generate strict Seccomp filters to supplement other virtualization tools.

---

## Core Capabilities

- **Analysis Mode (`-A`)**: Runs the target application under `strace`, logs its behavior, and generates an executable shell script containing a strict Seccomp allowlist based on the observed execution profile.
- **Dynamic Bitmask Generation**: Analyzes memory allocation syscalls (e.g., `mprotect` and `mmap`) during profiling to build a unified bitmask. This restricts memory execution rights to the application's observed requirements, mitigating unauthorized execution in memory.
- **Parser Fallback Handling**: If unresolved system-level flag constants (such as raw `ioctl` commands or namespace clone flags) are captured during profiling, the parser defaults to a broad allow rule for that specific syscall to maintain target application stability.

---

## Architecture: Seccomp + ptrace

Standard `seccomp` BPF filters evaluate numeric syscall arguments but cannot dereference pointers (such as a file path string passed to `openat`). `waterjail` utilizes a hybrid `seccomp` and `ptrace` architecture to inspect pointer arguments and control execution phases.

### String Argument Filtering
1. **Analysis Phase**: When executed with `-A`, `waterjail` logs string arguments in syscalls. If consistent strings are observed, it generates corresponding rules (e.g., `-a openat:1=="/etc/hosts"`).
2. **Execution Phase**: Because `seccomp` cannot evaluate strings, `waterjail` uses `ptrace` when string rules are defined. It intercepts the syscall, reads the process memory at the argument pointer via `PTRACE_PEEKDATA`, and validates the extracted string against the defined regex patterns. Unmatched syscalls return `EPERM`.
3. **TOCTOU Mitigation**: To address the Time-of-Check to Time-of-Use race condition inherent in userspace `ptrace` implementations, `waterjail` re-validates strings at syscall exit. If a memory modification is detected between entry and exit, the operation is neutralized (e.g., by injecting a `close()` syscall for the opened file descriptor or zeroing the memory buffer) before returning an error to the process.

### Time-Aware Sandboxing
Applications often require privileged syscalls during initialization that are unnecessary during their main execution loop.
- **`--setup-time <s>`**: Used during analysis to categorize syscalls observed only in the first `<s>` seconds as setup-specific.
- **`--runtime-time <s>`**: Uses `ptrace` to permit setup-only syscalls for `<s>` seconds. Once the timer expires, these syscalls are blocked. 

Transitions between phases are enforced using the kernel-level `SIGALRM` via `alarm()`, ensuring timers are respected regardless of the tracee's execution state.

---

## Profiling Logic

To maintain stability when profiling complex applications, the analyzer implements specific behavioral exemptions:

### I/O Tracking
Event-driven I/O syscalls (e.g., `accept4`, `bind`, `read` on dynamic sockets) may not trigger during the initial setup observation window. To prevent runtime crashes, `waterjail` tracks file descriptors. Syscalls operating on these descriptors are excluded from the `--setup-only` categorization. 

Additionally, syscalls querying core system information via a single pointer argument (e.g., `uname`) and internal mechanisms like `restart_syscall` are explicitly exempted from setup-only blocking.

### Wildcard Generation
When multiple similar strings are captured for a single argument (e.g., `prctl` thread names), the analyzer identifies the common prefix and generates a unified wildcard rule (e.g., `-a 'prctl:4=="jemalloc*"'`). The `ptrace` interceptor processes these using regex.

---

## Getting Started

### Prerequisites

To compile `waterjail` natively, the required Seccomp and memory handling modules must be installed:

```sh
v install --git https://github.com/tailsmails/vcomp
v install --git https://github.com/tailsmails/vanadium
```

---

## Usage

### Basic Syntax

The tool requires specifying a filter type, the associated rules, and the target application:

```bash
waterjail [OPTIONS] -- <target_command> [args...]
```

By default, `waterjail` uses a `blocklist` mode. For strict sandboxing, use the `allowlist` mode (`-t allowlist`), which drops all syscalls by default unless explicitly permitted by a rule.

### Syscall Rule Definition

Rules are passed using `-a` (allow), `-b` (block), or `-e` (block-errno). 
Format: `<syscall_name>[:<arg_index><operator><value>]`

#### 1. Numeric and Bitwise Arguments (u64)
Arguments are evaluated as 64-bit integers. Supported operators: `==`, `!=`, `>=`, `>`, and `&` (bitwise AND). Values are accepted in decimal or hexadecimal (`0x`).

*   **Block a specific value:**
    Block `write` if the first argument (index 0) is 1.
    ```bash
    waterjail -b "write:0==1" -- my_app
    ```
*   **Evaluate bitwise flags:**
    Allow `mprotect` only if the `PROT_EXEC` flag (value `4`) is not set.
    ```bash
    waterjail -t allowlist -a "mprotect:2&0x4" -- my_app
    ```

#### 2. String Arguments (Regex)
If the value is enclosed in double quotes with the `==` operator, the engine inspects the memory via `ptrace` and evaluates the string using standard regular expressions.

*   **Restrict access by regex:**
    Block `openat` if the path (index 1) matches the exact string `/etc/shadow`.
    ```bash
    waterjail -b "openat:1==\"^/etc/shadow$\"" -- my_app
    ```

### Global Filtering

Global flags apply rules universally across specific categories of syscalls.

#### Path Filtering (`-P` and `-W`)
Applies to all path-taking syscalls (e.g., `openat`, `unlinkat`, `mkdirat`). These flags use shell globbing syntax (`*`, `?`), which is internally converted to regex.

*   **Allow specific paths (blocks all others):**
    ```bash
    waterjail -W "/var/log/*.log" -W "/tmp/app_*" -- my_app
    ```

#### String Filtering (`-B` and `-S`)
Applies to any syscall accepting a string pointer (e.g., `execve`, `mount`, `chdir`). These flags expect standard regular expressions.

*   **Block string input matching a pattern:**
    ```bash
    waterjail -B "^/bin/(sh|bash)$" -- my_app
    ```

### Execution Phases and Timers

*   `--setup-time <seconds>`: Sets the duration of the initialization phase.
*   `--setup-only <syscall>`: Permits the specified syscall exclusively during the setup time window.
*   `--runtime-time <seconds>`: Sets an execution timeout for the sandboxed process.

**Example:** Allow `mmap` and `mprotect` for the first 3 seconds only.
```bash
waterjail -t allowlist -a "read,write,mmap,mprotect" --setup-only "mmap" --setup-only "mprotect" --setup-time 3 -- my_app
```

### Automated Analysis Mode

Passing the `-A` (or `--analyze`) flag runs the application under `strace` to monitor its behavior. `waterjail` then generates a `.sh` wrapper script containing the computed allowlist (including file paths, memory addresses, and numeric ranges).

```bash
# Profile the application with a 2-second setup phase
waterjail -A --setup-time 2 -- node server.js

# Generates 'node.sh' in the current directory.
```

---

## Command-Line Options Reference

| Flag | Long Flag | Description |
| :--- | :--- | :--- |
| `-b` | `--block` | Block a specific syscall. Format: `name` or `name:index<op>value`. |
| `-e` | `--block-errno` | Block a syscall and return a specific errno instead of terminating the process. |
| `-a` | `--allow` | Allow a specific syscall. |
| `-t` | `--type` | Base filter type: `allowlist` or `blocklist` (default: `blocklist`). |
| | `--errno-code` | The integer error code returned when a syscall is blocked (default: 1). |
| `-A` | `--analyze` | Run in profiling mode to generate a strict allowlist shell script. |
| `-P` | `--block-path` | Globally block paths matching a glob pattern (applies to path-taking syscalls). |
| `-W` | `--allow-path` | Globally allow paths matching a glob pattern, blocking all others. |
| `-B` | `--block-string`| Globally block strings matching a regex pattern (applies to all string args). |
| `-S` | `--allow-string`| Globally allow strings matching a regex pattern, blocking all others. |
| | `--setup-time` | Timer (in seconds) for the initialization phase. |
| `-s` | `--setup-only` | Specifies a syscall allowed only during the setup timer period. |
| | `--runtime-time` | Execution timeout (in seconds) for the sandboxed process. |

---

## License
![License](https://img.shields.io/badge/License-EUPL1.2-blue.svg)
