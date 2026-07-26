module main

import os
import flag
import strconv
import term
import vcomp
import regex
import vanadium

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/prctl.h>
#include <signal.h>
#include <errno.h>

struct C.timeval {
	tv_sec  i64
	tv_usec i64
}

fn C.fork() int
fn C.ptrace(request int, pid int, addr i64, data i64) i64
fn C.waitpid(pid int, status &int, options int) int
fn C.gettimeofday(tv &C.timeval, tz voidptr) int
fn C._exit(status int)
fn C.alarm(seconds u32) u32
fn C.signal(signum int, handler voidptr) voidptr
fn C.memcpy(dest voidptr, src voidptr, n usize) voidptr
fn C.__errno_location() &int
fn C.prctl(option int, arg2 int, arg3 int, arg4 int, arg5 int) int

fn get_errno() int {
	return unsafe { *C.__errno_location() }
}

const ptrace_traceme = 0
const ptrace_peekdata = 2
const ptrace_pokedata = 5
const ptrace_peekuser = 3
const ptrace_pokeuser = 6
const ptrace_cont = 7
const ptrace_syscall_op = 24
const ptrace_setoptions_op = 0x4200
const ptrace_o_tracesysgood = 0x01
const ptrace_o_tracefork = 0x02
const ptrace_o_tracevfork = 0x04
const ptrace_o_traceclone = 0x08
const ptrace_o_traceexec = 0x10
const ptrace_wall = 0x40000000
const ptrace_o_exitkill = 0x00100000
const sigalrm_const = 14
const eintr_const = 4
const pr_set_pdeathsig = 1
const sigkill_const = 9

$if x64 {
	const orig_rax_offset = 120
	const rax_offset = 80
	const rip_offset = 128
	const rsp_offset = 152
	const reg_offsets = [112, 104, 96, 56, 72, 64]
	const syscall_size = 2
} $else $if x32 {
	const orig_rax_offset = 36
	const rax_offset = 24
	const rip_offset = 40
	const rsp_offset = 48
	const reg_offsets = [0, 4, 8, 12, 16, 20]
	const syscall_size = 2
} $else $if arm64 {
	const orig_rax_offset = 64
	const rax_offset = 0
	const rip_offset = 256
	const rsp_offset = 264
	const reg_offsets = [0, 8, 16, 24, 32, 40]
	const syscall_size = 4
} $else $if arm32 {
	const orig_rax_offset = 68
	const rax_offset = 0
	const rip_offset = 60
	const rsp_offset = 56
	const reg_offsets = [0, 4, 8, 12, 16, 20]
	const syscall_size = 4
} $else {
	const orig_rax_offset = 120
	const rax_offset = 80
	const rip_offset = 128
	const rsp_offset = 152
	const reg_offsets = [112, 104, 96, 56, 72, 64]
	const syscall_size = 2
}

const output_buffer_args = {
	'read': [1],
	'pread64': [1],
	'recvfrom': [1],
	'getcwd': [0],
	'readlink': [1],
	'readlinkat': [2],
	'fgetxattr': [2],
	'lgetxattr': [2],
	'getxattr': [2],
	'listxattr': [1],
	'llistxattr': [1],
	'flistxattr': [1]
}

const path_taking_syscalls = ['open', 'openat', 'stat', 'lstat', 'newfstatat', 'statx', 'chmod', 'fchmodat', 'chown', 'fchownat', 'lchown', 'unlink', 'unlinkat', 'rmdir', 'mkdir', 'mkdirat', 'rename', 'renameat', 'renameat2', 'link', 'linkat', 'readlink', 'readlinkat', 'chdir', 'chroot', 'truncate']

fn sigalrm_handler(s os.Signal) {
}

struct ParsedSyscall {
	sys_name string
	args     []vcomp.ArgRule
	str_args []string
}

struct StrCheckData {
	ptr      u64
	orig     string
	sys_nr   int
	buf_ptr  u64
	buf_len  int
}

struct DynamicRule {
	str_args map[int][]regex.RE
	u64_args []vcomp.ArgRule
}

fn resolve_syscall_num(sys_name string) !int {
	nr := vcomp.get_syscall_number(sys_name) or {
		return error('unknown syscall name: ${sys_name}')
	}
	return int(nr)
}

fn glob_to_regex(glob string) string {
	mut s := []u8{}
	s << `^`
	for i := 0; i < glob.len; i++ {
		c := glob[i]
		match c {
			`*` { s << `.`; s << `*` }
			`?` { s << `.` }
			`.`, `+`, `(`, `)`, `{`, `}`, `[`, `]`, `^`, `$`, `|`, `\\` {
				s << `\\`; s << c
			}
			else { s << c }
		}
	}
	s << `$`.bytes()
	return s.bytestr()
}

fn op_to_str(op vcomp.Op) string {
	return match op {
		.eq { '==' }
		.neq { '!=' }
		.ge { '>=' }
		.gt { '>' }
		.bits_set { '&' }
	}
}

fn find_common_prefix(strings []string) string {
	if strings.len == 0 {
		return ''
	}
	if strings.len == 1 {
		return strings[0]
	}
	mut prefix := strings[0]
	for i in 1 .. strings.len {
		mut j := 0
		for j < prefix.len && j < strings[i].len && prefix[j] == strings[i][j] {
			j++
		}
		prefix = prefix[0..j]
		if prefix.len == 0 {
			break
		}
	}
	if prefix.len > 0 {
		mut last_delim := -1
		for i := 0; i < prefix.len; i++ {
			c := prefix[i]
			if c == `/` || c == `.` || c == `_` || c == `-` || c == ` ` {
				last_delim = i
			}
		}
		if last_delim >= 1 {
			prefix = prefix[0..last_delim + 1]
		} else {
			return ''
		}
	}
	return prefix
}

fn read_string_from_ptrace(pid int, addr u64) string {
	mut sb := vanadium.sec_buf(4096) or { return '' }
	mut current_addr := addr
	for {
		word := u64(C.ptrace(ptrace_peekdata, pid, i64(current_addr), 0))
		mut b := [8]u8{}
		unsafe { C.memcpy(&b[0], &word, 8) }
		mut found_null := false
		for i in 0 .. 8 {
			if b[i] == 0 {
				found_null = true
				break
			}
			sb.write_byte(b[i]) or { break }
		}
		if found_null {
			break
		}
		current_addr = vanadium.c_add(current_addr, u64(8)) or { break }
		if sb.data.len > 4096 {
			break
		}
	}
	res_str := (sb.read() or { []u8{} }).bytestr()
	sb.clear()
	return res_str
}

fn read_string_to_ijail(pid int, addr u64) !vanadium.IJail {
	mut sb := vanadium.sec_buf(4096) or { return error('failed to create sec_buf') }
	mut current_addr := addr
	for {
		word := u64(C.ptrace(ptrace_peekdata, pid, i64(current_addr), 0))
		mut b := [8]u8{}
		unsafe { C.memcpy(&b[0], &word, 8) }
		mut found_null := false
		for i in 0 .. 8 {
			if b[i] == 0 {
				found_null = true
				break
			}
			sb.write_byte(b[i]) or { break }
		}
		if found_null {
			break
		}
		current_addr = vanadium.c_add(current_addr, u64(8)) or { break }
		if sb.data.len > 4096 {
			break
		}
	}
	res_str := (sb.read() or { []u8{} }).bytestr()
	sb.clear()
	return vanadium.ijail(res_str)
}

fn inject_close(pid int, fd int) {
	close_sys_nr := resolve_syscall_num('close') or { 3 }
	saved_orig_rax := C.ptrace(ptrace_peekuser, pid, orig_rax_offset, 0)
	saved_arg0 := C.ptrace(ptrace_peekuser, pid, reg_offsets[0], 0)
	saved_rip := C.ptrace(ptrace_peekuser, pid, rip_offset, 0)
	C.ptrace(ptrace_pokeuser, pid, orig_rax_offset, i64(close_sys_nr))
	C.ptrace(ptrace_pokeuser, pid, reg_offsets[0], i64(fd))
	poke_rip := vanadium.c_sub[i64](saved_rip, i64(syscall_size)) or { saved_rip }
	C.ptrace(ptrace_pokeuser, pid, rip_offset, poke_rip)
	mut status := 0
	C.ptrace(ptrace_syscall_op, pid, 0, 0)
	C.waitpid(pid, &status, 0)
	C.ptrace(ptrace_syscall_op, pid, 0, 0)
	C.waitpid(pid, &status, 0)
	C.ptrace(ptrace_pokeuser, pid, orig_rax_offset, saved_orig_rax)
	C.ptrace(ptrace_pokeuser, pid, reg_offsets[0], saved_arg0)
	C.ptrace(ptrace_pokeuser, pid, rip_offset, saved_rip)
}

fn zero_tracee_memory(pid int, addr u64, len int) {
	if addr == 0 || len == 0 {
		return
	}
	mut i := 0
	limit := vanadium.c_sub(len, 8) or { return }
	for i <= limit {
		target_addr := vanadium.c_add(addr, u64(i)) or { break }
		C.ptrace(ptrace_pokedata, pid, i64(target_addr), 0)
		i = vanadium.c_add(i, 8) or { break }
	}
	if i < len {
		remaining := vanadium.c_sub(len, i) or { return }
		target_addr := vanadium.c_add(addr, u64(i)) or { return }
		mut word := u64(C.ptrace(ptrace_peekdata, pid, i64(target_addr), 0))
		shift_val := vanadium.c_mul(remaining, 8) or { return }
		mask := ~((u64(1) << shift_val) - 1)
		word &= mask
		C.ptrace(ptrace_pokedata, pid, i64(target_addr), i64(word))
	}
}

fn build_dynamic_rules_map(rules []string) map[int][]DynamicRule {
	mut m := map[int][]DynamicRule{}
	for sys_str in rules {
		parsed := parse_syscall_rule(sys_str) or { continue }
		sys_name := parsed.sys_name
		nr := resolve_syscall_num(sys_name) or { continue }
		nr_i := int(nr)
		if parsed.str_args.len == 0 && parsed.args.len == 0 {
			continue
		}
		mut str_args_map := map[int][]regex.RE{}
		for s_rule in parsed.str_args {
			parts := s_rule.split('==')
			if parts.len != 2 {
				continue
			}
			idx := parts[0].trim_space().int()
			if sys_name in output_buffer_args && idx in output_buffer_args[sys_name] {
				continue
			}
			pattern := parts[1].trim_space().trim_left('"').trim_right('"')
			re := regex.regex_opt(pattern) or {
				eprintln('Invalid regex "${pattern}": ${err}')
				continue
			}
			if idx !in str_args_map {
				str_args_map[idx] = []regex.RE{}
			}
			str_args_map[idx] << re
		}
		entry := DynamicRule{
			str_args: str_args_map
			u64_args: parsed.args
		}
		m[nr_i] << entry
	}
	return m
}

fn match_dynamic_rule(rule DynamicRule, pid int, sys_nr int, mut checks []StrCheckData, mut read_cache map[int]string) (bool, string) {
	for u64_arg in rule.u64_args {
		if u64_arg.index >= reg_offsets.len { return false, 'u64 arg index out of bounds' }
		reg_offset := reg_offsets[u64_arg.index]
		reg_val := u64(C.ptrace(ptrace_peekuser, pid, reg_offset, 0))
		mut matched := false
		match u64_arg.op {
			.eq { if reg_val == u64_arg.value { matched = true } }
			.neq { if reg_val != u64_arg.value { matched = true } }
			.ge { if reg_val >= u64_arg.value { matched = true } }
			.gt { if reg_val > u64_arg.value { matched = true } }
			.bits_set { if (reg_val & u64_arg.value) == u64_arg.value { matched = true } }
		}
		if !matched {
			return false, 'u64 arg[${u64_arg.index}]=0x${reg_val.hex()} did not match ${op_to_str(u64_arg.op)} 0x${u64_arg.value.hex()}'
		}
	}
	for idx, allowed_res in rule.str_args {
		if idx >= reg_offsets.len { return false, 'str arg index out of bounds' }
		mut actual_str := ''
		if idx in read_cache {
			actual_str = read_cache[idx]
		} else {
			reg_offset := reg_offsets[idx]
			arg_ptr := u64(C.ptrace(ptrace_peekuser, pid, reg_offset, 0))
			if arg_ptr < 0x10000 { return false, 'str arg[${idx}] has invalid pointer 0x${arg_ptr.hex()}' }
			
			mut actual_str_val := ''
			p_actual_str_val := &actual_str_val
			mut matched_any := false
			p_matched_any := &matched_any
			mut allowed_res_mut := allowed_res.clone()
			mut ij_str := read_string_to_ijail(pid, arg_ptr) or { return false, 'failed to secure string' }
			defer { ij_str.free() }
			ij_str.use(fn [p_actual_str_val, p_matched_any, mut allowed_res_mut] (s string) ! {
				unsafe {
					*p_actual_str_val = s.clone()
				}
				for mut re in allowed_res_mut {
					start, end := re.match_string(s)
					if start >= 0 && end >= start {
						unsafe {
							*p_matched_any = true
						}
						break
					}
				}
			}) or { return false, 'secured execution failed' }
			
			if !matched_any {
				return false, 'str arg[${idx}]="${actual_str}" did not match any pattern'
			}
			actual_str = actual_str_val
			read_cache[idx] = actual_str
			mut buf_ptr := u64(0)
			mut buf_len := 0
			sys_getcwd := resolve_syscall_num('getcwd') or { 89 }
			sys_readlink := resolve_syscall_num('readlink') or { 106 }
			sys_readlinkat := resolve_syscall_num('readlinkat') or { 262 }
			
			if sys_nr == sys_getcwd {
				buf_ptr = u64(C.ptrace(ptrace_peekuser, pid, reg_offsets[1], 0))
				buf_len = int(C.ptrace(ptrace_peekuser, pid, reg_offsets[2], 0))
			} else if sys_nr == sys_readlink {
				buf_ptr = u64(C.ptrace(ptrace_peekuser, pid, reg_offsets[1], 0))
				buf_len = 256
			} else if sys_nr == sys_readlinkat {
				buf_ptr = u64(C.ptrace(ptrace_peekuser, pid, reg_offsets[2], 0))
				buf_len = 256
			}
			checks << StrCheckData{arg_ptr, actual_str, sys_nr, buf_ptr, buf_len}
		}
	}
	return true, 'matched all conditions'
}

fn is_all_digits(s string) bool {
	if s == '' {
		return false
	}
	for c in s {
		if c < `0` || c > `9` {
			return false
		}
	}
	return true
}

fn clean_strace_args(args string) string {
	mut s := args
	if s.contains(' <unfinished') {
		s = s.split(' <unfinished')[0]
	}
	if s.contains('<unfinished') {
		s = s.split('<unfinished')[0]
	}
	return s.trim_space()
}

fn smart_split_args(args string) []string {
	mut parts := []string{}
	mut current := ''
	mut in_quote := false
	mut brace_depth := 0
	mut bracket_depth := 0
	for i := 0; i < args.len; i++ {
		c := args[i]
		if c == `"` {
			in_quote = !in_quote
		}
		if !in_quote {
			if c == `{` {
				brace_depth++
			} else if c == `}` {
				brace_depth--
			} else if c == `[` {
				bracket_depth++
			} else if c == `]` {
				bracket_depth--
			}
		}
		if c == `,` && !in_quote && brace_depth == 0 && bracket_depth == 0 {
			parts << current.trim_space()
			current = ''
		} else {
			current += c.ascii_str()
		}
	}
	if current.trim_space() != '' {
		parts << current.trim_space()
	}
	return parts
}

fn is_pointer_address(s string) bool {
	trimmed := s.trim_space()
	if trimmed.starts_with('0x') || trimmed.starts_with('0X') {
		if trimmed.len > 8 {
			return true
		}
	}
	return false
}

fn has_digits_or_letters(s string) bool {
	for c in s {
		if (c >= `0` && c <= `9`) || (c >= `a` && c <= `z`) || (c >= `A` && c <= `Z`) || c == `_` {
			return true
		}
	}
	return true
}

fn extract_return_value(line string) ?u64 {
	idx := line.index(' = ') or { -1 }
	if idx == -1 {
		return none
	}
	right := line[idx + 3..].trim_space()
	if right == '' {
		return none
	}
	parts := right.split(' ')
	first_part := parts[0].trim_space()
	if first_part.starts_with('-') {
		return none
	}
	if first_part.starts_with('0x') || first_part.starts_with('0X') {
		return strconv.parse_uint(first_part[2..], 16, 64) or { return none }
	}
	if is_all_digits(first_part) {
		return first_part.u64()
	}
	return none
}

fn try_parse_flags(expr string) ?u64 {
	parts := expr.split('|')
	mut total := u64(0)
	for part in parts {
		trimmed := part.trim_space()
		val := match trimmed {
			'AF_UNIX', 'PF_UNIX' { u64(1) }
			'AF_INET', 'PF_INET' { u64(2) }
			'AF_INET6', 'PF_INET6' { u64(10) }
			'AF_NETLINK', 'PF_NETLINK' { u64(16) }
			'SOCK_STREAM' { u64(1) }
			'SOCK_DGRAM' { u64(2) }
			'SOCK_RAW' { u64(3) }
			'SOCK_CLOEXEC' { u64(0x80000) }
			'SOCK_NONBLOCK' { u64(0x800) }
			'PROT_NONE' { u64(0) }
			'PROT_READ' { u64(1) }
			'PROT_WRITE' { u64(2) }
			'PROT_EXEC' { u64(4) }
			'PR_SET_NAME' { u64(15) }
			'PR_SET_SECCOMP' { u64(22) }
			'PR_SET_NO_NEW_PRIVS' { u64(38) }
			'PR_SET_VMA' { u64(0x53564d41) }
			'F_GETFL' { u64(3) }
			'F_SETFL' { u64(4) }
			'F_DUPFD' { u64(0) }
			'F_DUPFD_CLOEXEC' { u64(1030) }
			'CLONE_VM' { u64(0x00000100) }
			'CLONE_FS' { u64(0x00000200) }
			'CLONE_FILES' { u64(0x00000400) }
			'CLONE_SIGHAND' { u64(0x00000800) }
			'CLONE_THREAD' { u64(0x00010000) }
			'TCGETS' { u64(0x5401) }
			'TCSETS' { u64(0x5402) }
			'TIOCGWINSZ' { u64(0x5413) }
			'TIOCGPGRP' { u64(0x540f) }
			'TIOCSPGRP' { u64(0x5410) }
			'AT_FDCWD' { u64(0xFFFFFFFFFFFFFF9C) }
			'MAP_FAILED' { u64(0xFFFFFFFFFFFFFFFF) }
			else {
				if trimmed.starts_with('0x') || trimmed.starts_with('0X') {
					strconv.parse_uint(trimmed[2..], 16, 64) or { return none }
				} else if trimmed.starts_with('0') && trimmed.len > 1 {
					strconv.parse_uint(trimmed[1..], 8, 64) or { return none }
				} else if is_all_digits(trimmed) {
					trimmed.u64()
				} else {
					return none
				}
			}
		}
		total = vanadium.c_add(total, val) or { total }
	}
	return total
}

fn is_valid_syscall_name(s string) bool {
	if s == '' {
		return false
	}
	first := s[0]
	if !((first >= `a` && first <= `z`) || (first >= `A` && first <= `Z`) || first == `_`) {
		return false
	}
	for c in s {
		if !((c >= `a` && c <= `z`) || (c >= `A` && c <= `Z`) || (c >= `0` && c <= `9`) || c == `_`) {
			return false
		}
	}
	return true
}

fn parse_condition(cond string) !vcomp.ArgRule {
	mut op := vcomp.Op.eq
	mut op_str := ''
	if cond.contains('==') {
		op = .eq
		op_str = '=='
	} else if cond.contains('!=') {
		op = .neq
		op_str = '!='
	} else if cond.contains('>=') {
		op = .ge
		op_str = '>='
	} else if cond.contains('>') {
		op = .gt
		op_str = '>'
	} else if cond.contains('&') {
		op = .bits_set
		op_str = '&'
	} else {
		return error('invalid operator in condition: ' + cond)
	}
	parts := cond.split(op_str)
	if parts.len != 2 {
		return error('invalid condition format: ' + cond)
	}
	idx := parts[0].trim_space().int()
	if idx < 0 || idx > 5 {
		return error('syscall argument index must be between 0 and 5')
	}
	val_str := parts[1].trim_space()
	mut val := u64(0)
	if val_str.starts_with('0x') || val_str.starts_with('0X') {
		val = strconv.parse_uint(val_str[2..], 16, 64) or {
			return error('failed to parse hex value: ' + val_str)
		}
	} else if val_str.starts_with('-') {
		val = u64(val_str.i64())
	} else {
		val = val_str.u64()
	}
	return vcomp.ArgRule{
		index: idx
		op: op
		value: val
	}
}

fn parse_syscall_rule(input string) !ParsedSyscall {
	idx := input.index(':') or { -1 }
	if idx == -1 {
		return ParsedSyscall{
			sys_name: input.trim_space()
			args: []
			str_args: []
		}
	}
	sys_name := input[0..idx].trim_space()
	conds_str := input[idx + 1..].trim_space()
	if conds_str == '' {
		return ParsedSyscall{
			sys_name: sys_name
			args: []
			str_args: []
		}
	}
	mut cond_parts := []string{}
	mut current := ''
	mut in_quote := false
	for i := 0; i < conds_str.len; i++ {
		c := conds_str[i]
		if c == `"` {
			in_quote = !in_quote
		}
		if c == `,` && !in_quote {
			cond_parts << current.trim_space()
			current = ''
		} else {
			current += c.ascii_str()
		}
	}
	if current.trim_space() != '' {
		cond_parts << current.trim_space()
	}
	mut args := []vcomp.ArgRule{}
	mut str_args := []string{}
	for cond in cond_parts {
		trimmed := cond.trim_space()
		if trimmed != '' {
			if trimmed.contains('=="') {
				str_args << trimmed
			} else {
				rule := parse_condition(trimmed)!
				args << rule
			}
		}
	}
	return ParsedSyscall{
		sys_name: sys_name
		args: args
		str_args: str_args
	}
}

fn extract_strace_time(line string) ?f64 {
	parts := line.split(' ')
	mut start_idx := 0
	if parts.len > 0 && is_all_digits(parts[0]) {
		start_idx = 1
	}
	if start_idx >= parts.len {
		return none
	}
	time_str := parts[start_idx]
	if !time_str.contains(':') || !time_str.contains('.') {
		return none
	}
	t_parts := time_str.split(':')
	if t_parts.len != 3 {
		return none
	}
	h := strconv.atof64(t_parts[0]) or { return none }
	m := strconv.atof64(t_parts[1]) or { return none }
	s := strconv.atof64(t_parts[2]) or { return none }
	return h * 3600.0 + m * 60.0 + s
}

fn run_with_runtime_timer(
	target_cmd string,
	target_args []string,
	runtime_time int,
	setup_only_list []string,
	errno_code int,
	filter_type_str string,
	blocks []string,
	block_errnos []string,
	allows []string,
	block_paths []string,
	allow_paths []string,
	block_strings []string,
	allow_strings []string
) {
	mut sys_name_map := map[int]string{}
	for sys_str in blocks {
		parsed := parse_syscall_rule(sys_str) or { continue }
		nr := resolve_syscall_num(parsed.sys_name) or { continue }
		sys_name_map[int(nr)] = parsed.sys_name
	}
	for sys_str in block_errnos {
		parsed := parse_syscall_rule(sys_str) or { continue }
		nr := resolve_syscall_num(parsed.sys_name) or { continue }
		sys_name_map[int(nr)] = parsed.sys_name
	}
	for sys_str in allows {
		parsed := parse_syscall_rule(sys_str) or { continue }
		nr := resolve_syscall_num(parsed.sys_name) or { continue }
		sys_name_map[int(nr)] = parsed.sys_name
	}
	for sys_name in setup_only_list {
		nr := resolve_syscall_num(sys_name.trim_space()) or { continue }
		sys_name_map[int(nr)] = sys_name.trim_space()
	}
	for sys in path_taking_syscalls {
		nr := resolve_syscall_num(sys) or { continue }
		sys_name_map[int(nr)] = sys
	}

	mut explicit_block := map[int]bool{}
	for sys_name in setup_only_list {
		nr := resolve_syscall_num(sys_name.trim_space()) or {
			eprintln('Warning: unknown syscall "${sys_name}" in setup-only')
			continue
		}
		explicit_block[int(nr)] = true
	}

	dynamic_allow_rules := build_dynamic_rules_map(allows)
	dynamic_block_rules := build_dynamic_rules_map(blocks)
	dynamic_block_errno_rules := build_dynamic_rules_map(block_errnos)
	mut str_check_map := map[int][]StrCheckData{}

	mut path_arg_indices := map[int][]int{}
	mut compiled_block_paths := []regex.RE{}
	mut compiled_allow_paths := []regex.RE{}
	
	if block_paths.len > 0 || allow_paths.len > 0 {
		for sys in path_taking_syscalls {
			nr := resolve_syscall_num(sys) or { continue }
			nr_i := int(nr)
			if nr_i !in path_arg_indices {
				if sys in ['openat', 'newfstatat', 'statx', 'fchmodat', 'fchownat', 'unlinkat', 'mkdirat', 'readlinkat'] {
					path_arg_indices[nr_i] = [1]
				} else if sys in ['renameat', 'renameat2', 'linkat'] {
					path_arg_indices[nr_i] = [1, 3]
				} else if sys in ['rename', 'link'] {
					path_arg_indices[nr_i] = [0, 1]
				} else {
					path_arg_indices[nr_i] = [0]
				}
			}
		}
		for b_path in block_paths {
			re_pattern := glob_to_regex(b_path)
			re := regex.regex_opt(re_pattern) or {
				eprintln('Invalid path regex "${b_path}": ${err}')
				continue
			}
			compiled_block_paths << re
		}
		for a_path in allow_paths {
			re_pattern := glob_to_regex(a_path)
			re := regex.regex_opt(re_pattern) or {
				eprintln('Invalid path regex "${a_path}": ${err}')
				continue
			}
			compiled_allow_paths << re
		}
	}

	mut compiled_block_strings := []regex.RE{}
	mut compiled_allow_strings := []regex.RE{}

	if block_strings.len > 0 || allow_strings.len > 0 {
		mut string_arg_indices := map[int][]int{}
		str_arg_defs := {
			'open': [0], 'openat': [1], 'execve': [0], 'execveat': [1],
			'chdir': [0], 'chroot': [0], 'access': [0], 'faccessat': [1],
			'stat': [0], 'lstat': [0], 'newfstatat': [1], 'statx': [1],
			'chmod': [0], 'fchmodat': [1], 'chown': [0], 'lchown': [0], 'fchownat': [1],
			'unlink': [0], 'unlinkat': [1], 'rmdir': [0], 'mkdir': [0], 'mkdirat': [1],
			'rename': [0, 1], 'renameat': [1, 3], 'renameat2': [1, 3],
			'link': [0, 1], 'linkat': [1, 3], 'symlink': [0, 1], 'symlinkat': [0, 2],
			'readlink': [0], 'readlinkat': [1], 'truncate': [0],
			'mount': [0, 1, 2], 'umount2': [0], 'pivot_root': [0, 1],
			'setxattr': [0, 1], 'lsetxattr': [0, 1], 'fsetxattr': [1],
			'getxattr': [0, 1], 'lgetxattr': [0, 1], 'fgetxattr': [1],
			'removexattr': [0], 'lremovexattr': [0], 'fremovexattr': [1],
			'acct': [0], 'swapon': [0], 'swapoff': [0], 'quotactl': [1],
			'init_module': [0], 'finit_module': [1]
		}
		for name, idxs in str_arg_defs {
			nr := resolve_syscall_num(name) or { continue }
			string_arg_indices[int(nr)] = idxs
			sys_name_map[int(nr)] = name
		}
		for b_str in block_strings {
			re := regex.regex_opt(b_str) or { continue }
			compiled_block_strings << re
		}
		for a_str in allow_strings {
			re := regex.regex_opt(a_str) or { continue }
			compiled_allow_strings << re
		}
	}

	has_static_rules := blocks.len > 0 || block_errnos.len > 0 || allows.len > 0

	pid := C.fork()
	if pid < 0 {
		eprintln('Error: fork failed')
		exit(1)
	}

	if pid == 0 {
		C.ptrace(ptrace_traceme, 0, 0, 0)
		C.prctl(pr_set_pdeathsig, sigkill_const, 0, 0, 0)
		if has_static_rules {
			filter_type := match filter_type_str {
				'allowlist' { vcomp.FilterType.allowlist }
				else { vcomp.FilterType.blocklist }
			}
			mut builder := vcomp.new_filter().set_type(filter_type).set_errno(errno_code)
			for sys_str in blocks {
				parsed := parse_syscall_rule(sys_str) or { continue }
				builder = builder.block(parsed.sys_name)
				for arg in parsed.args {
					builder = builder.where_arg(arg.index, arg.op, arg.value)
				}
			}
			for sys_str in block_errnos {
				parsed := parse_syscall_rule(sys_str) or { continue }
				builder = builder.block_with_errno(parsed.sys_name)
				for arg in parsed.args {
					builder = builder.where_arg(arg.index, arg.op, arg.value)
				}
			}
			for sys_str in allows {
				parsed := parse_syscall_rule(sys_str) or { continue }
				builder = builder.allow(parsed.sys_name)
				for arg in parsed.args {
					builder = builder.where_arg(arg.index, arg.op, arg.value)
				}
			}
			builder.apply() or {
				eprintln('Error applying seccomp in child: ${err}')
				C._exit(1)
			}
		}
		os.execvp(target_cmd, target_args) or {
			eprintln('Error executing target: ${err}')
			C._exit(1)
		}
		C._exit(0)
	}

	mut status := 0
	C.waitpid(pid, &status, 0)

	ptrace_opts := ptrace_o_tracesysgood | ptrace_o_tracefork | ptrace_o_tracevfork | ptrace_o_traceclone | ptrace_o_traceexec | ptrace_o_exitkill
	C.ptrace(ptrace_setoptions_op, pid, 0, ptrace_opts)

	mut is_enter_map := map[int]bool{}
	mut blocked_this_map := map[int]bool{}
	mut blocked_set := map[int]bool{}

	is_enter_map[pid] = true

	mut tv := C.timeval{}
	C.gettimeofday(&tv, unsafe { nil })
	start_time := f64(tv.tv_sec) + f64(tv.tv_usec) / 1e6
	obs_time := if runtime_time > 5 { 5 } else if runtime_time < 1 { 1 } else { runtime_time }

	mut phase := 1
	mut obs_start := f64(0)
	mut current_pid := pid
	mut pending_sig := 0
	mut skip_ptrace := false

	if runtime_time > 0 {
		C.signal(sigalrm_const, sigalrm_handler)
		C.alarm(u32(runtime_time))
	}

	for {
		if !skip_ptrace {
			C.ptrace(ptrace_syscall_op, current_pid, 0, pending_sig)
			pending_sig = 0
		} else {
			skip_ptrace = false
		}
		ret := C.waitpid(-1, &status, ptrace_wall)
		if ret <= 0 {
			if get_errno() == eintr_const && runtime_time > 0 {
				skip_ptrace = true
				C.gettimeofday(&tv, unsafe { nil })
				now := f64(tv.tv_sec) + f64(tv.tv_usec) / 1e6
				if phase == 1 && (now - start_time) >= f64(runtime_time) {
					if explicit_block.len > 0 {
						phase = 3
						for k, _ in explicit_block {
							blocked_set[k] = true
						}
					} else {
						phase = 2
						obs_start = now
						C.alarm(u32(obs_time))
					}
				} else if phase == 2 && (now - obs_start) >= f64(obs_time) {
					phase = 3
				}
			}
			if get_errno() == 10 {
				break
			}
			continue
		}
		
		current_pid = ret

		if (status & 0x7f) == 0 {
			if current_pid == pid {
				exit((status >> 8) & 0xff)
			}
			is_enter_map.delete(current_pid)
			blocked_this_map.delete(current_pid)
			str_check_map.delete(current_pid)
			continue
		}
		if (status & 0xff) != 0x7f {
			if current_pid == pid {
				exit(128 + (status & 0x7f))
			}
			is_enter_map.delete(current_pid)
			blocked_this_map.delete(current_pid)
			str_check_map.delete(current_pid)
			continue
		}

		sig := (status >> 8) & 0xff
		event := (status >> 16) & 0xffff

		if event != 0 {
			if event == 4 {
				is_enter_map[current_pid] = true
			}
			continue
		}

		if sig != 0x85 {
			if sig == 19 || sig == 17 {
				pending_sig = 0
			} else {
				pending_sig = sig
			}
			continue
		}

		if current_pid !in is_enter_map {
			is_enter_map[current_pid] = true
		}

		if is_enter_map[current_pid] {
			sys_nr := int(C.ptrace(ptrace_peekuser, current_pid, orig_rax_offset, 0))
			C.gettimeofday(&tv, unsafe { nil })
			now := f64(tv.tv_sec) + f64(tv.tv_usec) / 1e6
			elapsed := now - start_time

			if runtime_time > 0 {
				if phase == 1 && elapsed >= f64(runtime_time) {
					if explicit_block.len > 0 {
						phase = 3
						for k, _ in explicit_block {
							blocked_set[k] = true
						}
					} else {
						phase = 2
						obs_start = now
						C.alarm(u32(obs_time))
					}
				}
				if phase == 2 && (now - obs_start) >= f64(obs_time) {
					phase = 3
				}
			}

			blocked_this_map[current_pid] = false
			mut blocked_by_str := false
			mut do_str_check := false
			mut str_block_detail := ''

			if runtime_time > 0 && phase == 3 {
				do_str_check = true
			} else if runtime_time == 0 {
				do_str_check = true
			}

			mut checks := []StrCheckData{}
			mut read_cache := map[int]string{}

			if do_str_check {
				mut matched_block := false
				if sys_nr in dynamic_block_rules {
					for rule in dynamic_block_rules[sys_nr] {
						res, detail := match_dynamic_rule(rule, current_pid, sys_nr, mut checks, mut read_cache)
						if res {
							matched_block = true
							str_block_detail = 'explicit block rule matched: ${detail}'
							break
						}
					}
				}
				if !matched_block && sys_nr in dynamic_block_errno_rules {
					for rule in dynamic_block_errno_rules[sys_nr] {
						res, detail := match_dynamic_rule(rule, current_pid, sys_nr, mut checks, mut read_cache)
						if res {
							matched_block = true
							str_block_detail = 'explicit block-errno rule matched: ${detail}'
							break
						}
					}
				}
				if matched_block {
					blocked_by_str = true
				} else if sys_nr in dynamic_allow_rules {
					mut matched_allow := false
					for rule in dynamic_allow_rules[sys_nr] {
						res, _ := match_dynamic_rule(rule, current_pid, sys_nr, mut checks, mut read_cache)
						if res {
							matched_allow = true
							break
						}
					}
					if !matched_allow {
						blocked_by_str = true
						mut args_str_list := []string{}
						for idx, s in read_cache {
							args_str_list << 'arg[${idx}]="${s}"'
						}
						if args_str_list.len > 0 {
							str_block_detail = 'no allow rule matched. Args observed: ${args_str_list.join(", ")}'
						} else {
							str_block_detail = 'no allow rule matched'
						}
					}
				}
			}

			mut path_blocked := false
			mut blocked_path_str := ''
			mut blocked_by_allowlist := false

			if (compiled_block_paths.len > 0 || compiled_allow_paths.len > 0) && sys_nr in path_arg_indices {
				for idx in path_arg_indices[sys_nr] {
					if idx >= reg_offsets.len { continue }
					reg_offset := reg_offsets[idx]
					arg_ptr := u64(C.ptrace(ptrace_peekuser, current_pid, reg_offset, 0))
					if arg_ptr < 0x10000 { continue }
					mut actual_path := ''
					if idx in read_cache {
						actual_path = read_cache[idx]
					} else {
						mut actual_path_val := ''
						p_actual_path_val := &actual_path_val
						p_path_blocked := &path_blocked
						p_blocked_path_str := &blocked_path_str
						p_blocked_by_allowlist := &blocked_by_allowlist
						mut compiled_block_paths_mut := compiled_block_paths.clone()
						mut compiled_allow_paths_mut := compiled_allow_paths.clone()

						mut ij_path := read_string_to_ijail(current_pid, arg_ptr) or { continue }
						defer { ij_path.free() }
						ij_path.use(fn [p_actual_path_val, p_path_blocked, p_blocked_path_str, p_blocked_by_allowlist, mut compiled_block_paths_mut, mut compiled_allow_paths_mut] (p string) ! {
							mut resolved := p
							if os.is_link(p) {
								resolved = os.real_path(p)
								if resolved == '' {
									resolved = p
								}
							}
							unsafe {
								*p_actual_path_val = p.clone()
							}
							mut matched_allow := false
							if compiled_allow_paths_mut.len > 0 {
								for mut re in compiled_allow_paths_mut {
									start, end := re.match_string(resolved)
									if start >= 0 && end >= start {
										matched_allow = true
										break
									}
								}
							}
							mut matched_block := false
							if compiled_block_paths_mut.len > 0 {
								for mut re in compiled_block_paths_mut {
									start, end := re.match_string(resolved)
									if start >= 0 && end >= start {
										matched_block = true
										break
									}
								}
							}
							if matched_allow {
								unsafe {
									*p_path_blocked = false
								}
							} else if matched_block {
								unsafe {
									*p_path_blocked = true
									*p_blocked_path_str = resolved.clone()
								}
							} else if compiled_allow_paths_mut.len > 0 {
								unsafe {
									*p_path_blocked = true
									*p_blocked_by_allowlist = true
									*p_blocked_path_str = resolved.clone()
								}
							}
							_ = p_actual_path_val
							_ = p_path_blocked
							_ = p_blocked_path_str
							_ = p_blocked_by_allowlist
						}) or { continue }
						actual_path = actual_path_val
						read_cache[idx] = actual_path
						checks << StrCheckData{arg_ptr, actual_path, sys_nr, u64(0), 0}
					}
				}
			}

			mut string_blocked := false
			mut blocked_string_val := ''
			mut str_blocked_by_allowlist := false

			mut mut_block_strings := compiled_block_strings.clone()
			mut mut_allow_strings := compiled_allow_strings.clone()

			if mut_block_strings.len > 0 || mut_allow_strings.len > 0 {
				mut string_arg_indices := map[int][]int{}
				str_arg_defs := {
					'open': [0], 'openat': [1], 'execve': [0], 'execveat': [1],
					'chdir': [0], 'chroot': [0], 'access': [0], 'faccessat': [1],
					'stat': [0], 'lstat': [0], 'newfstatat': [1], 'statx': [1],
					'chmod': [0], 'fchmodat': [1], 'chown': [0], 'lchown': [0], 'fchownat': [1],
					'unlink': [0], 'unlinkat': [1], 'rmdir': [0], 'mkdir': [0], 'mkdirat': [1],
					'rename': [0, 1], 'renameat': [1, 3], 'renameat2': [1, 3],
					'link': [0, 1], 'linkat': [1, 3], 'symlink': [0, 1], 'symlinkat': [0, 2],
					'readlink': [0], 'readlinkat': [1], 'truncate': [0],
					'mount': [0, 1, 2], 'umount2': [0], 'pivot_root': [0, 1],
					'setxattr': [0, 1], 'lsetxattr': [0, 1], 'fsetxattr': [1],
					'getxattr': [0, 1], 'lgetxattr': [0, 1], 'fgetxattr': [1],
					'removexattr': [0], 'lremovexattr': [0], 'fremovexattr': [1],
					'acct': [0], 'swapon': [0], 'swapoff': [0], 'quotactl': [1],
					'init_module': [0], 'finit_module': [1]
				}
				for name, idxs in str_arg_defs {
					nr := resolve_syscall_num(name) or { continue }
					string_arg_indices[int(nr)] = idxs
				}
				if sys_nr in string_arg_indices {
					for idx in string_arg_indices[sys_nr] {
						if idx >= reg_offsets.len { continue }
						reg_offset := reg_offsets[idx]
						arg_ptr := u64(C.ptrace(ptrace_peekuser, current_pid, reg_offset, 0))
						if arg_ptr < 0x10000 { continue }
						mut actual_str := ''
						if idx in read_cache {
							actual_str = read_cache[idx]
						} else {
							mut actual_str_val := ''
							p_actual_str_val := &actual_str_val
							p_string_blocked := &string_blocked
							p_blocked_string_val := &blocked_string_val
							p_str_blocked_by_allowlist := &str_blocked_by_allowlist

							mut ij_str := read_string_to_ijail(current_pid, arg_ptr) or { continue }
							defer { ij_str.free() }
							ij_str.use(fn [p_actual_str_val, p_string_blocked, p_blocked_string_val, p_str_blocked_by_allowlist, mut mut_block_strings, mut mut_allow_strings] (s string) ! {
								unsafe {
									*p_actual_str_val = s.clone()
								}
								for mut re in mut_block_strings {
									start, end := re.match_string(s)
									if start >= 0 && end >= start {
										unsafe {
											*p_string_blocked = true
											*p_blocked_string_val = s
										}
										break
									}
								}
								if !unsafe { *p_string_blocked } && mut_allow_strings.len > 0 {
									mut is_allowed := false
									for mut re in mut_allow_strings {
										start, end := re.match_string(s)
										if start >= 0 && end >= start {
											is_allowed = true
											break
										}
									}
									if !is_allowed {
										unsafe {
											*p_string_blocked = true
											*p_str_blocked_by_allowlist = true
											*p_blocked_string_val = s
										}
									}
								}
								_ = p_actual_str_val
								_ = p_string_blocked
								_ = p_blocked_string_val
								_ = p_str_blocked_by_allowlist
							}) or { continue }
							actual_str = actual_str_val
							read_cache[idx] = actual_str
							checks << StrCheckData{arg_ptr, actual_str, sys_nr, u64(0), 0}
						}
					}
				}
			}

			mut should_block := false
			mut block_reason := ''

			if path_blocked {
				should_block = true
				if blocked_by_allowlist {
					block_reason = 'path allowlist block: accessed "${blocked_path_str}" not in allowed paths'
				} else {
					block_reason = 'path block: accessed "${blocked_path_str}"'
				}
			} else if string_blocked {
				should_block = true
				if str_blocked_by_allowlist {
					block_reason = 'string allowlist block: string "${blocked_string_val}" not in allowed strings'
				} else {
					block_reason = 'string block: detected string "${blocked_string_val}"'
				}
			} else if runtime_time > 0 && phase == 3 {
				if sys_nr in blocked_set {
					should_block = true
					block_reason = 'blocked in setup-only set (expired)'
				} else if blocked_by_str {
					should_block = true
					block_reason = str_block_detail
				}
			} else if runtime_time == 0 {
				if blocked_by_str {
					should_block = true
					block_reason = str_block_detail
				}
			}

			if should_block {
				sys_name_str := if sys_nr in sys_name_map { sys_name_map[sys_nr] } else { 'sys_' + sys_nr.str() }
				eprintln('[ptrace] Blocked syscall "${sys_name_str}" (sys=${sys_nr}) pid=${current_pid} | Reason: ${block_reason}')
				C.ptrace(ptrace_pokeuser, current_pid, orig_rax_offset, -1)
				blocked_this_map[current_pid] = true
			}

			str_check_map[current_pid] = checks
			is_enter_map[current_pid] = false
		} else {
			sys_ret := C.ptrace(ptrace_peekuser, current_pid, rax_offset, 0)
			if current_pid in str_check_map {
				checks := str_check_map[current_pid]
				mut toctou_detected := false
				if sys_ret >= 0 {
					for chk in checks {
						mut ij_str := read_string_to_ijail(current_pid, chk.ptr) or { continue }
						defer { ij_str.free() }
						mut actual_str_exit := ''
						p_actual_str_exit := &actual_str_exit
						ij_str.use(fn [p_actual_str_exit] (s string) ! {
							unsafe {
								*p_actual_str_exit = s.clone()
							}
							_ = p_actual_str_exit
						}) or { continue }
						if actual_str_exit != chk.orig {
							toctou_detected = true
							if chk.sys_nr == 257 || chk.sys_nr == 2 {
								inject_close(current_pid, int(sys_ret))
							} else if chk.sys_nr == 89 {
								mut actual_len := int(sys_ret)
								if actual_len > chk.buf_len {
									actual_len = chk.buf_len
								}
								zero_tracee_memory(current_pid, chk.buf_ptr, actual_len)
							} else if chk.sys_nr == 106 || chk.sys_nr == 107 || chk.sys_nr == 262 {
								zero_tracee_memory(current_pid, chk.buf_ptr, 256)
							}
							break
						}
					}
				}
				str_check_map.delete(current_pid)
				if toctou_detected {
					eprintln('[ptrace] TOCTOU detected and neutralized! pid=${current_pid}')
					C.ptrace(ptrace_pokeuser, current_pid, rax_offset, -errno_code)
				}
			}
			if blocked_this_map[current_pid] {
				C.ptrace(ptrace_pokeuser, current_pid, rax_offset, -errno_code)
			}
			is_enter_map[current_pid] = true
		}
	}
}
fn main() {
	mut fp := flag.new_flag_parser(os.args)
	fp.application('waterjail')
	fp.version('0.1.3')
	fp.description('A CLI tool to sandbox programs using custom syscall filters with argument and regex evaluation.')
	fp.skip_executable()

	blocks := fp.string_multi('block', `b`, 'Block a syscall. Format: <name> or <name>:<arg_index><op><value>')
	block_errnos := fp.string_multi('block-errno', `e`, 'Block a syscall and return errno. Format: <name> or <name>:<arg_index><op><value>')
	allows := fp.string_multi('allow', `a`, 'Allow a syscall. Format: <name> or <name>:<arg_index><op><value>')
	filter_type_str := fp.string('type', `t`, 'blocklist', 'Filter type: blocklist or allowlist')
	errno_code := fp.int('errno-code', 0, 1, 'Errno code to return when blocked (e.g., 1 for EPERM)')
	analyze := fp.bool('analyze', `A`, false, 'Analyze the command to dynamically generate the required allowlist')

	setup_time := fp.int('setup-time', 0, 0, 'Setup timer in seconds for analyze mode (0 = disabled)')
	runtime_time := fp.int('runtime-time', 0, 0, 'Runtime timer in seconds for execution mode (0 = disabled)')
	setup_only := fp.string_multi('setup-only', `s`, 'Syscall allowed only during runtime timer period, blocked after')
	block_paths := fp.string_multi('block-path', `P`, 'Globally block a path (supports wildcards *, ?) for all path-taking syscalls')
	allow_paths := fp.string_multi('allow-path', `W`, 'Globally allow a path (supports wildcards *, ?). If set, blocks all other path accesses.')
	
	block_strings := fp.string_multi('block-string', `B`, 'Globally block any string matching regex')
	allow_strings := fp.string_multi('allow-string', `S`, 'Globally allow any string matching regex. If set, blocks all other string inputs.')

	remaining_args := fp.finalize() or {
		eprintln('Error parsing flags: ${err}')
		exit(1)
	}

	if remaining_args.len == 0 {
		println(fp.usage())
		eprintln('Error: Please specify the target command to run.')
		exit(1)
	}

	target_cmd := remaining_args[0]
	target_args := remaining_args[1..]

	dangerous_syscalls := ['bpf', 'userfaultfd', 'perf_event_open', 'ptrace', 'keyctl', 'add_key', 'request_key', 'kexec_load', 'open_by_handle_at', 'mbind', 'set_mempolicy', 'migrate_pages', 'move_pages']

	if analyze {
		strace_path := os.find_abs_path_of_executable('strace') or { '' }
		if strace_path == '' {
			eprintln('Error: "strace" is required for analysis mode. Please install it first.')
			exit(1)
		}

		temp_file := os.join_path(os.temp_dir(), 'waterjail_strace_${os.getpid()}.txt')
		mut p := os.new_process(strace_path)
		mut strace_args := ['-f']
		if setup_time > 0 {
			strace_args << '-tt'
		}
		strace_args << ['-o', temp_file, target_cmd]
		strace_args << target_args
		p.set_args(strace_args)
		p.run()
		p.wait()

		mut unique_syscalls := []string{}
		mut socket_domains := []u64{}
		mut mprotect_unified_mask := u64(0)
		mut mmap_unified_mask := u64(0)
		mut arg_profiles := map[string][]u64{}
		mut str_arg_profiles := map[string][]string{}
		mut syscall_dynamic_args := map[string]bool{}
		mut ephemeral_values := []u64{}
		mut syscall_min_args := map[string]int{}
		mut syscall_max_args := map[string]int{}
		mut setup_phase_syscalls := map[string]bool{}
		mut runtime_phase_syscalls := map[string]bool{}
		mut first_timestamp := f64(-1)

		lines := os.read_lines(temp_file) or { []string{} }
		for line in lines {
			trimmed := line.trim_space()
			ret_val := extract_return_value(trimmed) or { u64(0) }
			if ret_val > 2 {
				if ret_val !in ephemeral_values {
					ephemeral_values << ret_val
				}
			}

			mut current_phase := 0
			if setup_time > 0 {
				line_time := extract_strace_time(trimmed) or { f64(-1) }
				if line_time >= 0 {
					if first_timestamp < 0 {
						first_timestamp = line_time
					}
					elapsed := line_time - first_timestamp
					if elapsed <= f64(setup_time) {
						current_phase = 1
					} else {
						current_phase = 2
					}
				}
			}

			mut cmd_part := trimmed
			idx_space := trimmed.index(' ') or { -1 }
			if idx_space != -1 {
				first_part := trimmed[0..idx_space]
				if is_all_digits(first_part) {
					rest := trimmed[idx_space + 1..].trim_space()
					if setup_time > 0 {
						idx_space2 := rest.index(' ') or { -1 }
						if idx_space2 != -1 {
							second_part := rest[0..idx_space2]
							if second_part.contains(':') && second_part.contains('.') {
								cmd_part = rest[idx_space2 + 1..].trim_space()
							} else {
								cmd_part = rest
							}
						} else {
							cmd_part = rest
						}
					} else {
						cmd_part = rest
					}
				}
			}

			if cmd_part.starts_with('socket(') {
				args_str := cmd_part.all_after('socket(').all_before(')')
				clean_args := clean_strace_args(args_str)
				parts := clean_args.split(',')
				if parts.len >= 1 {
					domain_val := try_parse_flags(parts[0]) or { continue }
					if domain_val !in socket_domains {
						socket_domains << domain_val
					}
				}
			} else if cmd_part.starts_with('mprotect(') {
				args_str := cmd_part.all_after('mprotect(').all_before(')')
				clean_args := clean_strace_args(args_str)
				parts := clean_args.split(',')
				if parts.len >= 3 {
					prot_val := try_parse_flags(parts[2]) or { continue }
					mprotect_unified_mask |= prot_val
				}
			} else if cmd_part.starts_with('mmap(') {
				args_str := cmd_part.all_after('mmap(').all_before(')')
				clean_args := clean_strace_args(args_str)
				parts := clean_args.split(',')
				if parts.len >= 3 {
					prot_val := try_parse_flags(parts[2]) or { continue }
					mmap_unified_mask |= prot_val
				}
			}

			idx := trimmed.index('(') or { -1 }
			if idx != -1 {
				before_paren := trimmed[0..idx].trim_space()
				sys_parts := before_paren.split(' ')
				sys_name := sys_parts.last().trim_space()
				if is_valid_syscall_name(sys_name) && sys_name !in dangerous_syscalls {
					_ := vcomp.get_syscall_number(sys_name) or { continue }
					if sys_name !in unique_syscalls {
						unique_syscalls << sys_name
					}
					if sys_name !in syscall_min_args {
						syscall_min_args[sys_name] = 999
						syscall_max_args[sys_name] = 0
					}
					if current_phase == 1 {
						setup_phase_syscalls[sys_name] = true
					} else if current_phase == 2 {
						runtime_phase_syscalls[sys_name] = true
					}

					if sys_name != 'mprotect' && sys_name != 'mmap' {
						args_str := cmd_part.all_after('(').all_before(')')
						clean_args := clean_strace_args(args_str)
						parts := smart_split_args(clean_args)
						if parts.len < syscall_min_args[sys_name] {
							syscall_min_args[sys_name] = parts.len
						}
						if parts.len > syscall_max_args[sys_name] {
							syscall_max_args[sys_name] = parts.len
						}
						for i, part in parts {
							if i >= 6 {
								break
							}
							arg_key := sys_name + '_' + i.str()
							if syscall_min_args[sys_name] != syscall_max_args[sys_name] && i >= syscall_min_args[sys_name] {
								syscall_dynamic_args[arg_key] = true
								if arg_key in arg_profiles {
									arg_profiles.delete(arg_key)
								}
								continue
							}
							trimmed_part := part.trim_space()
							if trimmed_part == '' {
								continue
							}
							if trimmed_part.starts_with('"') || trimmed_part.starts_with("'") {
								if sys_name in output_buffer_args && i in output_buffer_args[sys_name] {
									continue
								}
								if sys_name !in path_taking_syscalls {
									continue
								}
								s := trimmed_part.trim_left('"\'').trim_right('"\'')
								if s.len > 0 && s.len < 256 && !s.contains(',') && !s.contains('"') && !s.contains('\\') {
									if arg_key !in str_arg_profiles {
										str_arg_profiles[arg_key] = []string{}
									}
									if s !in str_arg_profiles[arg_key] {
										str_arg_profiles[arg_key] << s
									}
								}
								continue
							}
							if trimmed_part.starts_with('{') || trimmed_part.starts_with('[') {
								continue
							}
							if is_pointer_address(trimmed_part) {
								continue
							}
							if syscall_dynamic_args[arg_key] {
								continue
							}
							val := try_parse_flags(trimmed_part) or {
								if has_digits_or_letters(trimmed_part) {
									syscall_dynamic_args[arg_key] = true
									if arg_key in arg_profiles {
										arg_profiles.delete(arg_key)
									}
								}
								continue
							}
							if val in ephemeral_values {
								syscall_dynamic_args[arg_key] = true
								if arg_key in arg_profiles {
									arg_profiles.delete(arg_key)
								}
								continue
							}
							if arg_key !in arg_profiles {
								arg_profiles[arg_key] = []u64{}
							}
							if val !in arg_profiles[arg_key] {
								arg_profiles[arg_key] << val
							}
						}
					}
				}
			}
		}
		os.rm(temp_file) or {}

		if unique_syscalls.len == 0 {
			eprintln('Error: No syscalls were captured during analysis.')
			exit(1)
		}

		mut setup_only_syscalls := []string{}
		if setup_time > 0 {
			for sys in unique_syscalls {
				if sys in setup_phase_syscalls && !(sys in runtime_phase_syscalls) {
					mut is_info_call := false
					if sys in syscall_min_args && syscall_min_args[sys] == 1 && syscall_max_args[sys] == 1 {
						key := sys + '_0'
						if key !in arg_profiles && key !in str_arg_profiles {
							is_info_call = true
						}
					}
					if !is_info_call && sys != 'restart_syscall' {
						setup_only_syscalls << sys
					}
				}
			}
		}

		executable_path := os.real_path(os.args[0])
		mut cmd_builder := []string{}
		cmd_builder << executable_path
		cmd_builder << '-t allowlist'
		if setup_time > 0 && setup_only_syscalls.len > 0 {
			cmd_builder << '--runtime-time ${setup_time}'
		}

		for sys in unique_syscalls {
			if sys == 'mprotect' && mprotect_unified_mask > 0 {
				inverse_mask := ~mprotect_unified_mask
				if inverse_mask != 0 {
					cmd_builder << '-e "mprotect:2&${inverse_mask}"'
				}
				cmd_builder << '-a mprotect'
			} else if sys == 'mmap' && mmap_unified_mask > 0 {
				inverse_mask := ~mmap_unified_mask
				if inverse_mask != 0 {
					cmd_builder << '-e "mmap:2&${inverse_mask}"'
				}
				cmd_builder << '-a mmap'
			} else {
				mut arg_rules := []string{}
				mut str_rules := []string{}
				for i in 0 .. 6 {
					key := sys + '_' + i.str()
					if !syscall_dynamic_args[key] && key in arg_profiles && arg_profiles[key].len == 1 {
						val := arg_profiles[key][0]
						if val < 0x80000000 {
							arg_rules << '${i}==${val}'
						}
					}
					if key in str_arg_profiles && str_arg_profiles[key].len > 0 {
						strs := str_arg_profiles[key]
						prefix := find_common_prefix(strs)
						if strs.len > 1 && prefix.len > 2 {
							str_rules << '${i}=="${prefix}.*"'
						} else {
							if strs.len <= 5 {
								for s in strs {
									str_rules << '${i}=="${s}"'
								}
							}
						}
					}
				}
				mut all_rules := []string{}
				all_rules << arg_rules
				all_rules << str_rules
				if all_rules.len > 0 {
					rule_str := all_rules.join(",")
					if str_rules.len > 0 {
						mut escaped_rule_str := rule_str.replace("'", "'\\''")
						cmd_builder << "-a '${sys}:${escaped_rule_str}'"
					} else {
						cmd_builder << "-a ${sys}:${rule_str}"
					}
				} else {
					cmd_builder << '-a ${sys}'
				}
			}
			if setup_time > 0 && sys in setup_only_syscalls {
				cmd_builder << '--setup-only ${sys}'
			}
		}
		
		if block_paths.len > 0 {
			for bp in block_paths {
				cmd_builder << "--block-path ${bp}"
			}
		}
		if allow_paths.len > 0 {
			for ap in allow_paths {
				cmd_builder << "--allow-path ${ap}"
			}
		}

		cmd_builder << '--'
		cmd_builder << target_cmd
		cmd_builder << target_args.join(' ')

		script_content := cmd_builder.join(' ') + ' "$@"'
		script_file := os.base(target_cmd) + '.sh'
		
		os.write_file(script_file, '#!/bin/sh\nexec ' + script_content + '\n') or {
			eprintln('Error writing script file: ${err}')
			exit(1)
		}
		
		os.chmod(script_file, 0o755) or {}
		
		println(term.green('Captured ${unique_syscalls.len} unique syscalls.'))
		if setup_time > 0 {
			println(term.cyan('Setup timer: ${setup_time}s | Setup-only: ${setup_only_syscalls.len} | Always-needed: ${unique_syscalls.len - setup_only_syscalls.len}'))
		}
		println(term.green('Generated hardened script: ${script_file}'))
		println(term.cyan('Run it using: ./${script_file} [args...]'))
		exit(0)
	}

	if blocks.len == 0 && block_errnos.len == 0 && allows.len == 0 && runtime_time == 0 && block_paths.len == 0 && allow_paths.len == 0 && block_strings.len == 0 && allow_strings.len == 0 {
		eprintln('Error: No syscall filter rules specified.')
		eprintln('If you are using "v run", please use the long flag "--block-errno" instead of "-e",')
		eprintln('or compile the binary first and run it directly to avoid flag interception.')
		exit(1)
	}

	mut has_string_rules := false
	for sys_str in allows {
		if sys_str.contains('=="') {
			has_string_rules = true
			break
		}
	}
	if !has_string_rules {
		for sys_str in blocks {
			if sys_str.contains('=="') {
				has_string_rules = true
				break
			}
		}
	}
	if !has_string_rules {
		for sys_str in block_errnos {
			if sys_str.contains('=="') {
				has_string_rules = true
				break
			}
		}
	}

	filter_type := match filter_type_str {
		'allowlist' { vcomp.FilterType.allowlist }
		else { vcomp.FilterType.blocklist }
	}

	mut builder := vcomp.new_filter()
		.set_type(filter_type)
		.set_errno(errno_code)

	for sys_str in blocks {
		parsed := parse_syscall_rule(sys_str) or {
			eprintln('Error parsing block rule "${sys_str}": ${err}')
			exit(1)
		}
		builder = builder.block(parsed.sys_name)
		for arg in parsed.args {
			builder = builder.where_arg(arg.index, arg.op, arg.value)
		}
	}

	for sys_str in block_errnos {
		parsed := parse_syscall_rule(sys_str) or {
			eprintln('Error parsing block-errno rule "${sys_str}": ${err}')
			exit(1)
		}
		builder = builder.block_with_errno(parsed.sys_name)
		for arg in parsed.args {
			builder = builder.where_arg(arg.index, arg.op, arg.value)
		}
	}

	for sys_str in allows {
		parsed := parse_syscall_rule(sys_str) or {
			eprintln('Error parsing allow rule "${sys_str}": ${err}')
			exit(1)
		}
		builder = builder.allow(parsed.sys_name)
		for arg in parsed.args {
			builder = builder.where_arg(arg.index, arg.op, arg.value)
		}
	}

	if runtime_time > 0 || has_string_rules || block_paths.len > 0 || allow_paths.len > 0 || block_strings.len > 0 || allow_strings.len > 0 {
		run_with_runtime_timer(
			target_cmd, target_args, runtime_time, setup_only, errno_code,
			filter_type_str, blocks, block_errnos, allows, block_paths, allow_paths, block_strings, allow_strings
		)
		return
	}

	builder.apply() or {
		eprintln('Error applying Seccomp filter: ${err}')
		exit(1)
	}

	os.execvp(target_cmd, target_args) or {
		eprintln('Error executing target command: ${err}')
		exit(1)
	}
}
