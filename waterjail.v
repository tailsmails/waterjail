module main

import os
import flag
import strconv
import term
import vcomp

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <signal.h>

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

const ptrace_traceme = 0
const ptrace_peekdata = 2
const ptrace_peekuser = 3
const ptrace_pokeuser = 5
const ptrace_cont = 7
const ptrace_syscall_op = 24
const ptrace_setoptions_op = 0x4200
const ptrace_o_tracesysgood = 0x01
const ptrace_o_tracefork = 0x02
const ptrace_o_tracevfork = 0x04
const ptrace_o_traceclone = 0x08
const ptrace_o_traceexec = 0x10
const ptrace_wall = 0x40000000
const orig_rax_offset = 120
const rax_offset = 80
const reg_offsets = [112, 104, 96, 56, 72, 64]
const sigalrm_const = 14
const eintr_const = 4

fn sigalrm_handler(s os.Signal) {
}

struct ParsedSyscall {
	sys_name string
	args     []vcomp.ArgRule
	str_args []string
}

fn read_string_from_ptrace(pid int, addr u64) string {
	mut res := []u8{}
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
			res << b[i]
		}
		if found_null {
			break
		}
		current_addr += 8
		if res.len > 4096 {
			break
		}
	}
	return res.bytestr()
}

fn build_str_rules_map(rules []string) map[int]map[int][]string {
	mut m := map[int]map[int][]string{}
	for sys_str in rules {
		parsed := parse_syscall_rule(sys_str) or { continue }
		if parsed.str_args.len == 0 {
			continue
		}
		nr := vcomp.get_syscall_number(parsed.sys_name) or { continue }
		nr_i := int(nr)
		if nr_i !in m {
			m[nr_i] = map[int][]string{}
		}
		for s_rule in parsed.str_args {
			parts := s_rule.split('==')
			if parts.len != 2 {
				continue
			}
			idx := parts[0].trim_space().int()
			val := parts[1].trim_space().trim_left('"').trim_right('"')
			if idx !in m[nr_i] {
				m[nr_i][idx] = []string{}
			}
			m[nr_i][idx] << val
		}
	}
	return m
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
	return false
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
		total += val
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

	cond_parts := conds_str.split(',')
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
) {
	mut explicit_block := map[int]bool{}
	for sys_name in setup_only_list {
		nr := vcomp.get_syscall_number(sys_name.trim_space()) or {
			eprintln('Warning: unknown syscall "${sys_name}" in setup-only')
			continue
		}
		explicit_block[int(nr)] = true
	}

	ptrace_str_rules := build_str_rules_map(allows)

	has_static_rules := blocks.len > 0 || block_errnos.len > 0 || allows.len > 0

	pid := C.fork()
	if pid < 0 {
		eprintln('Error: fork failed')
		exit(1)
	}

	if pid == 0 {
		C.ptrace(ptrace_traceme, 0, 0, 0)

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

	ptrace_opts := ptrace_o_tracesysgood | ptrace_o_tracefork | ptrace_o_tracevfork | ptrace_o_traceclone | ptrace_o_traceexec
	C.ptrace(ptrace_setoptions_op, pid, 0, ptrace_opts)

	mut is_enter_map := map[int]bool{}
	mut blocked_this_map := map[int]bool{}
	mut phase1_syscalls := map[int]bool{}
	mut phase2_syscalls := map[int]bool{}
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

	if runtime_time > 0 {
		C.signal(sigalrm_const, sigalrm_handler)
		C.alarm(u32(runtime_time))
		println(term.cyan('[waterjail] Timer mode phase 1: allowing all for ${runtime_time}s'))
	} else {
		println(term.cyan('[waterjail] String filter mode active.'))
	}

	for {
		C.ptrace(ptrace_syscall_op, current_pid, 0, pending_sig)
		pending_sig = 0

		ret := C.waitpid(-1, &status, ptrace_wall)
		
		if ret <= 0 {
			if C.errno == eintr_const && runtime_time > 0 {
				C.gettimeofday(&tv, unsafe { nil })
				now := f64(tv.tv_sec) + f64(tv.tv_usec) / 1e6
				
				if phase == 1 && (now - start_time) >= f64(runtime_time) {
					if explicit_block.len > 0 {
						phase = 3
						for k, _ in explicit_block {
							blocked_set[k] = true
						}
						println(term.yellow('[waterjail] Async Timer expired: blocking ${blocked_set.len} setup-only syscalls'))
					} else {
						phase = 2
						obs_start = now
						C.alarm(u32(obs_time))
						println(term.yellow('[waterjail] Async Timer expired: observing for ${obs_time}s...'))
					}
				} else if phase == 2 && (now - obs_start) >= f64(obs_time) {
					phase = 3
					for nr, _ in phase1_syscalls {
						if !(nr in phase2_syscalls) {
							blocked_set[nr] = true
						}
					}
					println(term.yellow('[waterjail] Observation done: blocking ${blocked_set.len} unused syscalls'))
				}
			}
			
			if C.errno == 10 {
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
			continue
		}
		if (status & 0xff) != 0x7f {
			if current_pid == pid {
				exit(128 + (status & 0x7f))
			}
			is_enter_map.delete(current_pid)
			blocked_this_map.delete(current_pid)
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
				is_enter_map[current_pid] = true
			} else {
				pending_sig = sig
			}
			continue
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
						println(term.yellow('[waterjail] Sync Timer expired: blocking ${blocked_set.len} setup-only syscalls'))
					} else {
						phase = 2
						obs_start = now
						C.alarm(u32(obs_time))
						println(term.yellow('[waterjail] Sync Timer expired: observing for ${obs_time}s...'))
					}
				}

				if phase == 2 && (now - obs_start) >= f64(obs_time) {
					phase = 3
					for nr, _ in phase1_syscalls {
						if !(nr in phase2_syscalls) {
							blocked_set[nr] = true
						}
					}
					println(term.yellow('[waterjail] Observation done: blocking ${blocked_set.len} unused syscalls'))
				}

				if phase == 1 {
					phase1_syscalls[sys_nr] = true
				} else if phase == 2 && sys_nr in phase1_syscalls {
					phase2_syscalls[sys_nr] = true
				}
			}

			blocked_this_map[current_pid] = false
			mut blocked_by_str := false
			
			if sys_nr in ptrace_str_rules {
				mut all_match := true
				for idx, allowed_strs in ptrace_str_rules[sys_nr] {
					reg_offset := reg_offsets[idx]
					arg_ptr := u64(C.ptrace(ptrace_peekuser, current_pid, reg_offset, 0))
					actual_str := read_string_from_ptrace(current_pid, arg_ptr)
					if actual_str !in allowed_strs {
						all_match = false
						break
					}
				}
				if !all_match {
					blocked_by_str = true
				}
			}

			if (phase == 3 && sys_nr in blocked_set) || blocked_by_str {
				C.ptrace(ptrace_pokeuser, current_pid, orig_rax_offset, -1)
				blocked_this_map[current_pid] = true
			}

			is_enter_map[current_pid] = false
		} else {
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
	fp.version('0.0.4')
	fp.description('A CLI tool to sandbox programs using custom syscall filters with argument evaluation.')

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
				if is_valid_syscall_name(sys_name) {
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
								s := trimmed_part.trim_left('"\'').trim_right('"\'')
								if s.len > 0 && s.len < 256 {
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
					setup_only_syscalls << sys
				}
			}
		}

		println(term.green('Captured ${unique_syscalls.len} unique syscalls.'))
		if setup_time > 0 {
			println(term.cyan('Setup timer: ${setup_time}s | Setup-only: ${setup_only_syscalls.len} | Always-needed: ${unique_syscalls.len - setup_only_syscalls.len}'))
		}
		println(term.cyan('Generated hardened command:\n'))

		mut cmd_builder := []string{}
		cmd_builder << './waterjail'
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
					if key in str_arg_profiles && str_arg_profiles[key].len > 0 && str_arg_profiles[key].len <= 5 {
						for s in str_arg_profiles[key] {
							str_rules << '${i}=="${s}"'
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
		cmd_builder << '--'
		cmd_builder << target_cmd
		cmd_builder << target_args.join(' ')

		println(term.bold(cmd_builder.join(' ')))
		println(term.yellow('\n=== Parameter Analysis ==='))

		if socket_domains.len > 0 {
			println('\n[socket] analysis:')
			for dom in socket_domains {
				println(' - Allowed socket domain: ${dom}')
			}
		}

		if mprotect_unified_mask > 0 {
			println('\n[mprotect] analysis:')
			println(' - Unified allowed bitmask: ${mprotect_unified_mask}')
			inverse_mask := ~mprotect_unified_mask
			if inverse_mask != 0 {
				println(term.magenta(' inverse block rule: -e "mprotect:2&${inverse_mask}"'))
			}
		}

		if mmap_unified_mask > 0 {
			println('\n[mmap] analysis:')
			println(' - Unified allowed bitmask: ${mmap_unified_mask}')
			inverse_mask := ~mmap_unified_mask
			if inverse_mask != 0 {
				println(term.magenta(' inverse block rule: -e "mmap:2&${inverse_mask}"'))
			}
		}

		if setup_time > 0 && setup_only_syscalls.len > 0 {
			println(term.yellow('\n=== Setup Timer Analysis (${setup_time}s) ==='))
			println(term.red('Setup-only syscalls (blocked after ${setup_time}s):'))
			for sys in setup_only_syscalls {
				println(term.red('  ${sys}'))
			}
			println(term.green('Always-needed syscalls:'))
			for sys in unique_syscalls {
				if sys !in setup_only_syscalls {
					println(term.green('  ${sys}'))
				}
			}
		}

		for sys in unique_syscalls {
			if sys == 'mprotect' || sys == 'mmap' {
				continue
			}
			mut printed_sys := false
			for i in 0 .. 6 {
				key := sys + '_' + i.str()
				if syscall_dynamic_args[key] {
					if !printed_sys {
						println('\n[${sys}] analysis:')
						printed_sys = true
					}
					println(term.red(' - Arg ${i}: Dynamic/unstable value detected. Filter omitted.'))
				} else if key in arg_profiles && arg_profiles[key].len > 0 {
					if !printed_sys {
						println('\n[${sys}] analysis:')
						printed_sys = true
					}
					if arg_profiles[key].len == 1 {
						val := arg_profiles[key][0]
						if val >= 0x80000000 {
							println(term.yellow(' - Arg ${i}: Large 64-bit value detected (${val}). Filter omitted for BPF safety.'))
						} else {
							println(' - Allowed argument ${i} values: ${arg_profiles[key]}')
						}
					} else {
						println(term.yellow(' - Arg ${i}: Multiple stable values detected (${arg_profiles[key].len}). Filter omitted.'))
					}
				} else if key in str_arg_profiles && str_arg_profiles[key].len > 0 {
					if !printed_sys {
						println('\n[${sys}] analysis:')
						printed_sys = true
					}
					if str_arg_profiles[key].len <= 5 {
						println(term.green(' - Allowed string argument ${i} values: ${str_arg_profiles[key]}'))
					} else {
						println(term.yellow(' - Arg ${i}: Too many unique strings detected (${str_arg_profiles[key].len}). Filter omitted.'))
					}
				}
			}
			if !printed_sys {
				println('\n[${sys}] analysis: No stable arguments to filter. Allowed unconditionally.')
			}
		}
		exit(0)
	}

	if blocks.len == 0 && block_errnos.len == 0 && allows.len == 0 && runtime_time == 0 {
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

	if runtime_time > 0 || has_string_rules {
		run_with_runtime_timer(
			target_cmd, target_args, runtime_time, setup_only, errno_code,
			filter_type_str, blocks, block_errnos, allows,
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
