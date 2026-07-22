module main

import os
import flag
import strconv
import term
import vcomp

struct ParsedSyscall {
	sys_name string
	args     []vcomp.ArgRule
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
			else {
				if trimmed.starts_with('0x') || trimmed.starts_with('0X') {
					strconv.parse_uint(trimmed[2..], 16, 64) or { return none }
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
		}
	}

	sys_name := input[0..idx].trim_space()
	conds_str := input[idx + 1..].trim_space()
	if conds_str == '' {
		return ParsedSyscall{
			sys_name: sys_name
			args: []
		}
	}

	cond_parts := conds_str.split(',')
	mut args := []vcomp.ArgRule{}
	for cond in cond_parts {
		trimmed := cond.trim_space()
		if trimmed != '' {
			rule := parse_condition(trimmed)!
			args << rule
		}
	}

	return ParsedSyscall{
		sys_name: sys_name
		args: args
	}
}

fn main() {
	mut fp := flag.new_flag_parser(os.args)
	fp.application('waterjail')
	fp.version('0.0.1')
	fp.description('A CLI tool to sandbox programs using custom syscall filters with argument evaluation.')
	
	fp.skip_executable()

	blocks := fp.string_multi('block', `b`, 'Block a syscall. Format: <syscall> or <syscall>:<arg_index><op><value>')
	block_errnos := fp.string_multi('block-errno', `e`, 'Block a syscall and return errno. Format: <syscall> or <syscall>:<arg_index><op><value>')
	allows := fp.string_multi('allow', `a`, 'Allow a syscall. Format: <syscall> or <syscall>:<arg_index><op><value>')
	filter_type_str := fp.string('type', `t`, 'blocklist', 'Filter type: blocklist or allowlist')
	errno_code := fp.int('errno-code', 0, 1, 'Errno code to return when blocked (e.g., 1 for EPERM)')
	analyze := fp.bool('analyze', `A`, false, 'Analyze the command to dynamically generate the required allowlist')

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

		temp_file := os.join_path(os.temp_dir(), 'vcomp_strace_${os.getpid()}.txt')
		
		mut p := os.new_process(strace_path)
		mut strace_args := ['-f', '-o', temp_file, target_cmd]
		strace_args << target_args
		p.set_args(strace_args)
		p.run()
		p.wait()

		mut unique_syscalls := []string{}
		mut socket_domains := []u64{}
		mut mprotect_unified_mask := u64(0)
		mut mmap_unified_mask := u64(0)
		mut unique_prctl_options := []u64{}
		mut unique_ioctl_requests := []u64{}
		mut unique_fcntl_cmds := []u64{}
		mut unique_clone_flags := []u64{}

		mut prctl_fallback := false
		mut ioctl_fallback := false
		mut fcntl_fallback := false
		mut clone_fallback := false

		lines := os.read_lines(temp_file) or { []string{} }
		for line in lines {
			trimmed := line.trim_space()
			
			mut cmd_part := trimmed
			idx_space := trimmed.index(' ') or { -1 }
			if idx_space != -1 {
				first_part := trimmed[0..idx_space]
				if is_all_digits(first_part) {
					cmd_part = trimmed[idx_space + 1..].trim_space()
				}
			}

			if cmd_part.starts_with('socket(') {
				args_str := cmd_part.all_after('socket(').all_before(')')
				clean_args := clean_strace_args(args_str)
				parts := clean_args.split(',')
				if parts.len >= 1 {
					domain_val := try_parse_flags(parts[0]) or {
						continue
					}
					if domain_val !in socket_domains {
						socket_domains << domain_val
					}
				}
			} else if cmd_part.starts_with('mprotect(') {
				args_str := cmd_part.all_after('mprotect(').all_before(')')
				clean_args := clean_strace_args(args_str)
				parts := clean_args.split(',')
				if parts.len >= 3 {
					prot_val := try_parse_flags(parts[2]) or {
						continue
					}
					mprotect_unified_mask |= prot_val
				}
			} else if cmd_part.starts_with('mmap(') {
				args_str := cmd_part.all_after('mmap(').all_before(')')
				clean_args := clean_strace_args(args_str)
				parts := clean_args.split(',')
				if parts.len >= 3 {
					prot_val := try_parse_flags(parts[2]) or {
						continue
					}
					mmap_unified_mask |= prot_val
				}
			} else if cmd_part.starts_with('prctl(') {
				args_str := cmd_part.all_after('prctl(').all_before(')')
				clean_args := clean_strace_args(args_str)
				parts := clean_args.split(',')
				if parts.len >= 1 {
					opt_val := try_parse_flags(parts[0]) or {
						prctl_fallback = true
						u64(0)
					}
					if !prctl_fallback && opt_val !in unique_prctl_options {
						unique_prctl_options << opt_val
					}
				}
			} else if cmd_part.starts_with('ioctl(') {
				args_str := cmd_part.all_after('ioctl(').all_before(')')
				clean_args := clean_strace_args(args_str)
				parts := clean_args.split(',')
				if parts.len >= 2 {
					req_val := try_parse_flags(parts[1]) or {
						ioctl_fallback = true
						u64(0)
					}
					if !ioctl_fallback && req_val !in unique_ioctl_requests {
						unique_ioctl_requests << req_val
					}
				}
			} else if cmd_part.starts_with('fcntl(') {
				args_str := cmd_part.all_after('fcntl(').all_before(')')
				clean_args := clean_strace_args(args_str)
				parts := clean_args.split(',')
				if parts.len >= 2 {
					cmd_val := try_parse_flags(parts[1]) or {
						fcntl_fallback = true
						u64(0)
					}
					if !fcntl_fallback && cmd_val !in unique_fcntl_cmds {
						unique_fcntl_cmds << cmd_val
					}
				}
			} else if cmd_part.starts_with('clone(') {
				args_str := cmd_part.all_after('clone(').all_before(')')
				clean_args := clean_strace_args(args_str)
				parts := clean_args.split(',')
				if parts.len >= 1 {
					flg_val := try_parse_flags(parts[0]) or {
						clone_fallback = true
						u64(0)
					}
					if !clone_fallback && flg_val !in unique_clone_flags {
						unique_clone_flags << flg_val
					}
				}
			}

			idx := trimmed.index('(') or { -1 }
			if idx != -1 {
				before_paren := trimmed[0..idx].trim_space()
				sys_parts := before_paren.split(' ')
				sys_name := sys_parts.last().trim_space()
				if is_valid_syscall_name(sys_name) {
					_ := vcomp.get_syscall_number(sys_name) or {
						continue
					}
					if sys_name !in unique_syscalls {
						unique_syscalls << sys_name
					}
				}
			}
		}
		os.rm(temp_file) or {}

		if unique_syscalls.len == 0 {
			eprintln('Error: No syscalls were captured during analysis.')
			exit(1)
		}

		println(term.green('Captured ${unique_syscalls.len} unique syscalls.'))
		println(term.cyan('Generated hardened command:\n'))
		
		mut cmd_builder := []string{}
		cmd_builder << './example'
		cmd_builder << '-t allowlist'
		for sys in unique_syscalls {
			if sys == 'socket' {
				cmd_builder << '-a socket'
			} else if sys == 'mprotect' && mprotect_unified_mask > 0 {
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
			} else if sys == 'prctl' && !prctl_fallback && unique_prctl_options.len > 0 {
				for opt in unique_prctl_options {
					cmd_builder << '-a prctl:0==${opt}'
				}
			} else if sys == 'ioctl' && !ioctl_fallback && unique_ioctl_requests.len > 0 {
				for req in unique_ioctl_requests {
					cmd_builder << '-a ioctl:1==${req}'
				}
			} else if sys == 'fcntl' && !fcntl_fallback && unique_fcntl_cmds.len > 0 {
				for cmd in unique_fcntl_cmds {
					cmd_builder << '-a fcntl:1==${cmd}'
				}
			} else if sys == 'clone' && !clone_fallback && unique_clone_flags.len > 0 {
				for flg in unique_clone_flags {
					cmd_builder << '-a clone:0==${flg}'
				}
			} else {
				cmd_builder << '-a ${sys}'
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
				println('  - Allowed socket domain: ${dom}')
			}
		}

		if mprotect_unified_mask > 0 {
			println('\n[mprotect] analysis:')
			println('  - Unified allowed bitmask: ${mprotect_unified_mask}')
			inverse_mask := ~mprotect_unified_mask
			if inverse_mask != 0 {
				println(term.magenta('    inverse block rule: -e "mprotect:2&${inverse_mask}"'))
			}
		}

		if mmap_unified_mask > 0 {
			println('\n[mmap] analysis:')
			println('  - Unified allowed bitmask: ${mmap_unified_mask}')
			inverse_mask := ~mmap_unified_mask
			if inverse_mask != 0 {
				println(term.magenta('    inverse block rule: -e "mmap:2&${inverse_mask}"'))
			}
		}

		if !prctl_fallback && unique_prctl_options.len > 0 {
			println('\n[prctl] analysis:')
			for opt in unique_prctl_options {
				println('  - Allowed prctl option: ${opt}')
			}
		} else if prctl_fallback {
			println(term.red('\n[prctl] analysis: Unresolved constants detected. Defaulting to safe fallback mode.'))
		}

		if !ioctl_fallback && unique_ioctl_requests.len > 0 {
			println('\n[ioctl] analysis:')
			for req in unique_ioctl_requests {
				println('  - Allowed ioctl request: ${req}')
			}
		} else if ioctl_fallback {
			println(term.red('\n[ioctl] analysis: Unresolved constants detected. Defaulting to safe fallback mode.'))
		}

		if !fcntl_fallback && unique_fcntl_cmds.len > 0 {
			println('\n[fcntl] analysis:')
			for cmd in unique_fcntl_cmds {
				println('  - Allowed fcntl cmd: ${cmd}')
			}
		} else if fcntl_fallback {
			println(term.red('\n[fcntl] analysis: Unresolved constants detected. Defaulting to safe fallback mode.'))
		}

		if !clone_fallback && unique_clone_flags.len > 0 {
			println('\n[clone] analysis:')
			for flg in unique_clone_flags {
				println('  - Allowed clone flags: ${flg}')
			}
		} else if clone_fallback {
			println(term.red('\n[clone] analysis: Unresolved constants detected. Defaulting to safe fallback mode.'))
		}
		exit(0)
	}

	if blocks.len == 0 && block_errnos.len == 0 && allows.len == 0 {
		eprintln('Error: No syscall filter rules specified.')
		eprintln('If you are using "v run", please use the long flag "--block-errno" instead of "-e",')
		eprintln('or compile the binary first and run it directly to avoid flag interception.')
		exit(1)
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

	builder.apply() or {
		eprintln('Error applying Seccomp filter: ${err}')
		exit(1)
	}

	os.execvp(target_cmd, target_args) or {
		eprintln('Error executing target command: ${err}')
		exit(1)
	}
}
