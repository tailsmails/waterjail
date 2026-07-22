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
			if c == `{` { brace_depth++ }
			else if c == `}` { brace_depth-- }
			else if c == `[` { bracket_depth++ }
			else if c == `]` { bracket_depth-- }
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
	fp.version('0.0.2')
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

		temp_file := os.join_path(os.temp_dir(), 'waterjail_strace_${os.getpid()}.txt')
		
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
		
		mut arg_profiles := map[string][]u64{}
		mut syscall_fallbacks := map[string]bool{}
		mut ephemeral_values := []u64{}

		lines := os.read_lines(temp_file) or { []string{} }
		for line in lines {
			trimmed := line.trim_space()
			
			ret_val := extract_return_value(trimmed) or { u64(0) }
			if ret_val > 2 {
				if ret_val !in ephemeral_values {
					ephemeral_values << ret_val
				}
			}

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

					if sys_name != 'socket' && sys_name != 'mprotect' && sys_name != 'mmap' {
						args_str := cmd_part.all_after('(').all_before(')')
						clean_args := clean_strace_args(args_str)
						parts := smart_split_args(clean_args)
						for i, part in parts {
							if i >= 6 { break }
							trimmed_part := part.trim_space()
							if trimmed_part == '' { continue }
							if trimmed_part.starts_with('"') || trimmed_part.starts_with("'") { continue }
							if trimmed_part.starts_with('{') || trimmed_part.starts_with('[') { continue }
							if is_pointer_address(trimmed_part) { continue }

							val := try_parse_flags(trimmed_part) or {
								if has_digits_or_letters(trimmed_part) {
									syscall_fallbacks[sys_name] = true
								}
								u64(0)
							}

							if val in ephemeral_values {
								syscall_fallbacks[sys_name] = true
								continue
							}

							if !syscall_fallbacks[sys_name] {
								key := sys_name + '_' + i.str()
								if key !in arg_profiles {
									if key !in arg_profiles {
										arg_profiles[key] = []u64{}
									}
								}
								if val !in arg_profiles[key] {
									arg_profiles[key] << val
								}
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

		println(term.green('Captured ${unique_syscalls.len} unique syscalls.'))
		println(term.cyan('Generated hardened command:\n'))
		
		mut cmd_builder := []string{}
		cmd_builder << './waterjail'
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
			} else if syscall_fallbacks[sys] {
				cmd_builder << '-a ${sys}'
			} else {
				mut has_arg_filters := false
				for i in 0 .. 6 {
					key := sys + '_' + i.str()
					if key in arg_profiles && arg_profiles[key].len > 0 && arg_profiles[key].len <= 5 {
						for val in arg_profiles[key] {
							cmd_builder << '-a ${sys}:${i}==${val}'
						}
						has_arg_filters = true
					}
				}
				if !has_arg_filters {
					cmd_builder << '-a ${sys}'
				}
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

		for sys in unique_syscalls {
			if sys == 'socket' || sys == 'mprotect' || sys == 'mmap' {
				continue
			}
			if syscall_fallbacks[sys] {
				println(term.red('\n[${sys}] analysis: Unresolved constants, pointers, or ephemeral IDs detected. Defaulting to safe fallback.'))
			} else {
				mut printed_sys := false
				for i in 0 .. 6 {
					key := sys + '_' + i.str()
					if key in arg_profiles && arg_profiles[key].len > 0 && arg_profiles[key].len <= 5 {
						if !printed_sys {
							println('\n[${sys}] analysis:')
							printed_sys = true
						}
						println('  - Allowed argument ${i} values: ${arg_profiles[key]}')
					}
				}
			}
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
