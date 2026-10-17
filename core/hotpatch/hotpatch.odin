/*
	Package hotpatch implements in-process hot code patching for procedures
	annotated with `@(watch)` and built by the Odin compiler's `odin watch`
	command.

	`odin watch` spawns the compiled program with the `ODIN_HOTPATCH_SOCK`
	environment variable set to a unix lc_socket path. The compiler injects this
	package into the build automatically (no import required). A background
	listener on that lc_socket (or `start` can be called explicitly) receives the
	new machine code and relocations of every `@(watch)` procedure whenever a
	watched source file changes, maps that code into executable memory, applies
	the relocations and redirects the live procedures to the new code.

	This package deliberately only depends on `base:intrinsics` and a handful of
	libc functions (declared locally) so that it also works under `-bedrock`,
	which removes the `core` collection.

	This is the Odin port of the relocation machinery from the dpatch project
	which does the same for D.

	Linux/amd64 only.
*/
#+feature global-context
package hotpatch

import "base:intrinsics"

// ---------------------------------------------------------------------------
// Wire format. Must be kept in sync with src/watch.cpp.
// ---------------------------------------------------------------------------

@(private="file")
WATCH_MAGIC :: u32(0x44505443) // "DPTC"

@(private="file")
MAX_STUBS :: 256
@(private="file")
MAX_GOTS  :: 256
@(private="file")
STUB_SIZE :: 14 // FF 25 00 00 00 00 + 8-byte absolute target
@(private="file")
GOT_SIZE  :: 24 // 8-byte pointer / Tls_Slot (pointer + i64 + bool)
@(private="file")
PAGE_SIZE :: 4096
@(private="file")
MAX_FUNCTIONS :: 512

@(private="file")
Reloc_Type :: enum u8 {
	Abs64    = 1, // R_X86_64_64
	PC32     = 2, // R_X86_64_PC32 / PLT32
	GOTPCREL = 3, // R_X86_64_GOTPCREL(x)
	TLSGD    = 4, // R_X86_64_TLSGD
	Abs32S   = 5, // R_X86_64_32S
	GOTTPOFF = 6, // R_X86_64_GOTTPOFF
}

// Kept alive by GOT slots; mirrors dpatch's TlsSlot.
@(private="file")
Tls_Slot :: struct {
	sym_name: cstring,
	offset:   i64,
	inited:   bool,
}

@(private="file")
Reloc :: struct {
	offset: u32,
	type:   Reloc_Type,
	symbol: string,
	addend: i64,
}

@(private="file")
Parsed_Function :: struct {
	name:          string,
	code:          []u8,
	new_code:      uintptr,
	code_len:      u32,
	rodata:        rawptr,
	relocs:        []Reloc,
	original:      rawptr,
	original_size: u64,
}

// ---------------------------------------------------------------------------
// libc bindings (declared locally to avoid the `core` collection)
// ---------------------------------------------------------------------------

@(private="file")
PROT_READ     :: 0x01
@(private="file")
PROT_WRITE    :: 0x02
@(private="file")
PROT_EXEC     :: 0x04
@(private="file")
MAP_PRIVATE   :: 0x0002
@(private="file")
MAP_ANONYMOUS :: 0x0020
@(private="file")
MAP_FAILED    :: rawptr(~uintptr(0))
@(private="file")
AF_UNIX       :: 1
@(private="file")
SOCK_STREAM   :: 1
@(private="file")
SIGTRAP       :: 5
@(private="file")
SA_SIGINFO    :: 4
@(private="file")
EINTR         :: 4

@(private="file")
Sockaddr :: struct {
	sa_family: u16,
	sa_data:   [14]u8,
}

@(private="file")
Sockaddr_Un :: struct {
	sun_family: u16,
	sun_path:   [108]u8,
}

@(private="file")
Sigset :: struct {
	__val: [16]u64,
}

@(private="file")
Siginfo :: struct #align(8) {
	_pad: [128]u8,
}

@(private="file")
Sigaction :: struct {
	using _: struct #raw_union {
		handler:   proc "c" (i32),
		sa_sigaction: proc "c" (i32, ^Siginfo, rawptr),
	},
	mask:     Sigset,
	flags:    i32,
	restorer: rawptr,
}

foreign import libc "system:c"

@(default_calling_convention="c")
foreign libc {
	@(link_name="malloc")           lc_malloc           :: proc(size: uintptr) -> rawptr ---
	@(link_name="realloc")          lc_realloc          :: proc(ptr: rawptr, size: uintptr) -> rawptr ---
	@(link_name="free")             lc_free             :: proc(ptr: rawptr) ---
	@(link_name="memcpy")           lc_memcpy           :: proc(dst: rawptr, src: rawptr, n: uintptr) -> rawptr ---
	@(link_name="getenv")           lc_getenv           :: proc(name: cstring) -> cstring ---
	@(link_name="write")            lc_write            :: proc(fd: i32, buf: rawptr, n: uintptr) -> int ---
	@(link_name="read")             lc_read             :: proc(fd: i32, buf: rawptr, n: uintptr) -> int ---


	@(link_name="fopen")            lc_fopen            :: proc(path: cstring, mode: cstring) -> rawptr ---
	@(link_name="fread")            lc_fread            :: proc(ptr: rawptr, size: uintptr, nmemb: uintptr, stream: rawptr) -> uintptr ---
	@(link_name="fclose")           lc_fclose           :: proc(stream: rawptr) -> i32 ---

	@(link_name="dlsym")            lc_dlsym            :: proc(handle: rawptr, symbol: cstring) -> rawptr ---
	@(link_name="__errno_location") lc_errno_location   :: proc() -> ^i32 ---

	@(link_name="pthread_self")     lc_pthread_self     :: proc() -> uintptr ---
	@(link_name="pthread_create")   lc_pthread_create   :: proc(thread: ^uintptr, attr: rawptr, start: proc "c" (rawptr) -> rawptr, arg: rawptr) -> i32 ---

	@(link_name="sigaction")        lc_sigaction        :: proc(signum: i32, act: ^Sigaction, oldact: ^Sigaction) -> i32 ---
	@(link_name="signal")           lc_signal           :: proc(signum: i32, handler: rawptr) -> rawptr ---
	@(link_name="raise")            lc_raise            :: proc(sig: i32) -> i32 ---

	@(link_name="mmap")             lc_mmap             :: proc(addr: rawptr, length: uintptr, prot: i32, flags: i32, fd: i32, offset: i64) -> rawptr ---
	@(link_name="munmap")           lc_munmap           :: proc(addr: rawptr, length: uintptr) -> i32 ---
	@(link_name="mprotect")         lc_mprotect         :: proc(addr: rawptr, length: uintptr, prot: i32) -> i32 ---

	@(link_name="socket")           lc_socket           :: proc(domain: i32, type: i32, protocol: i32) -> i32 ---
	@(link_name="bind")             lc_bind             :: proc(fd: i32, addr: ^Sockaddr, len: u32) -> i32 ---
	@(link_name="listen")           lc_listen           :: proc(fd: i32, backlog: i32) -> i32 ---
	@(link_name="accept")           lc_accept           :: proc(fd: i32, addr: ^Sockaddr, len: ^u32) -> i32 ---
}

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

@(private="file")
g_verbose := false
@(private="file")
g_initialized := false
@(private="file")
g_listen_fd: i32 = -1
@(private="file")
g_sock_path: [256]u8
@(private="file")
g_running := false

// Registered patched symbols let a later patch chain onto an earlier one.
@(private="file")
Patched_Symbol :: struct {
	name: string,
	addr: rawptr,
	size: u64,
}
@(private="file")
g_patched: [1024]Patched_Symbol
@(private="file")
g_num_patched: int

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

@(private="file")
store_u8 :: #force_inline proc(at: uintptr, v: u8) { (cast(^u8)at)^ = v }
@(private="file")
store_u32 :: #force_inline proc(at: uintptr, v: u32) { (cast(^u32)at)^ = v }
@(private="file")
store_i32 :: #force_inline proc(at: uintptr, v: i32) { (cast(^i32)at)^ = v }
@(private="file")
store_u64 :: #force_inline proc(at: uintptr, v: u64) { (cast(^u64)at)^ = v }
@(private="file")
store_i64 :: #force_inline proc(at: uintptr, v: i64) { (cast(^i64)at)^ = v }

@(private="file")
round_up_page :: #force_inline proc(v: uintptr) -> uintptr {
	return (v + PAGE_SIZE - 1) & ~uintptr(PAGE_SIZE - 1)
}

@(private="file")
errno :: #force_inline proc() -> i32 { return lc_errno_location()^ }

// `close`/`unlink` are declared by core:sys/posix with link names that would
// clash, so go through the raw syscall intrinsic instead (Linux/amd64).
@(private="file")
SYS_close  :: 3
@(private="file")
SYS_unlink :: 87

@(private="file")
lc_close :: proc(fd: i32) -> i32 {
	return i32(intrinsics.syscall(SYS_close, uintptr(fd)))
}

@(private="file")
lc_unlink :: proc(path: cstring) -> i32 {
	return i32(intrinsics.syscall(SYS_unlink, uintptr(rawptr(path))))
}

@(private="file")
w :: proc(fd: i32, s: string) {
	if len(s) > 0 {
		_ = lc_write(fd, raw_data(s), uintptr(len(s)))
	}
}

@(private="file")
print_u64 :: proc(fd: i32, v: u64, base: u64, width: int) {
	buf: [24]u8
	i := len(buf)
	n := v
	if n == 0 {
		i -= 1
		buf[i] = '0'
	} else {
		for n > 0 {
			d := u8(n % base)
			n /= base
			i -= 1
			buf[i] = d < 10 ? ('0' + d) : ('a' + (d - 10))
		}
	}
	for i > 0 && (len(buf) - i) < width {
		i -= 1
		buf[i] = '0'
	}
	_ = lc_write(fd, rawptr(&buf[i]), uintptr(len(buf) - i))
}

@(private="file")
print_i64 :: proc(fd: i32, v: i64) {
	if v < 0 {
		w(fd, "-")
		print_u64(fd, u64(-v), 10, 0)
	} else {
		print_u64(fd, u64(v), 10, 0)
	}
}

@(private="file")
print_ptr :: proc(fd: i32, p: rawptr) {
	w(fd, "0x")
	print_u64(fd, u64(uintptr(p)), 16, 16)
}

@(private="file")
eline :: proc(parts: ..string) {
	for p in parts { w(2, p) }
	w(2, "\n")
}

@(private="file")
oline :: proc(parts: ..string) {
	for p in parts { w(1, p) }
	w(1, "\n")
}

// Null-terminated copy of an Odin string.
@(private="file")
cstr_dup :: proc(s: string) -> cstring {
	if len(s) == 0 {
		return cstring(rawptr(nil))
	}
	p := lc_malloc(uintptr(len(s) + 1))
	if p == nil {
		return cstring(rawptr(nil))
	}
	_ = lc_memcpy(p, raw_data(s), uintptr(len(s)))
	(cast([^]u8)p)[len(s)] = 0
	return cstring(p)
}

@(private="file")
str_dup :: proc(s: string) -> string {
	if len(s) == 0 {
		return ""
	}
	p := lc_malloc(uintptr(len(s)))
	if p == nil {
		return ""
	}
	_ = lc_memcpy(p, raw_data(s), uintptr(len(s)))
	return string((cast([^]u8)p)[:len(s)])
}

// ---------------------------------------------------------------------------
// ELF symbol lookup in the running executable (for sizes and _DYNAMIC)
// ---------------------------------------------------------------------------

@(private="file")
Elf64_Ehdr :: struct {
	e_ident:     [16]u8,
	e_type:      u16,
	e_machine:   u16,
	e_version:   u32,
	e_entry:     u64,
	e_phoff:     u64,
	e_shoff:     u64,
	e_flags:     u32,
	e_ehsize:    u16,
	e_phentsize: u16,
	e_phnum:     u16,
	e_shentsize: u16,
	e_shnum:     u16,
	e_shstrndx:  u16,
}

@(private="file")
Elf64_Shdr :: struct {
	sh_name:      u32,
	sh_type:      u32,
	sh_flags:     u64,
	sh_addr:      u64,
	sh_offset:    u64,
	sh_size:      u64,
	sh_link:      u32,
	sh_info:      u32,
	sh_addralign: u64,
	sh_entsize:   u64,
}

@(private="file")
Elf64_Sym :: struct {
	st_name:  u32,
	st_info:  u8,
	st_other: u8,
	st_shndx: u16,
	st_value: u64,
	st_size:  u64,
}

@(private="file")
SHT_SYMTAB :: 2

// Reads the whole of /proc/self/exe into a lc_malloc'd buffer.
@(private="file")
read_self_exe :: proc(out_len: ^uintptr) -> rawptr {
	f := lc_fopen("/proc/self/exe", "rb")
	if f == nil {
		return nil
	}
	cap := uintptr(1 << 20)
	buf := lc_malloc(cap)
	if buf == nil {
		lc_fclose(f)
		return nil
	}
	total: uintptr = 0
	for {
		if total == cap {
			cap *= 2
			nb := lc_realloc(buf, cap)
			if nb == nil {
				lc_free(buf)
				lc_fclose(f)
				return nil
			}
			buf = nb
		}
		n := lc_fread(rawptr(uintptr(buf) + total), 1, cap - total, f)
		if n == 0 {
			break
		}
		total += n
	}
	lc_fclose(f)
	out_len^ = total
	return buf
}

@(private="file")
elf_lookup :: proc(name: string) -> (value: u64, size: u64, ok: bool) {
	flen: uintptr
	data := read_self_exe(&flen)
	if data == nil {
		return 0, 0, false
	}
	defer lc_free(data)

	if flen < uintptr(size_of(Elf64_Ehdr)) {
		return 0, 0, false
	}

	base := uintptr(data)
	ehdr := cast(^Elf64_Ehdr)base
	if ehdr.e_ident[0] != 0x7f || ehdr.e_ident[1] != 'E' || ehdr.e_ident[2] != 'L' || ehdr.e_ident[3] != 'F' {
		return 0, 0, false
	}
	if ehdr.e_shoff == 0 || ehdr.e_shnum == 0 {
		return 0, 0, false
	}

	shoff := int(ehdr.e_shoff)
	shnum := int(ehdr.e_shnum)
	if shoff < 0 || uintptr(shoff) + uintptr(shnum)*uintptr(size_of(Elf64_Shdr)) > flen {
		return 0, 0, false
	}
	shdrs := cast([^]Elf64_Shdr)(base + uintptr(shoff))

	symtab: ^Elf64_Shdr
	for i in 0..<shnum {
		if shdrs[i].sh_type == SHT_SYMTAB {
			symtab = &shdrs[i]
			break
		}
	}
	if symtab == nil || int(symtab.sh_link) >= shnum {
		return 0, 0, false
	}
	strtab := &shdrs[symtab.sh_link]

	symbase := base + uintptr(symtab.sh_offset)
	strbase := base + uintptr(strtab.sh_offset)
	strsize := uintptr(strtab.sh_size)
	count := int(symtab.sh_size / size_of(Elf64_Sym))

	for i in 0..<count {
		sym := &(cast([^]Elf64_Sym)symbase)[i]
		if sym.st_shndx == 0 {
			continue
		}
		if uintptr(sym.st_name) >= strsize {
			continue
		}
		nm := string(cast(cstring)rawptr(strbase + uintptr(sym.st_name)))
		if nm == name {
			return sym.st_value, sym.st_size, true
		}
	}
	return 0, 0, false
}

@(private="file")
g_base_addr: uintptr
@(private="file")
g_base_ready: bool

@(private="file")
dl_phdr_info :: struct {
	dlpi_addr: uintptr,
	dlpi_name: cstring,
}

@(default_calling_convention="c")
foreign libc {
	dl_iterate_phdr :: proc(cb: proc "c" (info: ^dl_phdr_info, size: uintptr, data: rawptr) -> i32, data: rawptr) -> i32 ---
}

@(private="file")
phdr_callback :: proc "c" (info: ^dl_phdr_info, size: uintptr, data: rawptr) -> i32 {
	// The main program is always the first entry.
	g_base_addr = info.dlpi_addr
	g_base_ready = true
	return 1
}

// Load bias of the main executable, reported by the dynamic loader.
@(private="file")
get_base_address :: proc() -> uintptr {
	if !g_base_ready {
		g_base_ready = true
		dl_iterate_phdr(phdr_callback, nil)
	}
	return g_base_addr
}

@(private="file")
resolve_symbol :: proc(name: string, out_size: ^u64) -> rawptr {
	if out_size != nil {
		out_size^ = 0
	}
	val, sz, ok := elf_lookup(name)
	if ok && out_size != nil {
		out_size^ = sz
	}

	// NOTE: leaks a small cstring per unique name; acceptable for a dev tool.
	cs := cstr_dup(name)
	addr := lc_dlsym(nil, cs)
	if addr != nil {
		return addr
	}
	if ok {
		if base := get_base_address(); base != 0 {
			return rawptr(base + uintptr(val))
		}
	}
	return nil
}

@(private="file")
resolve_symbol_local :: proc(name: string, out_size: ^u64) -> rawptr {
	lookup := name
	if len(lookup) > 6 && lookup[:6] == ".text." {
		lookup = lookup[6:]
	}
	for i in 0..<g_num_patched {
		if g_patched[i].name == lookup {
			if out_size != nil {
				out_size^ = g_patched[i].size
			}
			return g_patched[i].addr
		}
	}
	return resolve_symbol(name, out_size)
}

@(private="file")
register_patched_symbol :: proc(name: string, addr: rawptr, size: u64) {
	for i in 0..<g_num_patched {
		if g_patched[i].name == name {
			g_patched[i].addr = addr
			g_patched[i].size = size
			return
		}
	}
	if g_num_patched >= len(g_patched) {
		return
	}
	g_patched[g_num_patched] = {str_dup(name), addr, size}
	g_num_patched += 1
}

// ---------------------------------------------------------------------------
// TLS support
// ---------------------------------------------------------------------------

// On glibc/x86_64 the thread pointer equals lc_pthread_self().
@(private="file")
tls_base :: proc() -> rawptr {
	return rawptr(lc_pthread_self())
}

@(private="file")
hotpatch_tls_get_addr :: proc "c" (ti: rawptr) -> rawptr {
	slot := cast(^Tls_Slot)ti
	if !slot.inited {
		addr := resolve_symbol(string(slot.sym_name), nil)
		if addr == nil {
			return nil
		}
		tp := tls_base()
		slot.offset = i64(uintptr(addr)) - i64(uintptr(tp))
		slot.inited = true
	}
	tp := tls_base()
	return rawptr(uintptr(i64(uintptr(tp)) + slot.offset))
}

// ---------------------------------------------------------------------------
// Executable code pages
// ---------------------------------------------------------------------------

@(private="file")
g_next_jit_addr: uintptr

// Allocate a page near the main executable so 32-bit PC-relative references
// from the original code fit within +-2GB.
@(private="file")
alloc_code_page :: proc(size: int) -> rawptr {
	rounded := round_up_page(uintptr(size))
	base := get_base_address()

	if base == 0 {
		p := lc_mmap(nil, rounded, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
		if p == MAP_FAILED {
			return nil
		}
		return p
	}

	if g_next_jit_addr == 0 {
		g_next_jit_addr = base + 0x04000000
	}
	for _ in 0..<1000 {
		hint := g_next_jit_addr & ~uintptr(PAGE_SIZE - 1)
		diff := i64(hint) - i64(base)
		if diff < -2147483648 || diff > 2147483647 {
			g_next_jit_addr = base + 0x04000000
			hint = g_next_jit_addr & ~uintptr(PAGE_SIZE - 1)
		}
		p := lc_mmap(rawptr(hint), rounded, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
		if p != MAP_FAILED && p != nil {
			ad := i64(uintptr(p)) - i64(base)
			if ad >= -2147483648 && ad <= 2147483647 {
				g_next_jit_addr = uintptr(p) + rounded
				return p
			}
			lc_munmap(p, rounded)
		}
		g_next_jit_addr += 65536
	}

	p := lc_mmap(nil, rounded, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
	if p == MAP_FAILED {
		return nil
	}
	return p
}

// ---------------------------------------------------------------------------
// Trampoline + INT3 hazard lc_signal handler
// ---------------------------------------------------------------------------

@(private="file")
Hook :: struct {
	original_addr: rawptr,
	target_addr:   rawptr,
}
@(private="file")
g_hooks: [2048]Hook
@(private="file")
g_num_hooks: int
@(private="file")
g_old_sigaction: Sigaction
@(private="file")
g_signal_installed: bool

@(private="file")
Stack_T :: struct {
	ss_sp:    rawptr,
	ss_flags: i32,
	ss_size:  uintptr,
}
@(private="file")
Mcontext_T :: struct {
	gregs: [32]i64,
}
@(private="file")
Ucontext_T :: struct {
	uc_flags:    u64,
	uc_link:     ^Ucontext_T,
	uc_stack:    Stack_T,
	uc_mcontext: Mcontext_T,
}
@(private="file")
REG_RIP :: 16

@(private="file")
sigtrap_handler :: proc "c" (sig: i32, info: ^Siginfo, context_ptr: rawptr) {
	uc := cast(^Ucontext_T)context_ptr
	rip := uintptr(uc.uc_mcontext.gregs[REG_RIP])
	trigger := rip - 1
	for i in 0..<g_num_hooks {
		if uintptr(g_hooks[i].original_addr) == trigger {
			uc.uc_mcontext.gregs[REG_RIP] = i64(uintptr(g_hooks[i].target_addr))
			return
		}
	}
	if g_old_sigaction.sa_sigaction != nil {
		g_old_sigaction.sa_sigaction(sig, info, context_ptr)
	} else {
		_ = lc_signal(sig, nil)
		_ = lc_raise(sig)
	}
}

@(private="file")
install_signal_handler :: proc() -> bool {
	if g_signal_installed {
		return true
	}
	sa: Sigaction
	sa.flags = SA_SIGINFO
	sa.sa_sigaction = sigtrap_handler
	if lc_sigaction(SIGTRAP, &sa, &g_old_sigaction) != 0 {
		return false
	}
	g_signal_installed = true
	return true
}

@(private="file")
uninstall_signal_handler :: proc() {
	if !g_signal_installed {
		return
	}
	_ = lc_sigaction(SIGTRAP, &g_old_sigaction, nil)
	g_signal_installed = false
}

// Overwrite the prologue of `original` with a jump to `target` using a
// two-phase INT3 commit so a thread hitting the function mid-lc_write is
// redirected by the lc_signal handler.
@(private="file")
write_trampoline :: proc(original, target: rawptr, original_size: int) -> bool {
	if original == nil || target == nil {
		return false
	}
	if original_size > 0 && original_size < 5 {
		return false
	}

	// Pick the jump form by size: the 14-byte absolute jump (FF 25 + 8-byte
	// target) needs 14 bytes, so anything smaller uses a 5-byte relative jump
	// (E9 rel32). When the size is unknown (0) the relative form is used too, as
	// it writes the fewest bytes and is therefore the safest guess.
	use_rel32 := original_size < 14
	rel_diff: i64
	if use_rel32 {
		rel_diff = i64(uintptr(target)) - (i64(uintptr(original)) + 5)
		if rel_diff < -2147483648 || rel_diff > 2147483647 {
			return false
		}
	}
	if !install_signal_handler() {
		return false
	}

	trampoline_len := 14
	if use_rel32 {
		trampoline_len = original_size
		if trampoline_len < 5 {
			trampoline_len = 5
		}
	}

	dest := uintptr(original)
	page_start := dest & ~uintptr(PAGE_SIZE - 1)
	page_end := round_up_page(dest + uintptr(trampoline_len))
	if lc_mprotect(rawptr(page_start), page_end-page_start, PROT_READ|PROT_WRITE|PROT_EXEC) != 0 {
		return false
	}

	hook_idx := -1
	for i in 0..<g_num_hooks {
		if g_hooks[i].original_addr == original {
			hook_idx = i
			break
		}
	}
	if hook_idx == -1 {
		if g_num_hooks >= len(g_hooks) {
			return false
		}
		hook_idx = g_num_hooks
		g_num_hooks += 1
		g_hooks[hook_idx].original_addr = original
	}
	g_hooks[hook_idx].target_addr = target

	store_u8(dest, 0xCC)
	intrinsics.atomic_thread_fence(.Seq_Cst)

	if use_rel32 {
		store_i32(dest + 1, i32(rel_diff))
		for p in 5..<trampoline_len {
			store_u8(dest + uintptr(p), 0x90)
		}
		intrinsics.atomic_thread_fence(.Seq_Cst)
		store_u8(dest, 0xE9)
		intrinsics.atomic_thread_fence(.Seq_Cst)
	} else {
		store_u8(dest + 1, 0x25)
		store_u8(dest + 2, 0x00)
		store_u8(dest + 3, 0x00)
		store_u8(dest + 4, 0x00)
		store_u8(dest + 5, 0x00)
		tv := u64(uintptr(target))
		for i in 0..<8 {
			store_u8(dest + 6 + uintptr(i), u8(tv >> uint(i * 8)))
		}
		intrinsics.atomic_thread_fence(.Seq_Cst)
		store_u8(dest, 0xFF)
		intrinsics.atomic_thread_fence(.Seq_Cst)
	}

	_ = lc_mprotect(rawptr(page_start), page_end-page_start, PROT_READ|PROT_EXEC)
	return true
}

// ---------------------------------------------------------------------------
// Payload parsing
// ---------------------------------------------------------------------------

@(private="file")
Reader :: struct {
	data: []u8,
	pos:  int,
	ok:   bool,
}

@(private="file")
rget :: proc(r: ^Reader, n: int) -> []u8 {
	if !r.ok || n < 0 || r.pos + n > len(r.data) {
		r.ok = false
		return nil
	}
	s := r.data[r.pos:r.pos+n]
	r.pos += n
	return s
}

@(private="file")
ru8 :: proc(r: ^Reader) -> u8 {
	s := rget(r, 1)
	if s == nil { return 0 }
	return s[0]
}

@(private="file")
ru16 :: proc(r: ^Reader) -> u16 {
	s := rget(r, 2)
	if s == nil { return 0 }
	return u16(s[0]) | u16(s[1])<<8
}

@(private="file")
ru32 :: proc(r: ^Reader) -> u32 {
	s := rget(r, 4)
	if s == nil { return 0 }
	return u32(s[0]) | u32(s[1])<<8 | u32(s[2])<<16 | u32(s[3])<<24
}

@(private="file")
ri64 :: proc(r: ^Reader) -> i64 {
	s := rget(r, 8)
	if s == nil { return 0 }
	v: u64
	for i in 0..<8 {
		v |= u64(s[i]) << uint(i * 8)
	}
	return i64(v)
}

@(private="file")
rst :: proc(r: ^Reader, n: int) -> string {
	s := rget(r, n)
	if s == nil { return "" }
	return string(s)
}

// ---------------------------------------------------------------------------
// Applying a payload
// ---------------------------------------------------------------------------

@(private="file")
apply_relocations :: proc(f: ^Parsed_Function, funcs: []Parsed_Function) -> bool {
	rw_base := f.new_code + round_up_page(uintptr(f.code_len))
	stubs_base := rw_base
	gots_base := rw_base + uintptr(MAX_STUBS*STUB_SIZE)
	stub_idx := 0
	got_idx := 0

	for r in f.relocs {
		is_rodata := r.offset >= f.code_len
		patch_ptr: uintptr
		if is_rodata {
			patch_ptr = uintptr(f.rodata) + uintptr(r.offset - f.code_len)
		} else {
			patch_ptr = f.new_code + uintptr(r.offset)
		}

		target: rawptr
		switch r.symbol {
		case ".rodata":
			target = f.rodata
		case "__tls_get_addr":
			target = rawptr(hotpatch_tls_get_addr)
		case:
			lookup := r.symbol
			if len(lookup) > 6 && lookup[:6] == ".text." {
				lookup = lookup[6:]
			}
			for k in 0..<len(funcs) {
				if funcs[k].name == lookup {
					target = rawptr(funcs[k].new_code)
					break
				}
			}
			if target == nil {
				target = resolve_symbol_local(r.symbol, nil)
			}
		}

		if target == nil {
			if g_verbose {
				eline("[hotpatch] failed to resolve symbol: ", r.symbol)
			}
			return false
		}

		switch r.type {
		case .Abs64:
			store_u64(patch_ptr, u64(uintptr(target)) + u64(r.addend))

		case .PC32:
			toff := (i64(uintptr(target)) + r.addend) - i64(patch_ptr)
			if !is_rodata && (toff < -2147483648 || toff > 2147483647) {
				if stub_idx >= MAX_STUBS {
					return false
				}
				stub_addr := stubs_base + uintptr(stub_idx*STUB_SIZE)
				store_u8(stub_addr + 0, 0xFF)
				store_u8(stub_addr + 1, 0x25)
				store_u8(stub_addr + 2, 0x00)
				store_u8(stub_addr + 3, 0x00)
				store_u8(stub_addr + 4, 0x00)
				store_u8(stub_addr + 5, 0x00)
				store_u64(stub_addr + 6, u64(uintptr(target)) + u64(r.addend) + 4)
				toff = i64(stub_addr) - i64(patch_ptr) - 4
				stub_idx += 1
			}
			store_u32(patch_ptr, u32(toff & 0xFFFFFFFF))

		case .GOTPCREL:
			if got_idx >= MAX_GOTS {
				return false
			}
			slot := gots_base + uintptr(got_idx*GOT_SIZE)
			got_idx += 1
			store_u64(slot, u64(uintptr(target)) + u64(r.addend) + 4)
			toff := i64(slot) - i64(patch_ptr) - 4
			store_u32(patch_ptr, u32(toff & 0xFFFFFFFF))

		case .TLSGD:
			if got_idx >= MAX_GOTS {
				return false
			}
			slot := gots_base + uintptr(got_idx*GOT_SIZE)
			got_idx += 1
			ts := cast(^Tls_Slot)slot
			ts.sym_name = cstr_dup(r.symbol)
			ts.offset = 0
			ts.inited = false
			toff := i64(slot) - i64(patch_ptr) - 4
			store_u32(patch_ptr, u32(toff & 0xFFFFFFFF))

		case .Abs32S:
			val := i64(uintptr(target)) + r.addend
			store_i32(patch_ptr, i32(val))

		case .GOTTPOFF:
			addr := resolve_symbol(r.symbol, nil)
			if addr == nil {
				return false
			}
			if got_idx >= MAX_GOTS {
				return false
			}
			slot := gots_base + uintptr(got_idx*GOT_SIZE)
			got_idx += 1
			offset := i64(uintptr(addr)) - i64(uintptr(tls_base()))
			store_i64(slot, offset)
			toff := i64(slot) - i64(patch_ptr) - 4
			store_u32(patch_ptr, u32(toff & 0xFFFFFFFF))
		}
	}
	return true
}

// Returns the number of procedures patched, or a negative error code.
@(private="file")
process_payload :: proc(data: []u8) -> int {
	r := Reader{data = data, ok = true}

	magic := ru32(&r)
	if !r.ok {
		return -1
	}
	if magic != WATCH_MAGIC {
		if g_verbose {
			w(2, "[hotpatch] invalid magic ")
			print_u64(2, u64(magic), 16, 8)
			w(2, "\n")
		}
		return -2
	}
	_ = ru16(&r) // version
	num_functions := int(ru16(&r))
	if !r.ok || num_functions > MAX_FUNCTIONS {
		return -3
	}

	elf_size := int(ru32(&r))
	if elf_size > 0 {
		_ = rget(&r, elf_size)
	}

	rodata_len := int(ru32(&r))
	rodata: rawptr
	if rodata_len > 0 {
		rodata = alloc_code_page(rodata_len)
		if rodata == nil {
			return -3
		}
		bytes := rget(&r, rodata_len)
		if bytes == nil {
			return -3
		}
		_ = lc_memcpy(rodata, raw_data(bytes), uintptr(rodata_len))
	}

	funcs_mem := cast([^]Parsed_Function)lc_malloc(uintptr(num_functions) * uintptr(size_of(Parsed_Function)))
	if funcs_mem == nil {
		return -5
	}
	defer lc_free(funcs_mem)
	funcs := funcs_mem[:num_functions]

	for fi in 0..<num_functions {
		name_len := int(ru16(&r))
		name := rst(&r, name_len)
		_ = ru8(&r) // is_watched
		if !r.ok {
			return -4
		}

		f := &funcs[fi]
		f.name = name
		f.rodata = rodata

		sz: u64
		f.original = resolve_symbol_local(name, &sz)
		f.original_size = sz

		code_len := ru32(&r)
		code := rget(&r, int(code_len))
		if !r.ok || code == nil {
			return -6
		}
		f.code = code
		f.code_len = code_len

		nrel := int(ru16(&r))
		if !r.ok {
			return -7
		}
		relocs_mem := cast([^]Reloc)lc_malloc(uintptr(nrel) * uintptr(size_of(Reloc)))
		if relocs_mem == nil && nrel > 0 {
			return -7
		}
		f.relocs = relocs_mem[:nrel]
		for ri in 0..<nrel {
			off := ru32(&r)
			typ := Reloc_Type(ru8(&r))
			slen := int(ru16(&r))
			sym := rst(&r, slen)
			add := ri64(&r)
			if !r.ok {
				return -8
			}
			f.relocs[ri] = {off, typ, sym, add}
		}
	}
	defer {
		for fi in 0..<num_functions {
			if len(funcs[fi].relocs) > 0 {
				lc_free(rawptr(raw_data(funcs[fi].relocs)))
			}
		}
	}

	if r.pos != len(data) {
		return -22
	}

	// Allocate + copy code, then apply relocations while same-payload
	// functions are still private (not yet reachable through trampolines).
	for fi in 0..<num_functions {
		f := &funcs[fi]
		total := round_up_page(uintptr(f.code_len)) + uintptr(MAX_STUBS*STUB_SIZE + MAX_GOTS*GOT_SIZE)
		page := alloc_code_page(int(total))
		if page == nil {
			return -10
		}
		_ = lc_memcpy(page, raw_data(f.code), uintptr(f.code_len))
		f.new_code = uintptr(page)
	}

	for fi in 0..<num_functions {
		if !apply_relocations(&funcs[fi], funcs) {
			return -18
		}
	}

	// The code occupies whole pages at the start of each JIT allocation, so it
	// can be made lc_read+execute while the trailing stubs/GOT stay writable.
	for fi in 0..<num_functions {
		f := &funcs[fi]
		if rx := round_up_page(uintptr(f.code_len)); rx > 0 {
			_ = lc_mprotect(rawptr(f.new_code), rx, PROT_READ|PROT_EXEC)
		}
	}

	// Publish the new code so later patches and relocations can find it.
	for fi in 0..<num_functions {
		f := &funcs[fi]
		register_patched_symbol(f.name, rawptr(f.new_code), u64(f.code_len))
		if f.original == nil {
			s: u64
			f.original = resolve_symbol(f.name, &s)
			f.original_size = s
		}
	}

	// Commit trampolines last, in reverse so callees are published first.
	num_patched := 0
	for fi := num_functions - 1; fi >= 0; fi -= 1 {
		f := &funcs[fi]
		if f.original == nil {
			if g_verbose {
				w(1, "[hotpatch] registered new function ")
				w(1, f.name)
				w(1, " at ")
				print_ptr(1, rawptr(f.new_code))
				w(1, " (no trampoline)\n")
			}
			num_patched += 1
			continue
		}
		if f.original_size > 0 && f.original_size < 5 {
			w(2, "[hotpatch] skipped ")
			w(2, f.name)
			w(2, ": ")
			print_i64(2, i64(f.original_size))
			eline(" bytes is too small to hook (need >= 5)")
			continue
		}
		if !write_trampoline(f.original, rawptr(f.new_code), int(f.original_size)) {
			eline("[hotpatch] failed to lc_write trampoline for ", f.name)
			continue
		}
		if g_verbose {
			w(1, "[hotpatch] patched ")
			w(1, f.name)
			w(1, " (")
			print_ptr(1, f.original)
			w(1, " -> ")
			print_ptr(1, rawptr(f.new_code))
			w(1, ", size ")
			print_i64(1, i64(f.original_size))
			w(1, ")\n")
		}
		num_patched += 1
	}

	return num_patched
}

// ---------------------------------------------------------------------------
// Unix lc_socket listener
// ---------------------------------------------------------------------------

@(private="file")
read_connection :: proc(fd: i32) -> int {
	cap := uintptr(65536)
	buf := lc_malloc(cap)
	if buf == nil {
		return -20
	}
	total: uintptr = 0
	tmp: [8192]u8
	for {
		n := lc_read(fd, &tmp[0], uintptr(len(tmp)))
		if n <= 0 {
			if n < 0 && errno() == EINTR {
				continue
			}
			break
		}
		if total + uintptr(n) > cap {
			for total + uintptr(n) > cap {
				cap *= 2
			}
			nb := lc_realloc(buf, cap)
			if nb == nil {
				lc_free(buf)
				return -21
			}
			buf = nb
		}
		_ = lc_memcpy(rawptr(uintptr(buf) + total), &tmp[0], uintptr(n))
		total += uintptr(n)
	}
	if total == 0 {
		lc_free(buf)
		return 0
	}
	data := (cast([^]u8)buf)[:total]
	res := process_payload(data)
	lc_free(buf)
	return res
}

@(private="file")
listener_thread :: proc() {
	for g_running {
		client := lc_accept(g_listen_fd, nil, nil)
		if client < 0 {
			if errno() == EINTR {
				continue
			}
			if !g_running {
				return
			}
			continue
		}

		patched := read_connection(client)
		_ = lc_close(client)
		if patched < 0 {
			w(2, "[hotpatch] patch failed (error ")
			print_i64(2, i64(patched))
			w(2, ")\n")
		} else if patched > 0 {
			w(1, "[hotpatch] hotpatched ")
			print_i64(1, i64(patched))
			w(1, " procedure(s)\n")
		}
	}
}

@(private="file")
listener_thread_c :: proc "c" (arg: rawptr) -> rawptr {
	listener_thread()
	return nil
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

// Starts the hotpatch listener. Reads the lc_socket path from
// `ODIN_HOTPATCH_SOCK`; returns false if unset or on failure. Idempotent.
start :: proc(verbose := false) -> bool {
	if g_initialized {
		return true
	}
	g_verbose = verbose

	c := lc_getenv("ODIN_HOTPATCH_SOCK")
	if c == nil {
		return false
	}
	n := len(c)
	if n == 0 || n >= len(g_sock_path) {
		return false
	}
	cp := cast([^]u8)c
	for i in 0..<n {
		g_sock_path[i] = cp[i]
	}
	g_sock_path[n] = 0

	_ = lc_unlink(cstring(&g_sock_path[0]))

	fd := lc_socket(AF_UNIX, SOCK_STREAM, 0)
	if fd < 0 {
		return false
	}

	addr: Sockaddr_Un
	addr.sun_family = u16(AF_UNIX)
	for i in 0..<n {
		addr.sun_path[i] = cp[i]
	}

	if lc_bind(fd, cast(^Sockaddr)&addr, u32(size_of(addr))) != 0 {
		_ = lc_close(fd)
		return false
	}
	if lc_listen(fd, 8) != 0 {
		_ = lc_close(fd)
		return false
	}

	g_listen_fd = fd
	g_running = true

	if !install_signal_handler() {
		eline("[hotpatch] warning: could not install SIGTRAP handler")
	}

	tid: uintptr
	_ = lc_pthread_create(&tid, nil, listener_thread_c, nil)

	if g_verbose {
		w(1, "[hotpatch] listening on ")
		w(1, string(cast(cstring)&g_sock_path[0]))
		w(1, "\n")
	}
	g_initialized = true
	return true
}

// Processes one pending patch connection (for programs that prefer to poll
// instead of using the background listener; do not mix with `start`).
poll :: proc() -> int {
	if g_listen_fd < 0 {
		return 0
	}
	client := lc_accept(g_listen_fd, nil, nil)
	if client < 0 {
		return 0
	}
	patched := read_connection(client)
	_ = lc_close(client)
	return patched
}

shutdown :: proc() {
	if !g_initialized {
		return
	}
	g_running = false
	if g_listen_fd >= 0 {
		_ = lc_close(g_listen_fd)
		g_listen_fd = -1
	}
	_ = lc_unlink(cstring(&g_sock_path[0]))
	uninstall_signal_handler()
	g_initialized = false
}

@(private="file")
hotpatch_autostart_body :: proc() {
	c := lc_getenv("ODIN_HOTPATCH_SOCK")
	if c != nil && (cast([^]u8)c)[0] != 0 {
		start(false)
	}
}

when ODIN_BEDROCK {
	// `-bedrock` disables `@(init)`/`@(fini)`, so register a constructor
	// pointer in `.init_array`, which the C runtime runs before `main`.
	@(private="file")
	_hotpatch_ctor :: proc "c" (argc: i32, argv: rawptr, envp: rawptr) {
		hotpatch_autostart_body()
	}

	@(export, link_section=".init_array")
	_hotpatch_ctor_entry : proc "c" (i32, rawptr, rawptr) = _hotpatch_ctor
} else {
	@(init, private)
	_hotpatch_autostart :: proc() {
		hotpatch_autostart_body()
	}
}
