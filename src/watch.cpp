// watch.cpp - implements the `odin watch` command.
//
// `odin watch` behaves like `odin run`, but additionally:
//   1. spawns a recursive source watcher for .odin files,
//   2. recompiles the project to relocatable object files whenever a source
//      file changes,
//   3. extracts the code, read-only data and relocations of every procedure
//      annotated with @(watch),
//   4. ships that payload over a unix socket to the running process, which
//      hotpatches the procedures with the core:hotpatch runtime.
//
// The relocation machinery mirrors the dpatch project
// (/home/ryuukk/dev/kdom/src/dpatch) which does the same for D.

#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef GB_SYSTEM_WINDOWS
#include <spawn.h>
#include <sys/inotify.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <errno.h>
#include <limits.h>
#endif

// --------------------------------------------------------------------------
// Shared wire format (must match core:hotpatch)
// --------------------------------------------------------------------------
enum WatchRelocType : u8 {
	WatchReloc_64       = 1, // R_X86_64_64
	WatchReloc_PC32     = 2, // R_X86_64_PC32 / PLT32
	WatchReloc_GOTPCREL = 3, // R_X86_64_GOTPCREL(x)
	WatchReloc_TLSGD    = 4, // R_X86_64_TLSGD
	WatchReloc_32S      = 5, // R_X86_64_32S
	WatchReloc_GOTTPOFF = 6, // R_X86_64_GOTTPOFF
};

gb_global Array<String> g_watch_args = {};
gb_global Array<String> g_watch_run_args = {};

#if defined(GB_SYSTEM_WINDOWS)
gb_internal void watch_capture_build_args(Array<String> args, Array<String> run_args) {
	gb_printf_err("`odin watch` is only supported on Unix-like systems.\n");
}
gb_internal void watch_write_manifest(Checker *checker) {}
gb_internal int watch_run(String const &exe_name) {
	gb_printf_err("`odin watch` is only supported on Unix-like systems.\n");
	return 1;
}
#else

gb_global bool             g_watch_captured = false;
gb_global String           g_watch_socket_path = {};
gb_global String           g_watch_tmp_dir = {};
gb_global char             g_watch_socket_buf[PATH_MAX];
gb_global char             g_watch_tmp_buf[PATH_MAX];
gb_global volatile sig_atomic_t g_watch_stop = 0;
gb_global pid_t            g_watch_child_pid = -1;

// --------------------------------------------------------------------------
// Growth buffer
// --------------------------------------------------------------------------
typedef struct WatchBuffer {
	u8 *data;
	usize len;
	usize cap;
} WatchBuffer;

gb_internal void watch_buffer_reserve(WatchBuffer *b, usize extra) {
	if (b->len + extra <= b->cap) return;
	usize new_cap = b->cap == 0 ? 65536 : b->cap;
	while (new_cap < b->len + extra) new_cap *= 2;
	u8 *p = cast(u8 *)realloc(b->data, new_cap);
	if (p == nullptr) {
		gb_printf_err("odin watch: out of memory\n");
		exit(1);
	}
	b->data = p;
	b->cap = new_cap;
}

gb_internal void watch_buffer_write(WatchBuffer *b, void const *src, usize n) {
	watch_buffer_reserve(b, n);
	memcpy(b->data + b->len, src, n);
	b->len += n;
}

gb_internal void watch_buffer_u8(WatchBuffer *b, u8 v)  { watch_buffer_write(b, &v, 1); }
gb_internal void watch_buffer_u16(WatchBuffer *b, u16 v) { watch_buffer_write(b, &v, 2); }
gb_internal void watch_buffer_u32(WatchBuffer *b, u32 v) { watch_buffer_write(b, &v, 4); }
gb_internal void watch_buffer_i64(WatchBuffer *b, i64 v) { watch_buffer_write(b, &v, 8); }

// --------------------------------------------------------------------------
// Args / manifest
// --------------------------------------------------------------------------
gb_internal void watch_capture_build_args(Array<String> args, Array<String> run_args) {
	if (g_watch_captured) return;
	g_watch_captured = true;
	g_watch_args = array_make<String>(heap_allocator(), 0, args.count + 8);
	for_array(i, args) {
		array_add(&g_watch_args, copy_string(permanent_allocator(), args[i]));
	}
	g_watch_run_args = array_make<String>(heap_allocator(), 0, run_args.count + 8);
	for_array(i, run_args) {
		array_add(&g_watch_run_args, copy_string(permanent_allocator(), run_args[i]));
	}
}

// Writes the linker symbol name of every @(watch) procedure, plus every
// procedure transitively reachable from them within the same package, to the
// file pointed to by $ODIN_HOTPATCH_MANIFEST. Called after code generation.
gb_internal void watch_write_manifest(Checker *checker) {
	char const *path = getenv("ODIN_HOTPATCH_MANIFEST");
	if (path == nullptr || path[0] == '\0') return;
	if (checker == nullptr) return;

	FILE *f = fopen(path, "wb");
	if (f == nullptr) return;
	defer (fclose(f));

	// Packages that contain at least one @(watch) root. Only procedures in
	// these packages are emitted (so editing a callee in the same package also
	// takes effect), mirroring the reference implementation.
	PtrSet<AstPackage *> allowed = {}; ptr_set_init(&allowed, 0);
	defer (ptr_set_destroy(&allowed));

	PtrSet<Entity *> seen = {}; ptr_set_init(&seen, 0);
	defer (ptr_set_destroy(&seen));

	Array<Entity *> stack = array_make<Entity *>(heap_allocator(), 0, 64);
	defer (array_free(&stack));

	for_array(i, checker->info.entities) {
		Entity *e = checker->info.entities[i];
		if (e->kind != Entity_Procedure) continue;
		if (!e->Procedure.is_watched) continue;
		if (e->Procedure.is_foreign) continue;
		if (e->pkg != nullptr) ptr_set_add(&allowed, e->pkg);
		if (ptr_set_exists(&seen, e)) continue;
		ptr_set_add(&seen, e);
		array_add(&stack, e);
	}

	// Walk the call graph through declaration dependencies. Foreign procedures
	// cannot be patched, so they are not enqueued (and never emitted).
	while (stack.count > 0) {
		Entity *e = array_pop(&stack);
		DeclInfo *decl = decl_info_of_entity(e);
		if (decl == nullptr) continue;
		FOR_PTR_SET(dep, decl->deps) {
			if (dep == nullptr || dep->kind != Entity_Procedure) continue;
			if (dep->Procedure.is_foreign) continue;
			if (ptr_set_exists(&seen, dep)) continue;
			ptr_set_add(&seen, dep);
			array_add(&stack, dep);
		}
	}

	FOR_PTR_SET(e, seen) {
		if (e->kind != Entity_Procedure) continue;
		if (e->pkg == nullptr || !ptr_set_exists(&allowed, e->pkg)) continue;

		String name = e->token.string;
		String *cached = e->ir_mangled_name.load();
		if (cached != nullptr) name = *cached;

		fwrite(name.text, 1, name.len, f);
		fputc('\n', f);
	}
}

// --------------------------------------------------------------------------
// File helpers
// --------------------------------------------------------------------------
gb_internal u8 *watch_read_file(char const *path, usize *out_size) {
	int fd = open(path, O_RDONLY);
	if (fd < 0) return nullptr;
	struct stat st;
	if (fstat(fd, &st) != 0 || st.st_size <= 0) { close(fd); return nullptr; }
	u8 *buf = cast(u8 *)malloc((usize)st.st_size);
	if (buf == nullptr) { close(fd); return nullptr; }
	usize total = 0;
	while (total < (usize)st.st_size) {
		ssize_t n = read(fd, buf + total, (usize)st.st_size - total);
		if (n <= 0) break;
		total += (usize)n;
	}
	close(fd);
	if (total != (usize)st.st_size) { free(buf); return nullptr; }
	*out_size = total;
	return buf;
}

gb_internal bool watch_path_is_dir(char const *path) {
	struct stat st;
	if (stat(path, &st) != 0) return false;
	return S_ISDIR(st.st_mode);
}

// --------------------------------------------------------------------------
// ELF64 definitions
// --------------------------------------------------------------------------
typedef struct WElf64_Ehdr {
	u8     e_ident[16];
	u16    e_type;
	u16    e_machine;
	u32    e_version;
	u64    e_entry;
	u64    e_phoff;
	u64    e_shoff;
	u32    e_flags;
	u16    e_ehsize;
	u16    e_phentsize;
	u16    e_phnum;
	u16    e_shentsize;
	u16    e_shnum;
	u16    e_shstrndx;
} WElf64_Ehdr;

typedef struct WElf64_Shdr {
	u32 sh_name;
	u32 sh_type;
	u64 sh_flags;
	u64 sh_addr;
	u64 sh_offset;
	u64 sh_size;
	u32 sh_link;
	u32 sh_info;
	u64 sh_addralign;
	u64 sh_entsize;
} WElf64_Shdr;

typedef struct WElf64_Sym {
	u32 st_name;
	u8  st_info;
	u8  st_other;
	u16 st_shndx;
	u64 st_value;
	u64 st_size;
} WElf64_Sym;

typedef struct WElf64_Rela {
	u64 r_offset;
	u64 r_info;
	i64 r_addend;
} WElf64_Rela;

enum {
	W_SHT_PROGBITS = 1,
	W_SHT_SYMTAB   = 2,
	W_SHT_STRTAB   = 3,
	W_SHT_RELA     = 4,
	W_SHT_NOBITS   = 8,
	W_SHF_ALLOC     = 0x2,
	W_SHF_EXECINSTR = 0x4,
	W_STT_SECTION   = 3,
	W_STT_FUNC      = 2,
	W_STB_LOCAL     = 0,
};

#define W_ELF64_R_SYM(info)  ((u32)((info) >> 32))
#define W_ELF64_R_TYPE(info) ((u32)((info) & 0xffffffffu))
#define W_ELF64_ST_TYPE(i)   ((i) & 0xf)
#define W_ELF64_ST_BIND(i)   ((i) >> 4)

// --------------------------------------------------------------------------
// Extracted records
// --------------------------------------------------------------------------
#define WATCH_SYM_MAX 1024

typedef struct WatchRelocRecord {
	u32 offset;
	u8  type;
	char symbol[WATCH_SYM_MAX];
	i64 addend;
} WatchRelocRecord;

typedef struct WatchFuncRecord {
	char  name[WATCH_SYM_MAX];
	u8   *code;
	u32   code_len;
	WatchRelocRecord *relocs;
	u32   num_relocs;
} WatchFuncRecord;

gb_global Array<WatchFuncRecord> g_watch_funcs = {};
gb_global WatchBuffer g_watch_rodata = {};
gb_global isize g_watch_payload_count = 0;

gb_internal bool watch_symbol_is_watched(Array<String> const &watched, String name) {
	for_array(i, watched) {
		if (watched[i] == name) return true;
	}
	return false;
}

gb_internal u8 watch_map_reloc_type(u32 elf_type, bool *ok) {
	*ok = true;
	switch (elf_type) {
	case 1:  return WatchReloc_64;       // R_X86_64_64
	case 2:  return WatchReloc_PC32;     // R_X86_64_PC32
	case 4:  return WatchReloc_PC32;     // R_X86_64_PLT32
	case 9:  return WatchReloc_GOTPCREL; // R_X86_64_GOTPCREL
	case 41: return WatchReloc_GOTPCREL; // R_X86_64_GOTPCRELX
	case 42: return WatchReloc_GOTPCREL; // R_X86_64_REX_GOTPCRELX
	case 11: return WatchReloc_32S;      // R_X86_64_32S
	case 19: return WatchReloc_TLSGD;    // R_X86_64_TLSGD
	case 22: return WatchReloc_GOTTPOFF; // R_X86_64_GOTTPOFF
	case 0:  *ok = false; return 0;      // R_X86_64_NONE
	default: *ok = false; return 0;
	}
}

// Parse a single relocatable object file and append any watched procedure to
// g_watch_funcs, copying its rodata into g_watch_rodata.
gb_internal void watch_extract_object(char const *path, Array<String> const &watched) {
	usize size = 0;
	u8 *buf = watch_read_file(path, &size);
	if (buf == nullptr) return;
	defer (free(buf));

	if (size < sizeof(WElf64_Ehdr)) return;
	WElf64_Ehdr *ehdr = cast(WElf64_Ehdr *)buf;
	if (ehdr->e_ident[0] != 0x7f || ehdr->e_ident[1] != 'E' || ehdr->e_ident[2] != 'L' || ehdr->e_ident[3] != 'F') return;
	if (ehdr->e_shoff == 0 || ehdr->e_shnum == 0) return;

	WElf64_Shdr *shdrs = cast(WElf64_Shdr *)(buf + ehdr->e_shoff);
	WElf64_Shdr *shstr = &shdrs[ehdr->e_shstrndx];
	char *shstrtab = cast(char *)(buf + shstr->sh_offset);

	WElf64_Shdr *symtab = nullptr;
	WElf64_Shdr *strtab = nullptr;
	for (int i = 0; i < ehdr->e_shnum; i++) {
		if (shdrs[i].sh_type == W_SHT_SYMTAB) {
			symtab = &shdrs[i];
			if (symtab->sh_link < ehdr->e_shnum) strtab = &shdrs[symtab->sh_link];
			break;
		}
	}
	if (symtab == nullptr || strtab == nullptr) return;

	WElf64_Sym *syms = cast(WElf64_Sym *)(buf + symtab->sh_offset);
	usize num_syms = (usize)(symtab->sh_size / sizeof(WElf64_Sym));
	char *strtab_data = cast(char *)(buf + strtab->sh_offset);

	// Map each allocatable, non-executable section to its offset in g_watch_rodata.
	isize *sec_rodata_off = cast(isize *)malloc(sizeof(isize) * ehdr->e_shnum);
	for (int i = 0; i < ehdr->e_shnum; i++) sec_rodata_off[i] = -1;
	defer (free(sec_rodata_off));

	for (int i = 0; i < ehdr->e_shnum; i++) {
		WElf64_Shdr *sh = &shdrs[i];
		if ((sh->sh_flags & W_SHF_ALLOC) == 0) continue;
		if (sh->sh_flags & W_SHF_EXECINSTR) continue;
		if (sh->sh_type == W_SHT_NOBITS) continue;
		if (sh->sh_size == 0) continue;

		char const *name = &shstrtab[sh->sh_name];
		if (strncmp(name, ".eh_frame", 9) == 0 || strncmp(name, ".note", 5) == 0) continue;

		sec_rodata_off[i] = (isize)g_watch_rodata.len;
		watch_buffer_write(&g_watch_rodata, buf + sh->sh_offset, (usize)sh->sh_size);
	}

	// Process each watched procedure located in this object.
	for (usize si = 0; si < num_syms; si++) {
		WElf64_Sym *sym = &syms[si];
		if (W_ELF64_ST_TYPE(sym->st_info) != W_STT_FUNC) continue;
		if (sym->st_shndx == 0 || sym->st_shndx >= ehdr->e_shnum) continue;
		if (sym->st_size == 0) continue;
		if (sym->st_name == 0) continue;

		char const *sym_name = &strtab_data[sym->st_name];
		String sname = make_string_c(sym_name);
		if (!watch_symbol_is_watched(watched, sname)) continue;

		if (sym->st_size < 5) {
			gb_printf_err("[watch] Skipping '%s': %llu bytes is too small to hotpatch (need >= 5).\n",
			              sym_name, cast(unsigned long long)sym->st_size);
			continue;
		}

		WElf64_Shdr *code_sec = &shdrs[sym->st_shndx];
		if ((code_sec->sh_flags & W_SHF_EXECINSTR) == 0) continue;

		WatchFuncRecord rec = {};
		strncpy(rec.name, sym_name, WATCH_SYM_MAX - 1);
		rec.code_len = (u32)sym->st_size;
		rec.code = cast(u8 *)malloc(rec.code_len);
		if (rec.code == nullptr) continue;
		memcpy(rec.code, buf + code_sec->sh_offset + sym->st_value, rec.code_len);

		// Find the relocation section that targets the function's code section.
		WElf64_Shdr *rela = nullptr;
		for (int i = 0; i < ehdr->e_shnum; i++) {
			if (shdrs[i].sh_type == W_SHT_RELA && shdrs[i].sh_info == sym->st_shndx) {
				rela = &shdrs[i];
				break;
			}
		}

		usize max_relocs = rela ? (usize)(rela->sh_size / sizeof(WElf64_Rela)) : 0;
		WatchRelocRecord *relocs = nullptr;
		if (max_relocs > 0) {
			relocs = cast(WatchRelocRecord *)calloc(max_relocs, sizeof(WatchRelocRecord));
		}

		u32 num_relocs = 0;
		if (rela != nullptr) {
			WElf64_Rela *rela_data = cast(WElf64_Rela *)(buf + rela->sh_offset);
			for (usize ri = 0; ri < max_relocs; ri++) {
				WElf64_Rela *r = &rela_data[ri];
				if (r->r_offset < sym->st_value) continue;
				if (r->r_offset >= sym->st_value + sym->st_size) continue;

				u32 elf_type = W_ELF64_R_TYPE(r->r_info);
				bool ok = false;
				u8 type = watch_map_reloc_type(elf_type, &ok);
				if (!ok) {
					if (build_context.show_debug_messages) {
						gb_printf_err("[watch] Unsupported relocation type %u in %s\n", elf_type, sym_name);
					}
					continue;
				}

				u32 sym_index = W_ELF64_R_SYM(r->r_info);
				if (sym_index >= num_syms) continue;
				WElf64_Sym *rsym = &syms[sym_index];

				WatchRelocRecord *out = &relocs[num_relocs];
				out->offset = (u32)(r->r_offset - sym->st_value);
				out->type = type;
				out->addend = r->r_addend;

				bool is_section = rsym->st_name == 0 && W_ELF64_ST_TYPE(rsym->st_info) == W_STT_SECTION;
				bool is_local   = W_ELF64_ST_BIND(rsym->st_info) == W_STB_LOCAL;

				if (is_section) {
					// Relocation against a section symbol.
					if (rsym->st_shndx < ehdr->e_shnum && sec_rodata_off[rsym->st_shndx] >= 0) {
						strncpy(out->symbol, ".rodata", WATCH_SYM_MAX - 1);
						out->addend += (i64)sec_rodata_off[rsym->st_shndx];
					} else if (rsym->st_shndx == sym->st_shndx) {
						// Points into our own code; rebase onto the new function.
						strncpy(out->symbol, rec.name, WATCH_SYM_MAX - 1);
						out->addend += (i64)(rsym->st_value - sym->st_value);
					} else {
						continue;
					}
				} else if (is_local) {
					if (rsym->st_shndx < ehdr->e_shnum && sec_rodata_off[rsym->st_shndx] >= 0) {
						strncpy(out->symbol, ".rodata", WATCH_SYM_MAX - 1);
						out->addend += (i64)sec_rodata_off[rsym->st_shndx] + (i64)rsym->st_value;
					} else if (rsym->st_shndx == sym->st_shndx) {
						strncpy(out->symbol, rec.name, WATCH_SYM_MAX - 1);
						out->addend += (i64)(rsym->st_value - sym->st_value);
					} else {
						continue;
					}
				} else {
					strncpy(out->symbol, &strtab_data[rsym->st_name], WATCH_SYM_MAX - 1);
				}

				num_relocs++;
			}
		}

		rec.relocs = relocs;
		rec.num_relocs = num_relocs;
		array_add(&g_watch_funcs, rec);
	}
}

// --------------------------------------------------------------------------
// Payload packing
// --------------------------------------------------------------------------
gb_internal void watch_free_funcs(Array<WatchFuncRecord> *funcs) {
	for_array(fi, *funcs) {
		free((*funcs)[fi].code);
		free((*funcs)[fi].relocs);
	}
	array_free(funcs);
}

gb_internal bool watch_build_payload(Array<String> const &watched, WatchBuffer *out) {
	g_watch_funcs = array_make<WatchFuncRecord>(heap_allocator(), 0, 16);
	g_watch_rodata = {};
	defer (free(g_watch_rodata.data));
	defer (watch_free_funcs(&g_watch_funcs));

	DIR *d = opendir(g_watch_tmp_buf);
	if (d == nullptr) return false;
	struct dirent *ent;
	while ((ent = readdir(d)) != nullptr) {
		isize n = (isize)strlen(ent->d_name);
		if (n < 3) continue;
		if (strcmp(ent->d_name + n - 2, ".o") != 0) continue;
		char path[PATH_MAX];
		snprintf(path, sizeof(path), "%s/%s", g_watch_tmp_buf, ent->d_name);
		watch_extract_object(path, watched);
	}
	closedir(d);

	g_watch_payload_count = g_watch_funcs.count;

	if (g_watch_funcs.count == 0) {
		gb_printf_err("[watch] No watched procedures found in recompiled objects.\n");
		return false;
	}

	// Header
	u32 magic = 0x44505443; // "DPTC"
	watch_buffer_u32(out, magic);
	watch_buffer_u16(out, 1); // version
	watch_buffer_u16(out, (u16)g_watch_funcs.count);
	watch_buffer_u32(out, 0); // debug ELF size (unused)

	// Global rodata
	watch_buffer_u32(out, (u32)g_watch_rodata.len);
	if (g_watch_rodata.len > 0) {
		watch_buffer_write(out, g_watch_rodata.data, g_watch_rodata.len);
	}

	for_array(fi, g_watch_funcs) {
		WatchFuncRecord *f = &g_watch_funcs[fi];
		usize name_len = strlen(f->name);
		watch_buffer_u16(out, (u16)name_len);
		watch_buffer_write(out, f->name, name_len);
		watch_buffer_u8(out, 1); // is_watched
		watch_buffer_u32(out, f->code_len);
		watch_buffer_write(out, f->code, f->code_len);
		watch_buffer_u16(out, (u16)f->num_relocs);
		for (u32 ri = 0; ri < f->num_relocs; ri++) {
			WatchRelocRecord *r = &f->relocs[ri];
			watch_buffer_u32(out, r->offset);
			watch_buffer_u8(out, r->type);
			usize sl = strlen(r->symbol);
			watch_buffer_u16(out, (u16)sl);
			watch_buffer_write(out, r->symbol, sl);
			watch_buffer_i64(out, r->addend);
		}
	}
	return true;
}

// --------------------------------------------------------------------------
// Socket transport
// --------------------------------------------------------------------------
gb_internal bool watch_send_payload(u8 const *data, usize len) {
	for (int attempt = 0; attempt < 40; attempt++) {
		int fd = socket(AF_UNIX, SOCK_STREAM, 0);
		if (fd < 0) return false;

		struct sockaddr_un addr;
		memset(&addr, 0, sizeof(addr));
		addr.sun_family = AF_UNIX;
		strncpy(addr.sun_path, g_watch_socket_buf, sizeof(addr.sun_path) - 1);

		if (connect(fd, cast(struct sockaddr *)&addr, sizeof(addr)) == 0) {
			usize off = 0;
			bool ok = true;
			while (off < len) {
				ssize_t n = write(fd, data + off, len - off);
				if (n <= 0) { ok = false; break; }
				off += (usize)n;
			}
			close(fd);
			return ok;
		}
		close(fd);
		usleep(50000);
	}
	gb_printf_err("[watch] Failed to connect to hotpatch socket '%s'.\n", g_watch_socket_buf);
	gb_printf_err("[watch] The program did not open its hotpatch socket. Is it still running?\n");
	return false;
}

// --------------------------------------------------------------------------
// Subprocess helpers
// --------------------------------------------------------------------------
gb_internal int watch_spawn_and_wait(Array<char const *> argv) {
	pid_t pid = 0;
	array_add(&argv, nullptr);
	int rc = posix_spawn(&pid, argv[0], nullptr, nullptr, cast(char *const *)argv.data, environ);
	if (rc != 0) {
		gb_printf_err("[watch] Failed to spawn '%s': %s\n", argv[0], strerror(rc));
		return -1;
	}
	int status = 0;
	while (waitpid(pid, &status, 0) < 0) {
		if (errno != EINTR) return -1;
	}
	if (WIFEXITED(status)) return WEXITSTATUS(status);
	return -1;
}

// --------------------------------------------------------------------------
// Recursive inotify watching
// --------------------------------------------------------------------------
typedef struct WatchDirEntry {
	int  wd;
	char path[PATH_MAX];
} WatchDirEntry;

gb_global Array<WatchDirEntry> g_watch_dirs = {};
gb_global int g_watch_inotify_fd = -1;

gb_internal void watch_sigint_handler(int sig) {
	(void)sig;
	g_watch_stop = 1;
	if (g_watch_child_pid > 0) {
		kill(g_watch_child_pid, SIGTERM);
	}
}

gb_internal void watch_add_dir_recursive(char const *dir) {
	int wd = inotify_add_watch(g_watch_inotify_fd, dir,
		IN_CLOSE_WRITE | IN_MOVED_TO | IN_CREATE | IN_DELETE | IN_MOVED_FROM | IN_MODIFY);
	if (wd >= 0) {
		WatchDirEntry e = {};
		e.wd = wd;
		strncpy(e.path, dir, PATH_MAX - 1);
		array_add(&g_watch_dirs, e);
	}

	DIR *dp = opendir(dir);
	if (dp == nullptr) return;
	struct dirent *ent;
	while ((ent = readdir(dp)) != nullptr) {
		if (ent->d_name[0] == '.') continue; // skip hidden and . / ..
		char sub[PATH_MAX];
		snprintf(sub, sizeof(sub), "%s/%s", dir, ent->d_name);
		if (!watch_path_is_dir(sub)) continue;
		watch_add_dir_recursive(sub);
	}
	closedir(dp);
}

// --------------------------------------------------------------------------
// Rebuild + patch
// --------------------------------------------------------------------------
gb_internal bool watch_rebuild_and_patch(char const *compiler_path, char const *manifest_path) {
	// Compile the project to relocatable object files.
	setenv("ODIN_HOTPATCH_MANIFEST", manifest_path, 1);

	Array<char const *> argv = array_make<char const *>(heap_allocator(), 0, g_watch_args.count + 8);
	array_add(&argv, compiler_path);
	array_add(&argv, "build");
	for (isize i = 2; i < g_watch_args.count; i++) {
		String a = g_watch_args[i];
		if (string_starts_with(a, str_lit("-out:"))) continue;
		if (string_starts_with(a, str_lit("-build-mode:"))) continue;
		if (a == "-keep-executable") continue;
		array_add(&argv, alloc_cstring(permanent_allocator(), a));
	}
	array_add(&argv, "-build-mode:obj");
	char out_arg[PATH_MAX + 16];
	snprintf(out_arg, sizeof(out_arg), "-out:%s/patch", g_watch_tmp_buf);
	array_add(&argv, out_arg);

	int rc = watch_spawn_and_wait(argv);
	unsetenv("ODIN_HOTPATCH_MANIFEST");

	array_free(&argv);
	if (rc != 0) {
		gb_printf_err("[watch] Recompile failed (exit %d); waiting for next change...\n", rc);
		return false;
	}

	// Read the watched-symbol manifest.
	Array<String> watched = array_make<String>(heap_allocator(), 0, 16);
	defer (array_free(&watched));

	usize msize = 0;
	u8 *mbytes = watch_read_file(manifest_path, &msize);
	if (mbytes != nullptr) {
		defer (free(mbytes));
		usize start = 0;
		for (usize i = 0; i <= msize; i++) {
			if (i == msize || mbytes[i] == '\n') {
				if (i > start) {
					String s = make_string(mbytes + start, (isize)(i - start));
					array_add(&watched, copy_string(permanent_allocator(), s));
				}
				start = i + 1;
			}
		}
	}

	if (watched.count == 0) {
		gb_printf_err("[watch] No procedures annotated with @(watch); nothing to patch.\n");
		return false;
	}

	WatchBuffer payload = {};
	defer (free(payload.data));
	if (!watch_build_payload(watched, &payload)) return false;

	if (watch_send_payload(payload.data, payload.len)) {
		gb_printf("[watch] Hotpatched %td procedure(s).\n", g_watch_payload_count);
		return true;
	}
	return false;
}

// --------------------------------------------------------------------------
// Entry point
// --------------------------------------------------------------------------
gb_internal int watch_run(String const &exe_name) {
	if (g_watch_args.count == 0) {
		gb_printf_err("odin watch: missing build arguments\n");
		return 1;
	}

	// Compute the source directory to watch.
	char src_dir[PATH_MAX];
	{
		String pkg = g_watch_args[2];
		char pkg_buf[PATH_MAX];
		isize n = gb_min(pkg.len, (isize)(PATH_MAX - 1));
		memcpy(pkg_buf, pkg.text, n);
		pkg_buf[n] = '\0';

		if (string_ends_with(pkg, str_lit(".odin"))) {
			char *slash = strrchr(pkg_buf, '/');
			if (slash != nullptr) {
				*slash = '\0';
				snprintf(src_dir, sizeof(src_dir), "%s", pkg_buf);
			} else {
				snprintf(src_dir, sizeof(src_dir), ".");
			}
		} else {
			snprintf(src_dir, sizeof(src_dir), "%s", pkg_buf);
		}
	}
	if (!watch_path_is_dir(src_dir)) {
		snprintf(src_dir, sizeof(src_dir), ".");
	}

	// Temporary build directory + socket path.
	snprintf(g_watch_tmp_buf, sizeof(g_watch_tmp_buf), "/tmp/odin-watch-%d", (int)getpid());
	mkdir(g_watch_tmp_buf, 0700);
	g_watch_tmp_dir = make_string_c(g_watch_tmp_buf);

	snprintf(g_watch_socket_buf, sizeof(g_watch_socket_buf), "/tmp/odin-hotpatch-%d.sock", (int)getpid());
	g_watch_socket_path = make_string_c(g_watch_socket_buf);
	unlink(g_watch_socket_buf);
	setenv("ODIN_HOTPATCH_SOCK", g_watch_socket_buf, 1);

	char manifest_path[PATH_MAX];
	snprintf(manifest_path, sizeof(manifest_path), "%s/manifest", g_watch_tmp_buf);

	// Resolve our own executable so we can re-invoke the compiler.
	char compiler_path[PATH_MAX];
	ssize_t clen = readlink("/proc/self/exe", compiler_path, sizeof(compiler_path) - 1);
	if (clen <= 0) {
		gb_printf_err("odin watch: unable to resolve compiler executable path\n");
		return 1;
	}
	compiler_path[clen] = '\0';

	// Spawn the freshly built program.
	{
		char const *exe_c = alloc_cstring(heap_allocator(), exe_name);
		Array<char const *> argv = array_make<char const *>(heap_allocator(), 0, g_watch_run_args.count + 2);
		array_add(&argv, exe_c);
		for_array(i, g_watch_run_args) {
			array_add(&argv, alloc_cstring(heap_allocator(), g_watch_run_args[i]));
		}
		array_add(&argv, nullptr);

		pid_t pid = 0;
		int rc = posix_spawn(&pid, exe_c, nullptr, nullptr, cast(char *const *)argv.data, environ);
		array_free(&argv);
		if (rc != 0) {
			gb_printf_err("odin watch: failed to run '%s': %s\n", exe_c, strerror(rc));
			return 1;
		}
		g_watch_child_pid = pid;
		gb_printf("[watch] Running %.*s (pid %d)\n", LIT(exe_name), (int)pid);
		gb_printf("[watch] Hotpatch socket: %s\n", g_watch_socket_buf);
		gb_printf("[watch] Watching '%.*s' for .odin changes...\n", (int)strlen(src_dir), src_dir);
	}

	// Install SIGINT handler so Ctrl-C tears down the child too.
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = watch_sigint_handler;
	sigaction(SIGINT, &sa, nullptr);
	sigaction(SIGTERM, &sa, nullptr);

	// Set up the recursive watcher.
	g_watch_inotify_fd = inotify_init1(IN_NONBLOCK);
	if (g_watch_inotify_fd < 0) {
		gb_printf_err("odin watch: inotify_init1 failed: %s\n", strerror(errno));
		kill(g_watch_child_pid, SIGTERM);
		return 1;
	}
	g_watch_dirs = array_make<WatchDirEntry>(heap_allocator(), 0, 64);
	watch_add_dir_recursive(src_dir);

	char evbuf[64 * 1024] __attribute__((aligned(8)));

	int result = 0;
	bool pending = false;
	u64 pending_since = 0;
	auto watch_now_ms = []() -> u64 {
		struct timespec ts;
		clock_gettime(CLOCK_MONOTONIC, &ts);
		return (u64)ts.tv_sec * 1000u + (u64)ts.tv_nsec / 1000000u;
	};

	while (!g_watch_stop) {
		int status = 0;
		pid_t wp = waitpid(g_watch_child_pid, &status, WNOHANG);
		if (wp == g_watch_child_pid) {
			if (WIFEXITED(status)) result = WEXITSTATUS(status);
			else result = 128;
			break;
		}

		struct pollfd pfd;
		pfd.fd = g_watch_inotify_fd;
		pfd.events = POLLIN;
		int pr = poll(&pfd, 1, pending ? 120 : 250);

		bool got_event = false;
		if (pr > 0 && (pfd.revents & POLLIN)) {
			ssize_t n = read(g_watch_inotify_fd, evbuf, sizeof(evbuf));
			if (n > 0) {
				ssize_t off = 0;
				while (off < n) {
					struct inotify_event *ev = cast(struct inotify_event *)(evbuf + off);
					if (ev->len > 0 && ev->name[0] != '.') {
						isize nl = (isize)strlen(ev->name);
						if (nl >= 5 && strcmp(ev->name + nl - 5, ".odin") == 0) {
							got_event = true;
						}
					}
					if ((ev->mask & IN_ISDIR) && (ev->mask & IN_CREATE)) {
						// New directory: start watching it (path lookup by wd).
						for_array(di, g_watch_dirs) {
							if (g_watch_dirs[di].wd == ev->wd && ev->name[0] != '.') {
								char sub[PATH_MAX];
								snprintf(sub, sizeof(sub), "%s/%s", g_watch_dirs[di].path, ev->name);
								watch_add_dir_recursive(sub);
								break;
							}
						}
					}
					off += sizeof(struct inotify_event) + ev->len;
				}
			}
		}

		if (got_event) {
			pending = true;
			pending_since = watch_now_ms();
		}

		if (pending) {
			// Debounce: wait for a quiet period before rebuilding.
			u64 now = watch_now_ms();
			if (now - pending_since >= 300) {
				pending = false;
				gb_printf("[watch] Change detected, recompiling...\n");
				struct timespec req = {0, 150 * 1000 * 1000};
				nanosleep(&req, nullptr);
				watch_rebuild_and_patch(compiler_path, manifest_path);
			}
		}
	}

	if (g_watch_child_pid > 0 && !g_watch_stop) {
		int status = 0;
		if (waitpid(g_watch_child_pid, &status, WNOHANG) == 0) {
			kill(g_watch_child_pid, SIGTERM);
			waitpid(g_watch_child_pid, &status, 0);
		}
	}
	close(g_watch_inotify_fd);
	unlink(g_watch_socket_buf);
	return result;
}

#endif // !GB_SYSTEM_WINDOWS
