/* A 64bit counter per 32bit word in the sym.  */
struct sym_coverage {
	uint64_t counter[0];
};

enum loc_flags {
	LOC_F_INLINED = (1 << 0),
};

struct sym_src_loc {
	struct sym_src_loc *next;
	const char *filename;
	unsigned int linenr;
	uint32_t flags;
};

struct sym_linemap {
	struct sym_src_loc locs[0];
};

struct sym
{
	struct sym *next;
	uint64_t addr;
	uint64_t size;
	int hits;
	uint64_t total_time;
	char *src_filename;

	struct sym_linemap *linemap;
	unsigned int maxline;
	struct sym_coverage *cov;

	/* For gcov, only counts entries no time.  */
	struct sym_coverage *cov_ent;
	int namelen;
	char name[128];
};

void sym_show_stats(void **store);
void sym_show(const char *prefix, const struct sym *s);
struct sym *sym_lookup_by_addr(void **rootp, uint64_t addr);
struct sym *sym_lookup_by_name(void **rootp, const char *name);
struct sym *sym_get_all(void **store, size_t *nr_syms);
struct sym *sym_get_unknown(void **store);
void sym_read_from_elf(void **rootp, char *nm, char *elf);
void sym_build_linemap(void **rootp, const char *addr2line, const char *elf);
void sym_update_cov(struct sym *sym, uint64_t start, uint64_t end,
			uint32_t time);
