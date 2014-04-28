
enum trace_format {
	TRACE_NONE = 0,
	TRACE_ETRACE = 1,
	TRACE_VCD = 2,
	TRACE_ASCII_HEX = 3,
	TRACE_ASCII_HEX_BE = 4
};

struct tracer {
	int fd;
	FILE *fp_out;
	void **sym_tree;

	struct {
		const char *objdump;
		const char *machine;
	} host, guest;
};

struct trace_backend {
	void (*exec)(char *unitname, uint64_t start, uint64_t end,
			struct sym *sym);
};
