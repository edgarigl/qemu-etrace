
enum trace_format {
	TRACE_NONE = 0,
	TRACE_ETRACE,
	TRACE_HUMAN,
	TRACE_VCD,
	TRACE_ASCII_HEX,
	TRACE_ASCII_HEX_LE16,
	TRACE_ASCII_HEX_LE32,
	TRACE_ASCII_HEX_LE64,
	TRACE_ASCII_HEX_BE16,
	TRACE_ASCII_HEX_BE32,
	TRACE_ASCII_HEX_BE64
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
