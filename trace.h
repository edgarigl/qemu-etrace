
enum trace_format {
	TRACE_NONE = 0,
	TRACE_ETRACE = 1,
	TRACE_VCD = 2,
};

struct trace_backend {
	void (*exec)(char *unitname, uint64_t start, uint64_t end,
			struct sym *sym);
};
