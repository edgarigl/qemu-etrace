void hextrace_show(int fd, FILE *fp_out,
                    const char *objdump, const char *machine,
                    const char *guest_objdump, const char *guest_machine,
                    void **sym_tree, enum cov_format cov_fmt,
		    enum trace_format trace_in_fmt,
		    enum trace_format trace_out_fmt);
