enum cov_format {
	NONE = 0,
	ETRACE,
	CACHEGRIND,
	GCOV,
	QCOV,
	LCOV,
};

void coverage_emit(void **store, const char *filename, enum cov_format fmt,
		const char *gcov_strip, const char *gcov_prefix,
		const char *exclude);
void coverage_init(void **store, const char *filename, enum cov_format fmt,
                const char *gcov_strip, const char *gcov_prefix);
