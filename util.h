
void *safe_malloc(size_t size);
void *safe_mallocz(size_t size);
void *safe_realloc(void *ptr, size_t size);
size_t get_filesize(int fd);
static inline size_t align_pow2(size_t v, size_t alignment)
{
	v += alignment - 1;
	v &= ~(alignment - 1);
	return v;
}

bool fd_is_socket(int fd);

bool filename_is_likely_header(const char *s);
