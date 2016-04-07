void *excludes_create(const char *filename);
void excludes_destroy(void *ex);

bool excludes_match(void *excludes, const char *filename, int linenr);

