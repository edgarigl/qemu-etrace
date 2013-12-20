#include <stdlib.h>
#include <stdio.h>
#include <string.h>

char *filename_sanitize(const char *filename)
{
	char *p1, *p2;
	char *s;

	s = strdup(filename);

	do {
		p1 = strstr(s, "/../");
		p2 = p1 - 1;
		if (p1) {
			while (p2 > s && *p2 != '/') {
				p2--;
			}
			if (*p2 == '/')
				p2++;

			strcpy(p2, p1 + 4);
		}
	} while (p1);
	return s;
}

#if 0
int main(void)
{
	const char *s;

	s = filename_sanitize("");
	printf("%s\n", s);
	s = filename_sanitize("../");
	printf("%s\n", s);
	s = filename_sanitize("kalle/../hans/");
	printf("%s\n", s);
	s = filename_sanitize("/kalle/pelle/../hans/");
	printf("%s\n", s);
	return 0;
}
#endif
