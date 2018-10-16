/*
 * Copyright: 2013 Xilinx Inc
 * Written by Edgar E. Iglesias <edgar.iglesias@xilinx.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; version 2.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA. 
 *
 */

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
