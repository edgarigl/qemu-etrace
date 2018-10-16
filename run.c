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

#define __GNU_SOURCE
#define __USE_GNU

#include <stdint.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#undef D
#define D(x)

pid_t run(char *app, char **args, int stdio[3]) {
	pid_t kid;
	extern char **environ;
	int i;

	assert(app);

	kid = fork();
	if (kid == 0) {
		for (i = 0; i < 3; i++) {
			if (stdio[i] != i) {
				int r;
				r = dup2(stdio[i], i);
				if (r < 0)
					perror("dup");
			}
		}

		execve(app, args, environ);
		perror(app);
		_exit(1);
	}

	return kid;
}
