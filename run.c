/*
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
