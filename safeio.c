/*
Safe IO, take care of signal interruption and partial reads/writes.

Copyright (c) 2009, Edgar E. Iglesias <edgar.iglesias@gmail.com>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met: 

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer. 

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

The views and conclusions contained in the software and documentation are those
of the authors and should not be interpreted as representing official policies, 
either expressed or implied, of the FreeBSD Project.
*/

#define _LARGEFILE64_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>

#define D(x)

#if !defined(SPLICE_F_MOVE) && defined(__NR_splice)
#define SPLICE_F_MOVE          1
#include <sys/syscall.h>

long splice(int fd_in, off_t *off_in, int fd_out,
                   off_t *off_out, size_t len, unsigned int flags)
{
	return syscall(__NR_splice, fd_in, off_in, 
		       fd_out, off_out, len, flags);
}
#endif

ssize_t
safe_read(int fd, void *rbuf, size_t count)
{
	ssize_t r;
	size_t rlen = 0;
	unsigned char *buf = rbuf;

	do {
		if ((r = read(fd, buf + rlen, count - rlen)) < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		rlen += r;
	} while (rlen < count && r);

	return rlen;
}

ssize_t
safe_write(int fd, const void *wbuf, size_t count)
{
	ssize_t r;
	size_t wlen = 0;
	const unsigned char *buf = wbuf;

	do {
		if ((r = write(fd, buf + wlen, count - wlen)) < 0) {
			if (errno == EINTR) {
				continue;
			} else if (errno == EAGAIN) 
				break;
			return -1;
		}

		wlen += r;
	} while (wlen < count);

	return wlen;
}

/* Try to splice if possible.  */
int safe_copyfd(int s, off64_t off, size_t olen, int d)
{
	static unsigned char buf[16 * 1024];
	int len = olen;
	int rlen;
	int wlen;
	int tlen = 0;

	D(fprintf(stderr, "%s off=%lld len=%d\n", __func__, off, len));
	lseek64(s, off, SEEK_SET);
#if 0
	long r;	
	do 
	{
		wlen = len > 16 * 1024 ? 16 * 1024 : len;
		r = splice(s, NULL, d, NULL, wlen, 0);
		D(fprintf(stderr, "splice r=%d errno=%d\n", r, errno));
		if (r == -1) {
			D(perror("splice"));
			if (errno == ENOSYS
			    || errno == EINVAL
			    || errno == EBADF)
				goto classic_read_write;
			if (errno == EAGAIN)
				continue;
		}
		else
			len -= r;
	}
	while (r > 0 && len > 0);

	D(fprintf (stderr, "dcore len=%d r=%ld errno=%d\n", len, r, errno));
	return r;
  classic_read_write:
#endif
	D(fprintf (stderr,
		   "dcore: fallback to classic read-write"
		   " r=%d errno=%d olen=%d.\n",
		   r, errno, olen));
	do
	{
		rlen = len > sizeof buf ? sizeof buf : len;
		rlen = read(s, buf, rlen);
		D(printf("read=%d errno=%d\n", rlen, errno));
		if (rlen == -1
		    && (errno == EAGAIN || errno == EINTR))
			continue;
		wlen = 0;
		while (rlen && wlen < rlen) 
		{
			int w;
			w = safe_write(d, buf + wlen, rlen - wlen);
			if (w == -1) {
				D(perror("write"));
				break;
			}
			wlen += w;
		}
		tlen += wlen;
		len -= wlen;
	} while (rlen && len);
	D(fprintf (stderr, "done tlen=%d olen=%d\n", tlen, olen));
	return tlen;
}
