// SPDX-License-Identifier: GPL-2.0-only
/*
 * fgt-sector0: read or write sector 0 of a block device, 512 bytes, with
 * real direct I/O.
 *
 *   fgt-sector0 read  <device> <file>   sector 0 of <device> to <file>,
 *                                       a new file (never an existing
 *                                       one, nor a symbolic link)
 *   fgt-sector0 write <device> <file>   <file> (512 bytes) to sector 0
 *
 * The kernel guards the boot disk of a dual-slot appliance and lets the
 * installer write LBA 0 alone (a window of one sector). A buffered
 * 512-byte write would reach the device as a page (sectors 0-7), and
 * busybox dd at bs=512 with oflag=direct silently falls back to
 * buffered I/O (its buffer is not aligned). Here the buffer is aligned
 * on 4 KiB, the device is opened with O_DIRECT (and O_SYNC to write),
 * and any error is final: there is no buffered fallback.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <linux/fs.h>

#define SECTOR	512
#define ALIGN	4096

static int fail(const char *what, const char *arg)
{
	fprintf(stderr, "fgt-sector0: %s %s: %s\n", what, arg,
		errno ? strerror(errno) : "failed");
	return 1;
}

/* Direct I/O on a block device of 512-byte logical sectors (or a file) */
static int open_direct(const char *dev, int flags)
{
	struct stat st;
	int fd, ssz;

	fd = open(dev, flags | O_DIRECT | O_CLOEXEC);
	if (fd < 0)
		return -1;
	if (fstat(fd, &st) < 0)
		goto err;
	if (S_ISBLK(st.st_mode)) {
		if (ioctl(fd, BLKSSZGET, &ssz) < 0)
			goto err;
		if (ssz != SECTOR) {
			errno = EINVAL;
			goto err;
		}
	} else if (!S_ISREG(st.st_mode)) {
		errno = EINVAL;
		goto err;
	}
	/* O_DIRECT really set (no silent fallback) */
	if (!(fcntl(fd, F_GETFL) & O_DIRECT)) {
		errno = EINVAL;
		goto err;
	}
	return fd;
err:
	close(fd);
	return -1;
}

int main(int argc, char **argv)
{
	unsigned char *buf;
	ssize_t n;
	int fd, f;

	if (argc != 4 || (strcmp(argv[1], "read") && strcmp(argv[1], "write"))) {
		fprintf(stderr, "usage: fgt-sector0 read|write <device> <file>\n");
		return 2;
	}
	errno = posix_memalign((void **)&buf, ALIGN, ALIGN);
	if (errno)
		return fail("allocating", "buffer");
	memset(buf, 0, ALIGN);

	if (!strcmp(argv[1], "read")) {
		fd = open_direct(argv[2], O_RDONLY);
		if (fd < 0)
			return fail("opening", argv[2]);
		errno = 0;
		n = pread(fd, buf, SECTOR, 0);
		if (n != SECTOR)
			return fail("reading", argv[2]);
		close(fd);
		f = open(argv[3], O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW |
			 O_CLOEXEC, 0600);
		if (f < 0)
			return fail("creating", argv[3]);
		errno = 0;
		if (write(f, buf, SECTOR) != SECTOR || fsync(f) || close(f))
			return fail("writing", argv[3]);
		return 0;
	}

	/* write: the file must be exactly one sector */
	f = open(argv[3], O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	if (f < 0)
		return fail("opening", argv[3]);
	errno = 0;
	n = read(f, buf, SECTOR + 1);
	close(f);
	if (n != SECTOR) {
		errno = n < 0 ? errno : EINVAL;
		return fail("not one sector:", argv[3]);
	}
	fd = open_direct(argv[2], O_WRONLY | O_SYNC);
	if (fd < 0)
		return fail("opening", argv[2]);
	errno = 0;
	n = pwrite(fd, buf, SECTOR, 0);
	if (n != SECTOR)
		return fail("writing", argv[2]);
	if (fsync(fd) || close(fd))
		return fail("syncing", argv[2]);
	return 0;
}
