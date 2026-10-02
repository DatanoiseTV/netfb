// SPDX-License-Identifier: GPL-2.0-only
/*
 * Guest-side helper for the netfb end-to-end test.
 *
 *   fbtest scenario   draws a repeating sequence through write() and mmap()
 *   fbtest kbd        prints "KEY <code> <value>" for every event the netfb
 *                     virtual keyboard delivers
 *
 * Scenario phases (3 s each, XRGB8888), which the host test waits for:
 *   1 write(): whole screen red
 *   2 mmap():  rows 50..99 green
 *   3 write(): rows 150..151 blue
 *   4 write(): whole screen black
 */
#include <dirent.h>
#include <fcntl.h>
#include <linux/fb.h>
#include <linux/input.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#define PHASE_SECONDS 3

static void die(const char *m)
{
	perror(m);
	exit(1);
}

static void write_rows(int fd, unsigned int stride, unsigned int width,
		       unsigned int y, unsigned int rows, uint32_t px)
{
	uint32_t *row = malloc(stride);
	unsigned int i;

	if (!row)
		die("malloc");
	for (i = 0; i < width; i++)
		row[i] = px;
	for (i = 0; i < rows; i++) {
		if (pwrite(fd, row, stride, (off_t)(y + i) * stride) != (ssize_t)stride)
			die("pwrite");
	}
	free(row);
}

static int scenario(void)
{
	struct fb_var_screeninfo var;
	struct fb_fix_screeninfo fix;
	int fd = open("/dev/fb0", O_RDWR);
	uint8_t *map;
	unsigned int y, x;

	if (fd < 0)
		die("open /dev/fb0");
	if (ioctl(fd, FBIOGET_VSCREENINFO, &var) || ioctl(fd, FBIOGET_FSCREENINFO, &fix))
		die("ioctl");
	if (var.bits_per_pixel != 32) {
		fprintf(stderr, "scenario needs 32 bpp\n");
		return 1;
	}
	map = mmap(NULL, fix.smem_len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (map == MAP_FAILED)
		die("mmap");

	for (;;) {
		write_rows(fd, fix.line_length, var.xres, 0, var.yres, 0x00ff0000);
		puts("PHASE 1");
		sleep(PHASE_SECONDS);

		for (y = 50; y < 100; y++)
			for (x = 0; x < var.xres; x++)
				((uint32_t *)(map + (size_t)y * fix.line_length))[x] = 0x0000ff00;
		puts("PHASE 2");
		sleep(PHASE_SECONDS);

		write_rows(fd, fix.line_length, var.xres, 150, 2, 0x000000ff);
		puts("PHASE 3");
		sleep(PHASE_SECONDS);

		write_rows(fd, fix.line_length, var.xres, 0, var.yres, 0);
		puts("PHASE 4");
		sleep(PHASE_SECONDS);
	}
}

static int kbd(void)
{
	char path[320], name[64];
	struct input_event ev;
	struct dirent *de;
	int fd = -1;
	DIR *d;

	for (int tries = 0; tries < 50 && fd < 0; tries++) {
		d = opendir("/dev/input");
		while (d && (de = readdir(d))) {
			if (strncmp(de->d_name, "event", 5))
				continue;
			snprintf(path, sizeof(path), "/dev/input/%s", de->d_name);
			fd = open(path, O_RDONLY);
			if (fd >= 0 && ioctl(fd, EVIOCGNAME(sizeof(name)), name) > 0 &&
			    !strcmp(name, "netfb virtual keyboard"))
				break;
			if (fd >= 0)
				close(fd);
			fd = -1;
		}
		if (d)
			closedir(d);
		if (fd < 0)
			usleep(100000);
	}
	if (fd < 0) {
		fprintf(stderr, "no netfb keyboard\n");
		return 1;
	}
	puts("KBD READY");
	while (read(fd, &ev, sizeof(ev)) == sizeof(ev)) {
		if (ev.type == EV_KEY && ev.value != 2)	/* skip autorepeat */
			printf("KEY %u %d\n", ev.code, ev.value);
	}
	return 0;
}

int main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IOLBF, 0);
	if (argc == 2 && !strcmp(argv[1], "scenario"))
		return scenario();
	if (argc == 2 && !strcmp(argv[1], "kbd"))
		return kbd();
	fprintf(stderr, "usage: fbtest scenario|kbd\n");
	return 2;
}
