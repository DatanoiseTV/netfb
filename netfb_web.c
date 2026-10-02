// SPDX-License-Identifier: GPL-2.0-only
/*
 * The web UI (web/index.html, gzip-compressed by the Makefile) embedded as
 * read-only data. NETFB_WEB_GZ is an absolute path supplied by Kbuild.
 */

#include <linux/types.h>

#include "netfb.h"

asm(".pushsection .rodata, \"a\"\n"
    ".balign 16\n"
    ".global netfb_web_gz\n"
    "netfb_web_gz:\n"
    ".incbin \"" NETFB_WEB_GZ "\"\n"
    ".global netfb_web_gz_end\n"
    "netfb_web_gz_end:\n"
    ".popsection\n");
