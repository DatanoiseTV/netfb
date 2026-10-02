# SPDX-License-Identifier: GPL-2.0-only
KDIR ?= /lib/modules/$(shell uname -r)/build
ROOT := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
ROOT := $(patsubst %/,%,$(ROOT))

all: web/index.html.gz
	$(MAKE) -C $(KDIR) M=$(ROOT) NETFB_ROOT=$(ROOT) modules

# The UI is embedded compressed; -n keeps the output reproducible.
web/index.html.gz: web/index.html
	gzip -9nc $< > $@

clean:
	$(MAKE) -C $(KDIR) M=$(ROOT) NETFB_ROOT=$(ROOT) clean
	rm -f web/index.html.gz

.PHONY: all clean
