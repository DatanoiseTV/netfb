# SPDX-License-Identifier: GPL-2.0-only
obj-m += netfb.o
netfb-y := netfb_fb.o netfb_net.o netfb_ws.o netfb_vnc.o netfb_web.o

# Absolute path: .incbin is resolved by the assembler, not by kbuild.
ccflags-y += -DNETFB_WEB_GZ=\"$(NETFB_ROOT)/web/index.html.gz\"

$(obj)/netfb_web.o: $(NETFB_ROOT)/web/index.html.gz
