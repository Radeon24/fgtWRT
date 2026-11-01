# SPDX-License-Identifier: GPL-2.0-only
# bcm5331x-dsa.c #includes the unchanged base module bcm53314-fg100d.c (same
# directory). The tagger needs the private net/dsa/tag.h.
obj-m += bcm5331x-dsa.o
obj-m += tag_bcm5331x_8021q.o
# the base module on its own (step "init" runs from a separate load)
obj-m += bcm53314-fg100d.o
ccflags-y += -I$(src)
CFLAGS_tag_bcm5331x_8021q.o += -I$(srctree)/net/dsa
