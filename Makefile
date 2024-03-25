# Copyright (C) Xilinx Inc.
# Written by Edgar E. Iglesias
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; version 2.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA. 
#

CC = $(CROSS)gcc
LD = $(CC)
PKGCONFIG = pkg-config

CFLAGS  += -Wall -O3 -g
CFLAGS  += $(shell $(PKGCONFIG) --cflags glib-2.0)
#CFLAGS += -m32
#CFLAGS += -pg
# Binutils 2.29 and newer have a new API for the disassembler. Unfortunately,
# the library does not provide an easy way to detect the installed version.
# Manually comment out the following if you're using older binutils.
CPPFLAGS  += -DBINUTILS_2_29_OR_NEWER

#LDFLAGS += -pg
#LDFLAGS += -static
LDLIBS += -lbfd
LDLIBS += -lopcodes
LDLIBS += -lbfd
LDLIBS += -lsframe
LDLIBS += -liberty
LDLIBS += -lz
LDLIBS += -ldl
LDLIBS += $(shell $(PKGCONFIG) --libs glib-2.0)

OBJS += qemu-etrace.o
OBJS += trace-open.o
OBJS += filename.o
OBJS += util.o
OBJS += safeio.o
OBJS += run.o
OBJS += syms.o
OBJS += excludes.o
OBJS += disas.o
OBJS += coverage.o
OBJS += cov-gcov.o
OBJS += cov-cachegrind.o
OBJS += etrace.o
OBJS += trace-hex.o
OBJS += trace-qemu-simple.o

TARGET = qemu-etrace

all: $(TARGET).sh

-include $(OBJS:.o=.d)
CFLAGS += -MMD

$(TARGET): $(OBJS)
	$(LD) $(HEAD) $(OBJS) $(LDFLAGS) $(LDLIBS) -o $@

BU_VER=binutils-2.42
BU_FILE=$(BU_VER).tar.gz
BU_URL=http://ftp.gnu.org/gnu/binutils/$(BU_FILE)
BU_INSTALLDIR=$(CURDIR)/$(BU_VER)-install
BU_BUILDDIR=$(BU_VER)-build

CPPFLAGS += -I $(BU_INSTALLDIR)/include
LDFLAGS += -L $(BU_INSTALLDIR)/lib

$(BU_FILE):
	if [ ! -f $(BU_FILE) ]; then	\
		wget $(BU_URL) ;	\
	fi

$(BU_VER): $(BU_FILE)
	tar -xzf $(BU_FILE)


binutils: $(BU_VER)
	mkdir -p $(BU_BUILDDIR)
	mkdir -p $(BU_INSTALLDIR)
	cd $(BU_BUILDDIR); \
	if [ ! -f config.log ]; then \
		../$(BU_VER)/configure --enable-targets=all --disable-werror --prefix=$(BU_INSTALLDIR) ; \
	fi;
	$(MAKE) -C $(BU_BUILDDIR)
	$(MAKE) -C $(BU_BUILDDIR) install
	cp $(BU_BUILDDIR)/libiberty/libiberty.a $(BU_INSTALLDIR)/lib

$(TARGET).sh: $(TARGET)
	echo "#!/bin/sh" >$@
	echo "#" >>$@
	echo "# Autogenerated helper script." >>$@
	echo "" >>$@
	echo "BUILD_DIR=$(CURDIR)" >>$@
	if [ -d $(BU_INSTALLDIR) ]; then \
		echo "BU_INSTALLDIR=$(BU_INSTALLDIR)" >>$@; \
		echo "ARGS=\"--nm \$${BU_INSTALLDIR}/bin/nm\"" >>$@; \
		echo "ARGS=\"--objdump \$${BU_INSTALLDIR}/bin/objdump\"" >>$@; \
		echo "ARGS=\"--addr2line \$${BU_INSTALLDIR}/bin/addr2line\"" >>$@; \
	fi
	echo "ETRACE=\$${BUILD_DIR}/qemu-etrace" >>$@
	echo "" >>$@
	echo "\$${ETRACE} \$${ARGS} \$$*" >>$@
	chmod +x $@

clean:
	$(RM) $(OBJS) $(OBJS:.o=.d) $(TARGET) $(TARGET).sh

distclean: clean
	$(RM) -r $(BU_BUILDDIR) $(BU_INSTALLDIR) $(BU_VER)
	$(RM) $(BU_FILE)
