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
PYTHON ?= python3
PYTEST ?= $(PYTHON) -m pytest
INSTALL ?= install

prefix ?= /usr/local
bindir ?= $(prefix)/bin
libdir ?= $(prefix)/lib

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
PLUGIN_NAME = libqemu-etrace.so
QEMU_SRC ?= ../qemu
QEMU_PLUGIN_HEADER ?= $(firstword \
	$(wildcard $(QEMU_SRC)/include/plugins/qemu-plugin.h) \
	$(wildcard $(QEMU_SRC)/include/qemu/qemu-plugin.h))
QEMU_PLUGIN_API ?= $(or $(shell sed -n \
	's/^[[:space:]]*\#define[[:space:]]*QEMU_PLUGIN_VERSION[[:space:]]*//p' \
	$(QEMU_PLUGIN_HEADER) 2>/dev/null),unknown)
PLUGIN ?= .plugin-build/$(QEMU_PLUGIN_API)/$(PLUGIN_NAME)
plugindir ?= $(libdir)/qemu-etrace/plugins/$(QEMU_PLUGIN_API)
TEST_BUILD_DIR = .test-build
TEST_BINS = $(TEST_BUILD_DIR)/test-filename
TEST_BINS += $(TEST_BUILD_DIR)/test-excludes
TEST_BINS += $(TEST_BUILD_DIR)/test-plugin
TEST_BINS += $(TEST_BUILD_DIR)/test-plugin-v1
TEST_BINS += $(TEST_BUILD_DIR)/test-plugin-v7
TEST_FIXTURES = $(TEST_BUILD_DIR)/coverage-fixture
TEST_FIXTURES += $(TEST_BUILD_DIR)/duplicate-inline-fixture
TEST_FIXTURES += $(TEST_BUILD_DIR)/inline-function-fixture

all: $(TARGET).sh

.PHONY: all binutils check clean distclean install plugin print-plugin-path uninstall

-include $(OBJS:.o=.d)
CFLAGS += -MMD

$(TARGET): $(OBJS)
	$(LD) $(HEAD) $(OBJS) $(LDFLAGS) $(LDLIBS) -o $@

plugin: $(PLUGIN)

$(PLUGIN): plugin/etrace-plugin.c etrace-format.h $(QEMU_PLUGIN_HEADER)
	@test -n "$(QEMU_PLUGIN_HEADER)" || { \
		echo "Set QEMU_SRC or QEMU_PLUGIN_HEADER to a QEMU source tree" >&2; \
		exit 1; \
	}
	mkdir -p $(dir $@)
	$(CC) -Wall -Wextra -O2 -g -fPIC -fvisibility=hidden \
		-I. -I$(dir $(QEMU_PLUGIN_HEADER)) \
		$(shell $(PKGCONFIG) --cflags glib-2.0) \
		-shared plugin/etrace-plugin.c -pthread -lz -o $@

print-plugin-path:
	@echo $(plugindir)/$(PLUGIN_NAME)

$(TEST_BUILD_DIR):
	mkdir -p $@

$(TEST_BUILD_DIR)/test-filename: tests/unit/test-filename.c filename.c filename.h | $(TEST_BUILD_DIR)
	$(CC) $(CPPFLAGS) $(filter-out -MMD,$(CFLAGS)) -I. \
		tests/unit/test-filename.c filename.c \
		$(shell $(PKGCONFIG) --libs glib-2.0) -o $@

$(TEST_BUILD_DIR)/test-excludes: tests/unit/test-excludes.c excludes.c excludes.h | $(TEST_BUILD_DIR)
	$(CC) $(CPPFLAGS) $(filter-out -MMD,$(CFLAGS)) -I. \
		tests/unit/test-excludes.c excludes.c \
		$(shell $(PKGCONFIG) --libs glib-2.0) -o $@

$(TEST_BUILD_DIR)/test-plugin: tests/unit/test-plugin.c plugin/etrace-plugin.c \
		tests/plugin/qemu-plugin.h etrace-format.h | $(TEST_BUILD_DIR)
	$(CC) $(filter-out -MMD,$(CFLAGS)) -I. -Itests/plugin \
		tests/unit/test-plugin.c plugin/etrace-plugin.c -pthread \
		$(shell $(PKGCONFIG) --libs glib-2.0) -lz -o $@

$(TEST_BUILD_DIR)/test-plugin-v1: tests/unit/test-plugin.c plugin/etrace-plugin.c \
		tests/plugin/qemu-plugin.h etrace-format.h | $(TEST_BUILD_DIR)
	$(CC) $(filter-out -MMD,$(CFLAGS)) -DQEMU_PLUGIN_VERSION=1 \
		-I. -Itests/plugin tests/unit/test-plugin.c \
		plugin/etrace-plugin.c -pthread \
		$(shell $(PKGCONFIG) --libs glib-2.0) -lz -o $@

$(TEST_BUILD_DIR)/test-plugin-v7: tests/unit/test-plugin.c plugin/etrace-plugin.c \
		tests/plugin/qemu-plugin.h etrace-format.h | $(TEST_BUILD_DIR)
	$(CC) $(filter-out -MMD,$(CFLAGS)) -DQEMU_PLUGIN_VERSION=7 \
		-I. -Itests/plugin tests/unit/test-plugin.c \
		plugin/etrace-plugin.c -pthread \
		$(shell $(PKGCONFIG) --libs glib-2.0) -lz -o $@

$(TEST_BUILD_DIR)/coverage-fixture: tests/fixtures/coverage.c | $(TEST_BUILD_DIR)
	$(CC) -O0 -g -fno-inline -fno-pie -no-pie $< -o $@

$(TEST_BUILD_DIR)/inline-function-fixture: tests/fixtures/inline-function.c | $(TEST_BUILD_DIR)
	$(CC) -O2 -g -fno-pie -no-pie $< -o $@

$(TEST_BUILD_DIR)/duplicate-inline-fixture: \
		$(TEST_BUILD_DIR)/duplicate-inline-a.o \
		$(TEST_BUILD_DIR)/duplicate-inline-b.o \
		tests/fixtures/duplicate-inline-main.c \
		| $(TEST_BUILD_DIR)
	$(CC) -O2 -g -fno-pie -no-pie \
		$(TEST_BUILD_DIR)/duplicate-inline-a.o \
		$(TEST_BUILD_DIR)/duplicate-inline-b.o \
		tests/fixtures/duplicate-inline-main.c -o $@

$(TEST_BUILD_DIR)/duplicate-inline-a.o: tests/fixtures/duplicate-inline.c | $(TEST_BUILD_DIR)
	$(CC) -O2 -g -fno-pie -DCALLER=call_inline_helper_a \
		-DKEEP=keep_inline_helper_a -c $< -o $@

$(TEST_BUILD_DIR)/duplicate-inline-b.o: tests/fixtures/duplicate-inline.c | $(TEST_BUILD_DIR)
	$(CC) -O2 -g -fno-pie -DCALLER=call_inline_helper_b \
		-DKEEP=keep_inline_helper_b -c $< -o $@

check: $(TARGET) $(TEST_BINS) $(TEST_FIXTURES)
	$(TEST_BUILD_DIR)/test-excludes
	$(TEST_BUILD_DIR)/test-filename
	$(TEST_BUILD_DIR)/test-plugin
	$(TEST_BUILD_DIR)/test-plugin-v1
	$(TEST_BUILD_DIR)/test-plugin-v7
	$(PYTEST) -q

install: $(TARGET) $(PLUGIN)
	$(INSTALL) -d $(DESTDIR)$(bindir) $(DESTDIR)$(plugindir)
	$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)$(bindir)/$(notdir $(TARGET))
	$(INSTALL) -m 0755 $(PLUGIN) $(DESTDIR)$(plugindir)/$(PLUGIN_NAME)

uninstall:
	$(RM) $(DESTDIR)$(bindir)/$(notdir $(TARGET))
	$(RM) $(DESTDIR)$(plugindir)/$(PLUGIN_NAME)

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
	echo "ETRACE=$(abspath $(TARGET))" >>$@
	if [ -d $(BU_INSTALLDIR) ]; then \
		echo "BU_INSTALLDIR=$(BU_INSTALLDIR)" >>$@; \
		echo "exec \"\$${ETRACE}\" --nm \"\$${BU_INSTALLDIR}/bin/nm\" --objdump \"\$${BU_INSTALLDIR}/bin/objdump\" --addr2line \"\$${BU_INSTALLDIR}/bin/addr2line\" \"\$$@\"" >>$@; \
	else \
		echo "exec \"\$${ETRACE}\" \"\$$@\"" >>$@; \
	fi
	chmod +x $@

clean:
	$(RM) $(OBJS) $(OBJS:.o=.d) $(TARGET) $(TARGET).sh libqemu-etrace.so
	$(RM) -r .plugin-build $(TEST_BUILD_DIR) .pytest_cache tests/__pycache__

distclean: clean
	$(RM) -r $(BU_BUILDDIR) $(BU_INSTALLDIR) $(BU_VER)
	$(RM) $(BU_FILE)
