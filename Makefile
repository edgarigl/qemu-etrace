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
USE_LOCAL_BINUTILS ?= 0

ifneq ($(USE_LOCAL_BINUTILS),0)
ifneq ($(USE_LOCAL_BINUTILS),1)
$(error USE_LOCAL_BINUTILS must be 0 or 1)
endif
endif

prefix ?= /usr/local
bindir ?= $(prefix)/bin
libdir ?= $(prefix)/lib
datadir ?= $(prefix)/share
qemuetracedir ?= $(datadir)/qemu-etrace

BU_VER = binutils-2.42
BU_FILE = $(BU_VER).tar.gz
BU_URL = https://ftp.gnu.org/gnu/binutils/$(BU_FILE)
BU_INSTALLDIR = $(CURDIR)/$(BU_VER)-install
BU_BUILDDIR = $(BU_VER)-build

CFLAGS  += -Wall -O3 -g
CFLAGS  += $(shell $(PKGCONFIG) --cflags glib-2.0)
#CFLAGS += -m32
#CFLAGS += -pg
# Binutils 2.29 and newer have a new API for the disassembler. Unfortunately,
# the library does not provide an easy way to detect the installed version.
# Manually comment out the following if you're using older binutils.
CPPFLAGS  += -DBINUTILS_2_29_OR_NEWER

# LDFLAGS += -pg
# LDFLAGS += -static
BINUTILS_MODE = system
ifeq ($(USE_LOCAL_BINUTILS),1)
BINUTILS_MODE = local
CPPFLAGS += -I$(BU_INSTALLDIR)/include
LDFLAGS += -L$(BU_INSTALLDIR)/lib
LDLIBS += -lbfd
LDLIBS += -lopcodes
LDLIBS += -lbfd
LDLIBS += -lsframe
LDLIBS += -liberty
else
LDLIBS += -lbfd
LDLIBS += -lopcodes
LDLIBS += -lsframe
endif
LDLIBS += -lz
LDLIBS += -ldl
LDLIBS += $(shell $(PKGCONFIG) --libs glib-2.0)
BINUTILS_MODE_STAMP = .binutils-mode-$(BINUTILS_MODE)

OBJS += qemu-etrace.o
OBJS += address-map.o
OBJS += trace.o
OBJS += trace-open.o
OBJS += filename.o
OBJS += util.o
OBJS += safeio.o
OBJS += run.o
OBJS += dwarf-lines.o
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
VIEWER = etrace-view
VIEWER_DATA = etrace-view.py etrace.py addr2line.py
PLUGIN_NAME = libqemu-etrace.so
QEMU_SRC ?= ../qemu
QEMU_PLUGIN_HEADER ?= $(firstword \
	$(wildcard $(QEMU_SRC)/include/plugins/qemu-plugin.h) \
	$(wildcard $(QEMU_SRC)/include/qemu/qemu-plugin.h))
QEMU_PLUGIN_API ?= $(or $(shell sed -n \
	's/^[[:space:]]*\#define[[:space:]]*QEMU_PLUGIN_VERSION[[:space:]]*//p' \
	$(QEMU_PLUGIN_HEADER) 2>/dev/null),unknown)
QEMU_PLUGIN_HAS_DISCON := $(shell if test -n "$(QEMU_PLUGIN_HEADER)" && \
	grep -q 'qemu_plugin_register_vcpu_discon_cb' \
	"$(QEMU_PLUGIN_HEADER)"; then echo 1; fi)
ifeq ($(QEMU_PLUGIN_HAS_DISCON),1)
PLUGIN_CPPFLAGS += -DHAVE_QEMU_PLUGIN_VCPU_DISCON_CB
endif
PLUGIN ?= .plugin-build/$(QEMU_PLUGIN_API)/$(PLUGIN_NAME)
plugindir ?= $(libdir)/qemu-etrace/plugins/$(QEMU_PLUGIN_API)
TEST_BUILD_DIR = .test-build
TEST_BINS = $(TEST_BUILD_DIR)/test-filename
TEST_BINS += $(TEST_BUILD_DIR)/test-address-map
TEST_BINS += $(TEST_BUILD_DIR)/test-disas
TEST_BINS += $(TEST_BUILD_DIR)/test-excludes
TEST_BINS += $(TEST_BUILD_DIR)/test-dwarf-lines
TEST_BINS += $(TEST_BUILD_DIR)/test-plugin
TEST_BINS += $(TEST_BUILD_DIR)/test-plugin-v1
TEST_BINS += $(TEST_BUILD_DIR)/test-plugin-v2
TEST_BINS += $(TEST_BUILD_DIR)/test-plugin-v4
TEST_BINS += $(TEST_BUILD_DIR)/test-plugin-v5-discon
TEST_BINS += $(TEST_BUILD_DIR)/test-plugin-v6-discon
TEST_BINS += $(TEST_BUILD_DIR)/test-plugin-v7
TEST_BINS += $(TEST_BUILD_DIR)/test-run
TEST_FIXTURES = $(TEST_BUILD_DIR)/coverage-fixture
TEST_FIXTURES += $(TEST_BUILD_DIR)/duplicate-inline-fixture
TEST_FIXTURES += $(TEST_BUILD_DIR)/inline-function-fixture

ALL_TARGETS = $(TARGET)
ifeq ($(USE_LOCAL_BINUTILS),1)
ALL_TARGETS += $(TARGET).sh
endif

all: $(ALL_TARGETS)

.PHONY: all binutils check check-local-binutils clean distclean install \
	plugin print-plugin-path uninstall

-include $(OBJS:.o=.d)
CFLAGS += -MMD

$(TARGET): $(OBJS)
	$(LD) $(HEAD) $(OBJS) $(LDFLAGS) $(LDLIBS) -o $@

$(BINUTILS_MODE_STAMP):
	$(RM) .binutils-mode-system .binutils-mode-local
	touch $@

$(OBJS): $(BINUTILS_MODE_STAMP)

ifeq ($(USE_LOCAL_BINUTILS),1)
$(OBJS): | check-local-binutils

check-local-binutils:
	@test -f $(BU_INSTALLDIR)/lib/libbfd.a || { \
		echo "Local Binutils is missing; run 'make binutils' first" >&2; \
		exit 1; \
	}
else
check-local-binutils:
	@:
endif

plugin: $(PLUGIN)

$(PLUGIN): plugin/etrace-plugin.c etrace-format.h $(QEMU_PLUGIN_HEADER)
	@test -n "$(QEMU_PLUGIN_HEADER)" || { \
		echo "Set QEMU_SRC or QEMU_PLUGIN_HEADER to a QEMU source tree" >&2; \
		exit 1; \
	}
	mkdir -p $(dir $@)
	$(CC) -Wall -Wextra -O2 -g -fPIC -fvisibility=hidden \
		$(PLUGIN_CPPFLAGS) \
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

$(TEST_BUILD_DIR)/test-address-map: tests/unit/test-address-map.c \
		address-map.c address-map.h | $(TEST_BUILD_DIR)
	$(CC) $(CPPFLAGS) $(filter-out -MMD,$(CFLAGS)) -I. \
		tests/unit/test-address-map.c address-map.c \
		$(shell $(PKGCONFIG) --libs glib-2.0) -o $@

$(TEST_BUILD_DIR)/test-disas: tests/unit/test-disas.c disas.c disas.h \
		run.c run.h safeio.c safeio.h util.c util.h | $(TEST_BUILD_DIR)
	$(CC) $(CPPFLAGS) $(filter-out -MMD,$(CFLAGS)) -I. \
		tests/unit/test-disas.c disas.c run.c safeio.c util.c \
		$(LDFLAGS) $(LDLIBS) -o $@

$(TEST_BUILD_DIR)/test-excludes: tests/unit/test-excludes.c excludes.c excludes.h | $(TEST_BUILD_DIR)
	$(CC) $(CPPFLAGS) $(filter-out -MMD,$(CFLAGS)) -I. \
		tests/unit/test-excludes.c excludes.c \
		$(shell $(PKGCONFIG) --libs glib-2.0) -o $@

$(TEST_BUILD_DIR)/test-dwarf-lines: tests/unit/test-dwarf-lines.c \
		dwarf-lines.c dwarf-lines.h | $(TEST_BUILD_DIR)
	$(CC) $(CPPFLAGS) $(filter-out -MMD,$(CFLAGS)) -I. \
		tests/unit/test-dwarf-lines.c dwarf-lines.c \
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

$(TEST_BUILD_DIR)/test-plugin-v2: tests/unit/test-plugin.c plugin/etrace-plugin.c \
		tests/plugin/qemu-plugin.h etrace-format.h | $(TEST_BUILD_DIR)
	$(CC) $(filter-out -MMD,$(CFLAGS)) -DQEMU_PLUGIN_VERSION=2 \
		-I. -Itests/plugin tests/unit/test-plugin.c \
		plugin/etrace-plugin.c -pthread \
		$(shell $(PKGCONFIG) --libs glib-2.0) -lz -o $@

$(TEST_BUILD_DIR)/test-plugin-v4: tests/unit/test-plugin.c plugin/etrace-plugin.c \
		tests/plugin/qemu-plugin.h etrace-format.h | $(TEST_BUILD_DIR)
	$(CC) $(filter-out -MMD,$(CFLAGS)) -DQEMU_PLUGIN_VERSION=4 \
		-I. -Itests/plugin tests/unit/test-plugin.c \
		plugin/etrace-plugin.c -pthread \
		$(shell $(PKGCONFIG) --libs glib-2.0) -lz -o $@

$(TEST_BUILD_DIR)/test-plugin-v5-discon: tests/unit/test-plugin.c \
		plugin/etrace-plugin.c tests/plugin/qemu-plugin.h etrace-format.h \
		| $(TEST_BUILD_DIR)
	$(CC) $(filter-out -MMD,$(CFLAGS)) -DQEMU_PLUGIN_VERSION=5 \
		-DHAVE_QEMU_PLUGIN_VCPU_DISCON_CB -I. -Itests/plugin \
		tests/unit/test-plugin.c plugin/etrace-plugin.c -pthread \
		$(shell $(PKGCONFIG) --libs glib-2.0) -lz -o $@

$(TEST_BUILD_DIR)/test-plugin-v6-discon: tests/unit/test-plugin.c \
		plugin/etrace-plugin.c tests/plugin/qemu-plugin.h etrace-format.h \
		| $(TEST_BUILD_DIR)
	$(CC) $(filter-out -MMD,$(CFLAGS)) -DQEMU_PLUGIN_VERSION=6 \
		-DHAVE_QEMU_PLUGIN_VCPU_DISCON_CB -I. -Itests/plugin \
		tests/unit/test-plugin.c plugin/etrace-plugin.c -pthread \
		$(shell $(PKGCONFIG) --libs glib-2.0) -lz -o $@

$(TEST_BUILD_DIR)/test-plugin-v7: tests/unit/test-plugin.c plugin/etrace-plugin.c \
		tests/plugin/qemu-plugin.h etrace-format.h | $(TEST_BUILD_DIR)
	$(CC) $(filter-out -MMD,$(CFLAGS)) -DQEMU_PLUGIN_VERSION=7 \
		-DHAVE_QEMU_PLUGIN_VCPU_DISCON_CB \
		-I. -Itests/plugin tests/unit/test-plugin.c \
		plugin/etrace-plugin.c -pthread \
		$(shell $(PKGCONFIG) --libs glib-2.0) -lz -o $@

$(TEST_BUILD_DIR)/test-run: tests/unit/test-run.c run.c run.h | $(TEST_BUILD_DIR)
	$(CC) $(CPPFLAGS) $(filter-out -MMD,$(CFLAGS)) -I. \
		tests/unit/test-run.c run.c \
		$(shell $(PKGCONFIG) --libs glib-2.0) -o $@

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
	$(TEST_BUILD_DIR)/test-address-map
	$(TEST_BUILD_DIR)/test-disas
	$(TEST_BUILD_DIR)/test-excludes
	$(TEST_BUILD_DIR)/test-dwarf-lines
	$(TEST_BUILD_DIR)/test-filename
	$(TEST_BUILD_DIR)/test-plugin
	$(TEST_BUILD_DIR)/test-plugin-v1
	$(TEST_BUILD_DIR)/test-plugin-v2
	$(TEST_BUILD_DIR)/test-plugin-v4
	$(TEST_BUILD_DIR)/test-plugin-v5-discon
	$(TEST_BUILD_DIR)/test-plugin-v6-discon
	$(TEST_BUILD_DIR)/test-plugin-v7
	$(TEST_BUILD_DIR)/test-run
	$(PYTEST) -q

install: $(TARGET) $(PLUGIN)
	$(INSTALL) -d $(DESTDIR)$(bindir) $(DESTDIR)$(plugindir) \
		$(DESTDIR)$(qemuetracedir)
	$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)$(bindir)/$(notdir $(TARGET))
	sed 's|@QEMU_ETRACE_DATADIR@|$(qemuetracedir)|g' etrace-view.in \
		>$(DESTDIR)$(bindir)/$(notdir $(VIEWER))
	chmod 0755 $(DESTDIR)$(bindir)/$(notdir $(VIEWER))
	$(INSTALL) -m 0644 $(VIEWER_DATA) $(DESTDIR)$(qemuetracedir)
	$(INSTALL) -m 0755 $(PLUGIN) $(DESTDIR)$(plugindir)/$(PLUGIN_NAME)

uninstall:
	$(RM) $(DESTDIR)$(bindir)/$(notdir $(TARGET))
	$(RM) $(DESTDIR)$(bindir)/$(notdir $(VIEWER))
	$(RM) $(addprefix $(DESTDIR)$(qemuetracedir)/,$(VIEWER_DATA))
	$(RM) $(DESTDIR)$(plugindir)/$(PLUGIN_NAME)

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
	$(RM) $(OBJS) $(OBJS:.o=.d) $(TARGET) $(TARGET).sh \
		libqemu-etrace.so .binutils-mode-system .binutils-mode-local
	$(RM) -r .plugin-build $(TEST_BUILD_DIR) .pytest_cache tests/__pycache__

distclean: clean
	$(RM) -r $(BU_BUILDDIR) $(BU_INSTALLDIR) $(BU_VER)
	$(RM) $(BU_FILE)
