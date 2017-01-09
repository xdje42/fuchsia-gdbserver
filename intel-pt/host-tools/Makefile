# Copyright 2016 The Fuchsia Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

LIBIPT_CFLAGS := -I/hack/fuchsia/ipt/simplept/github/real-processor-trace/libipt/include
LIBIPT_LIBDIR := /hack/fuchsia/ipt/simplept/github/real-processor-trace/lib
LIBIPT_LDFLAGS := -L $(LIBIPT_LIBDIR) -Wl,-rpath,$(LIBIPT_LIBDIR)

UDIS86_CFLAGS := -DHAVE_UDIS86 -I/hack/fuchsia/ipt/simplept/github/udis86
UDIS86_LIBDIR := /hack/fuchsia/ipt/simplept/github/udis86/libudis86/.libs
UDIS86_LDFLAGS := -L $(UDIS86_LIBDIR) -Wl,-rpath,$(UDIS86_LIBDIR)

CC = gcc
C++ = g++

CFLAGS = -g
CXXFLAGS = $(CFLAGS)

INCLUDES = -I../../../../out/sysroot/x86_64-fuchsia/include

ALL_CFLAGS = $(CFLAGS) $(INCLUDES) $(LIBIPT_CFLAGS) $(UDIS86_CFLAGS)
ALL_CXXFLAGS = $(CXXFLAGS) $(INCLUDES) $(LIBIPT_CFLAGS) $(UDIS86_CFLAGS)

LDFLAGS :=
LDLIBS :=

SPTDECODE_LDFLAGS = $(LIBIPT_LDFLAGS) $(UDIS86_LDFLAGS)
SPTDECODE_LDLIBS = -lipt -ludis86 -ldwarf -lelf

ALL := ktrace-reader sptdecode

all: $(ALL)

ktrace-reader: ktrace-reader.cc ktrace-reader.h
	$(CXX) -o $@ ktrace-reader.cc $(ALL_CXXFLAGS) -DTEST

ktrace-reader.o: ktrace-reader.cc ktrace-reader.h
	$(CXX) -c -o $@ ktrace-reader.cc

SPTDECODE_OBJS := sptdecode.o map.o elf.o symtab.o dtools.o dwarf.o

sptdecode: LDFLAGS += $(SPTDECODE_LDFLAGS)
sptdecode: LDLIBS += $(SPTDECODE_LDLIBS)

sptdecode: $(SPTDECODE_OBJS)
	$(CXX) -o $@ $(SPTDECODE_OBJS) $(ALL_CXXFLAGS) $(LDFLAGS) $(LDLIBS)

clean:
	rm -f $(ALL)
	rm -f *.o

%.o: %.c
	$(CC) -c -o $@ $< $(ALL_CFLAGS)

%.o: %.cc
	$(CXX) -c -o $@ $< $(ALL_CXXFLAGS)
