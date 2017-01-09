# Copyright 2016 The Fuchsia Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

CC = gcc
C++ = g++

CFLAGS = -g
CXXFLAGS = $(CFLAGS)

INCLUDES = -I../../out/sysroot/x86_64-fuchsia/include

ALL_CFLAGS = $(CFLAGS) $(INCLUDES)
ALL_CXXFLAGS = $(CXXFLAGS) $(INCLUDES)

all: ktrace-reader

ktrace-reader: ktrace-reader.cc ktrace-reader.h
	$(CXX) -o $@ ktrace-reader.cc $(ALL_CXXFLAGS) -DTEST
