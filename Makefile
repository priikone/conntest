RM=rm -f
CC=cc
CFLAGS=-g -O3 -Wall -D_GNU_SOURCE

VER := $(shell git describe --abbrev=0 | cut -d - -f 2-)
ORIG_TAR := ../conntest_$(VER).orig.tar.xz

all: conntest

conntest: conntest.o ike.o
	$(CC) -o conntest conntest.o ike.o

clean: 
	-$(RM) conntest conntest.o ike.o

$(ORIG_TAR): gen-orig-tarball

.PHONY: gen-orig-tarball
gen-orig-tarball:
	git archive --format=tar --prefix=conntest-$(VER)/ HEAD | xz -c > $(ORIG_TAR)
