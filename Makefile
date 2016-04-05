#
# Makefile for Nharu libraries
# Copyleft (C) 2015 by The Crypthing Initiative
#
#
SHELL = /bin/bash

.PHONY : all clean
all:
	$(MAKE) -C src DEBUG=$(DEBUG) ALIGN=$(ALIGN)
	$(MAKE) -C jca/native DEBUG=$(DEBUG)
	$(MAKE) -C test DEBUG=$(DEBUG)

clean:
	$(MAKE) clean -C src DEBUG=$(DEBUG) ALIGN=$(ALIGN)
	$(MAKE) clean -C jca/native DEBUG=$(DEBUG)
	$(MAKE) clean -C test DEBUG=$(DEBUG)

