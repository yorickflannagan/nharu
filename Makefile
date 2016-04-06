#
# Makefile for Nharu libraries
# Copyleft (C) 2015 by The Crypthing Initiative
#
#
SHELL = /bin/bash

ANT_CMDLINE  = -DDEBUG=$(DEBUG) -DJAVA_LOG_PATH=org.crypthing.security

.PHONY : all clean
all:
	$(MAKE) -C src DEBUG=$(DEBUG) ALIGN=$(ALIGN)
	$(MAKE) -C jca/native DEBUG=$(DEBUG)
	$(MAKE) -C test DEBUG=$(DEBUG)
	ant -buildfile jca/build.xml $(ANT_CMDLINE)

clean:
	$(MAKE) clean -C src DEBUG=$(DEBUG) ALIGN=$(ALIGN)
	$(MAKE) clean -C jca/native DEBUG=$(DEBUG)
	$(MAKE) clean -C test DEBUG=$(DEBUG)
	ant -buildfile jca/build.xml clean $(ANT_CMDLINE)

