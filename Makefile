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
	ant -buildfile jca/build.xml $(ANT_CMDLINE)
	$(MAKE) -C jca/native DEBUG=$(DEBUG)
	ant -buildfile crl-service/build.xml $(ANT_CMDLINE)
	$(MAKE) -C test DEBUG=$(DEBUG)

clean:
	$(MAKE) clean -C src DEBUG=$(DEBUG) ALIGN=$(ALIGN)
	ant -buildfile jca/build.xml clean $(ANT_CMDLINE)
	$(MAKE) clean -C jca/native DEBUG=$(DEBUG)
	ant -buildfile crl-service/build.xml clean $(ANT_CMDLINE)
	$(MAKE) clean -C test DEBUG=$(DEBUG)

