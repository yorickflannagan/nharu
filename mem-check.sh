#!/bin/bash

HOME_DIR=/home/magut/development/nharu
JAVA=/home/magut/development/3rdparty/jdk

TEST_DIR="$HOME_DIR/test"
CMD_LINE="$TEST_DIR/ntest-app"
SUPP_FILES="--suppressions=$HOME_DIR/linux/openssl.supp"
SHOW_REACH="--show-reachable=yes"

if [ "$1" == "--java" ]
then
	CMD_LINE="$JAVA -cp $HOME_DIR/jca/java-bin $TEST_DIR/signer.p12"
	SUPP_FILES="$SUPP_FILES --suppressions=$HOME_DIR/linux/java.supp --suppressions=$HOME_DIR/linux/exclusions.supp"
	SHOW_REACH="--show-reachable=no"
fi

valgrind  --leak-check=full --track-origins=yes --error-limit=no --smc-check=all $SHOW_REACH --gen-suppressions=all $SUPP_FILES --log-file=valgrind.txt $CMD_LINE

