#!/bin/bash
# in GDB: target remote | vgdb
# break at somewhre
# monitor leak_check full reachable any
# monitor block_list <lost record number>
#
source nharu-env
PROG_NAME="$TEST_TARGET/debug/$NTEST_PRJ"
PROG_ARGS=""
SUPP_FILES="--suppressions=./openssl.supp"

if [ "$1" == "--java" ]
then
	PROG_NAME="$JAVA_HOME/bin/java"
	PROG_ARGS="-cp $ECLIPSE_WRKSPC/jca-provider/bin -Djava.compiler=NONE -XX:UseSSE=0 -Xmx512M org.crypthing.security.provider.NharuProvider $ECLIPSE_WRKSPC/jca-provider/signer.p12"
	SUPP_FILES="$SUPP_FILES --suppressions=./java.supp --suppressions=./exclusions.supp"
fi

valgrind --vgdb=yes --vgdb-error=0 --leak-check=full --track-origins=yes --show-reachable=yes --error-limit=no --smc-check=all --num-callers=12 $SUPP_FILES --log-file=valgrind.txt $PROG_NAME $PROG_ARGS &
gdb $PROG_NAME


