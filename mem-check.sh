source nharu-env
CMD_LINE="$TEST_TARGET/debug/$NTEST_PRJ"
SUPP_FILES="--suppressions=./openssl.supp"

if [ "$1" == "--java" ]
then
	CMD_LINE="$JAVA_HOME/bin/java -cp $ECLIPSE_WRKSPC/jca-provider/bin -Djava.compiler=NONE -XX:UseSSE=0 -Xmx512M org.crypthing.security.provider.NharuProvider $ECLIPSE_WRKSPC/jca-provider/signer.p12"
	SUPP_FILES="$SUPP_FILES --suppressions=./java.supp --suppressions=./exclusions.supp"
fi

valgrind  --leak-check=full --track-origins=yes --show-reachable=yes --error-limit=no --smc-check=all --num-callers=24 --gen-suppressions=all $SUPP_FILES --log-file=valgrind.text $CMD_LINE

