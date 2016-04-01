#!/bin/bash
source nharu-env
addSources()
{
	if [ -f temp.sh ]
	then
		rm temp.sh
	fi

	echo -e "\tscan dir: $1"

	find $1 -name  "*.[h|c]" -exec echo export temp={}>temp.sh \;  -exec echo echo "directory \$(dirname \$temp)" >> temp.sh \;
	chmod 755 temp.sh
	./temp.sh | sort |  uniq >> sources
	rm temp.sh
}


if [ "$1" == "--scan"  -o  ! -e sources ]
then
	if [ -f sources ]
	then
		rm sources
	fi

	echo "Scanning sources"
	addSources  $NHARU_DIR
fi


if [ -f .gdbinit ]
then
	rm .gdbinit
fi

if [ -f sources ]
then
	cat sources >> .gdbinit
fi

if [ -f breaks ]
then
	cat  breaks >> .gdbinit
fi


gdb --args $TEST_TARGET/debug/$NTEST_PRJ 
#gdb --args  $JAVA_HOME/bin/java -cp $ECLIPSE_WRKSPC/jca-provider/bin org.crypthing.security.provider.NharuProvider $ECLIPSE_WRKSPC/jca-provider/signer.p12

