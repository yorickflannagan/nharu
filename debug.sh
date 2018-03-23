#!/bin/bash
# $1:
#    -z = aplicação nativa
#    j = aplicação Java, onde o segundo parâmetro é o nome da classe de execução de test-case, dentro
#         do pacote org.crypthing.pkcs.test
#    p = aplicação php
# REMEMBER:
# set auto-load safe-path /
# line to your configuration file "/home/magut/.gdbinit".
procura="set auto-load safe-path /"
if [ -f "$HOME/.gdbinit" ]; then
	teste=$(grep "$procura" "$HOME/.gdbinit");
	if [ ! "$teste" == "$procura" ]; then
		echo "set auto-load safe-path /" >> "$HOME/.gdbinit"
		echo "incluido"
	fi
else
	echo "não existia"
	echo "set auto-load safe-path /" > "$HOME/.gdbinit"
fi




# GDB environment
echo "# Environment" > .gdbinit
env | while read line; do echo "set environment $line" >> .gdbinit ; done



DEBUG_APP="/usr/lib/jvm/java-7-oracle/jre/bin/java"

APP_CLASSPATH="/home/dsvs/development/3rdParty/jboss-eap-6.2/modules/system/layers/base/org/picketbox/main/picketbox-infinispan-4.0.19.SP2-redhat-1.jar:/home/dsvs/development/3rdParty/jboss-eap-6.2/modules/system/layers/base/org/picketbox/main/picketbox-commons-1.0.0.final-redhat-2.jar:/home/dsvs/development/3rdParty/jboss-eap-6.2/modules/system/layers/base/org/picketbox/main/picketbox-4.0.19.SP2-redhat-1.jar:/home/dsvs/development/3rdParty/jboss-eap-6.2/modules/system/layers/base/org/jboss/logging/main/jboss-logging-3.1.2.GA-redhat-1.jar"
APP_CLASS="br.gov.caixa.testcert.ValidaCert"

APP_ARGS="-Djava.library.path=/home/dsvs/development/nharu/jca/native/ -cp $APP_CLASSPATH:/home/dsvs/workspace/TesteKeystore/bin/ $APP_CLASS"


FSOURCE_DIR="/home/dsvs/development/nharu/src/"


# Source files
echo "dir $FSOURCE_DIR" >> .gdbinit

# Debug application
echo "# Debug app" >> .gdbinit
echo "set breakpoint pending on" >> .gdbinit
if [ -f "$APP_SRC_DIR/custom.debug" ]; then
	cat "$APP_SRC_DIR/custom.debug" >> .gdbinit
fi
echo "file $DEBUG_APP" >> .gdbinit
echo "set args $APP_ARGS" >> .gdbinit

# Debug user
sudo gdb
# -q -iex "set auto-load safe-path $NHARU_DIR"

