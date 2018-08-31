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



#DEBUG_APP="/usr/lib/jvm/java-7-oracle/jre/bin/java"
#DEBUG_APP="/usr/lib/jvm/java-8-oracle/jre/bin/java"
#DEBUG_APP="./test/ntest-app"
DEBUG_APP="/home/dsvs/development/build/ssl/linux/bin/openssl"
APP_CLASSPATH="/home/dsvs/development/3rdParty/jboss-eap-6.2/modules/system/layers/base/org/picketbox/main/picketbox-infinispan-4.0.19.SP2-redhat-1.jar:/home/dsvs/development/3rdParty/jboss-eap-6.2/modules/system/layers/base/org/picketbox/main/picketbox-commons-1.0.0.final-redhat-2.jar:/home/dsvs/development/3rdParty/jboss-eap-6.2/modules/system/layers/base/org/picketbox/main/picketbox-4.0.19.SP2-redhat-1.jar:/home/dsvs/development/3rdParty/jboss-eap-6.2/modules/system/layers/base/org/jboss/logging/main/jboss-logging-3.1.2.GA-redhat-1.jar"
#APP_CLASS="br.gov.caixa.testcert.ValidaCert"
#APP_CLASS="br.gov.caixa.testcert.ValidaJKS"
APP_CLASSPATH="/home/dsvs/development/nharu/jca/nharujca.jar:/home/dsvs/development/test/crapscrap/teste/target/classes"
APP_CLASS="teste.teste.TesteCert"

#APP_ARGS="-cp $APP_CLASSPATH:/home/dsvs/workspace/TesteKeystore/bin/ $APP_CLASS"
APP_ARGS=" smime -verify -in /home/dsvs/development/nharu/test/signed.pem -inform PEM -CAfile /home/dsvs/development/nharu/test/chain.p7"


BASE="/home/dsvs/development/nharu"


# Source files
echo "dir $BASE/src" >> .gdbinit
echo "dir $BASE/test" >> .gdbinit
echo "dir $BASE/include" >> .gdbinit
echo "dir $BASE/jca/native" >> .gdbinit
echo "dir $BASE/jca/native/b64" >> .gdbinit
echo "dir $BASE/jca/native/sb8" >> .gdbinit


OPENSSL="/home/dsvs/development/3rdParty/libssl/"
#find $OPENSSL -name "*.[h|c]" -exec dirname {} \; | sort | uniq | awk '{ print "dir "$1 }'

echo "dir $OPENSSL" >> .gdbinit
echo "dir $OPENSSL/apps" >> .gdbinit
echo "dir $OPENSSL/crypto" >> .gdbinit
echo "dir $OPENSSL/crypto/aes" >> .gdbinit
echo "dir $OPENSSL/crypto/asn1" >> .gdbinit
echo "dir $OPENSSL/crypto/async" >> .gdbinit
echo "dir $OPENSSL/crypto/async/arch" >> .gdbinit
echo "dir $OPENSSL/crypto/bf" >> .gdbinit
echo "dir $OPENSSL/crypto/bio" >> .gdbinit
echo "dir $OPENSSL/crypto/blake2" >> .gdbinit
echo "dir $OPENSSL/crypto/bn" >> .gdbinit
echo "dir $OPENSSL/crypto/bn/asm" >> .gdbinit
echo "dir $OPENSSL/crypto/buffer" >> .gdbinit
echo "dir $OPENSSL/crypto/camellia" >> .gdbinit
echo "dir $OPENSSL/crypto/cast" >> .gdbinit
echo "dir $OPENSSL/crypto/chacha" >> .gdbinit
echo "dir $OPENSSL/crypto/cmac" >> .gdbinit
echo "dir $OPENSSL/crypto/cms" >> .gdbinit
echo "dir $OPENSSL/crypto/comp" >> .gdbinit
echo "dir $OPENSSL/crypto/conf" >> .gdbinit
echo "dir $OPENSSL/crypto/ct" >> .gdbinit
echo "dir $OPENSSL/crypto/des" >> .gdbinit
echo "dir $OPENSSL/crypto/dh" >> .gdbinit
echo "dir $OPENSSL/crypto/dsa" >> .gdbinit
echo "dir $OPENSSL/crypto/dso" >> .gdbinit
echo "dir $OPENSSL/crypto/ec" >> .gdbinit
echo "dir $OPENSSL/crypto/engine" >> .gdbinit
echo "dir $OPENSSL/crypto/err" >> .gdbinit
echo "dir $OPENSSL/crypto/evp" >> .gdbinit
echo "dir $OPENSSL/crypto/hmac" >> .gdbinit
echo "dir $OPENSSL/crypto/idea" >> .gdbinit
echo "dir $OPENSSL/crypto/include/internal" >> .gdbinit
echo "dir $OPENSSL/crypto/kdf" >> .gdbinit
echo "dir $OPENSSL/crypto/lhash" >> .gdbinit
echo "dir $OPENSSL/crypto/md2" >> .gdbinit
echo "dir $OPENSSL/crypto/md4" >> .gdbinit
echo "dir $OPENSSL/crypto/md5" >> .gdbinit
echo "dir $OPENSSL/crypto/mdc2" >> .gdbinit
echo "dir $OPENSSL/crypto/modes" >> .gdbinit
echo "dir $OPENSSL/crypto/objects" >> .gdbinit
echo "dir $OPENSSL/crypto/ocsp" >> .gdbinit
echo "dir $OPENSSL/crypto/pem" >> .gdbinit
echo "dir $OPENSSL/crypto/pkcs12" >> .gdbinit
echo "dir $OPENSSL/crypto/pkcs7" >> .gdbinit
echo "dir $OPENSSL/crypto/poly1305" >> .gdbinit
echo "dir $OPENSSL/crypto/rand" >> .gdbinit
echo "dir $OPENSSL/crypto/rc2" >> .gdbinit
echo "dir $OPENSSL/crypto/rc4" >> .gdbinit
echo "dir $OPENSSL/crypto/rc5" >> .gdbinit
echo "dir $OPENSSL/crypto/ripemd" >> .gdbinit
echo "dir $OPENSSL/crypto/rsa" >> .gdbinit
echo "dir $OPENSSL/crypto/seed" >> .gdbinit
echo "dir $OPENSSL/crypto/sha" >> .gdbinit
echo "dir $OPENSSL/crypto/srp" >> .gdbinit
echo "dir $OPENSSL/crypto/stack" >> .gdbinit
echo "dir $OPENSSL/crypto/ts" >> .gdbinit
echo "dir $OPENSSL/crypto/txt_db" >> .gdbinit
echo "dir $OPENSSL/crypto/ui" >> .gdbinit
echo "dir $OPENSSL/crypto/whrlpool" >> .gdbinit
echo "dir $OPENSSL/crypto/x509" >> .gdbinit
echo "dir $OPENSSL/crypto/x509v3" >> .gdbinit
echo "dir $OPENSSL/demos/bio" >> .gdbinit
echo "dir $OPENSSL/demos/cms" >> .gdbinit
echo "dir $OPENSSL/demos/evp" >> .gdbinit
echo "dir $OPENSSL/demos/pkcs12" >> .gdbinit
echo "dir $OPENSSL/demos/smime" >> .gdbinit
echo "dir $OPENSSL/engines" >> .gdbinit
echo "dir $OPENSSL/engines/afalg" >> .gdbinit
echo "dir $OPENSSL/engines/vendor_defns" >> .gdbinit
echo "dir $OPENSSL/fuzz" >> .gdbinit
echo "dir $OPENSSL/include/internal" >> .gdbinit
echo "dir $OPENSSL/include/openssl" >> .gdbinit
echo "dir $OPENSSL/install/include/openssl" >> .gdbinit
echo "dir $OPENSSL/ms" >> .gdbinit
echo "dir $OPENSSL/os-dep" >> .gdbinit
echo "dir $OPENSSL/ssl" >> .gdbinit
echo "dir $OPENSSL/ssl/record" >> .gdbinit
echo "dir $OPENSSL/ssl/statem" >> .gdbinit
echo "dir $OPENSSL/test" >> .gdbinit

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

