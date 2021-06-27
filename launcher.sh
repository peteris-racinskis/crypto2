#!/usr/bin/sh

# For evaluation, execute in order:
# ./launcher.sh generate
#  ^-- inspect results in outputs/
# ./launcher.sh validate-pass
# ./launcher.sh validate-fail
# ./launcher.sh encrypt
#  ^-- inspect results in outputs/
# ./launcher.sh decrypt
#  ^-- inspect results in outputs/
echo $0
case $0 in
    "generate")
        outfile="--outfile outputs/test-exist"
        test_command="generate"
        args="outputs/test-config.txt --priv-key outputs/test-exist-private-key.pem"
        ;;
    "validate-pass")
        test_command="validate"
        args="outputs/test-exist-cert.pem"
        ;;
    "validate-fail")
        test_command="validate"
        args="outputs/garbled.pem"
        ;;
    "encrypt")
        outfile="outputs/encrypted.bin"
        test_command="encrypt"
        args="outputs/original.txt outputs/test-exist-cert.pem"
        ;;
    "decrypt")
        outfile="outputs/decrypted.txt"
        test_command="decrypt"
        args="outputs/encrypted.bin outputs/test-exist-private-key.pem"
        ;;
    * )
        echo "Choose a test_command"
        ;;
esac
arguments="./crypto2 $outfile $test_command $args"

exec $arguments
