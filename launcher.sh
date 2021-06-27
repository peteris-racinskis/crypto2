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

outfile = ""
comm = ""
args = ""
case $1 in
    "generate")
        outfile = "--outfile outputs/test-exist"
        comm = "generate"
        args = "outputs/test-config.txt --priv-key outputs/test-exist-private-key.pem"
        ;;
    "validate-pass")
        comm = "validate"
        args = "outputs/test-exist-cert.pem"
        ;;
    "validate-fail")
        comm = "validate"
        args = "outputs/garbled.pem"
        ;;
    "encrypt")
        outfile = "outputs/encrypted.bin"
        comm = "encrypt"
        args = "outputs/original.txt outputs/test-exist-cert.pem"
        ;;
    "decrypt")
        outfile = "outputs/decrypted.txt"
        comm = "decrypt"
        args = "outputs/encrypted.bin outputs/test-exist-private-key.pem"
        ;;
arguments="./crypto2 $outfile $command $args"

exec $arguments
