## crypto2 - cryptography homework. Simple wrapper for the .NET x509 certificate and RSA interface

### How to use

Download the release, decompress, navigate to root directory. Launch script available for straightforward evaluation purposes and example commands. 

**The script allows one to quickly go through an example use case for all commands.**
```
# For evaluation, execute in order:
# ./launcher.sh generate
#  ^-- inspect results in outputs/
# ./launcher.sh validate-pass
# ./launcher.sh validate-fail
# ./launcher.sh encrypt
#  ^-- inspect results in outputs/
# ./launcher.sh decrypt
#  ^-- inspect results in outputs/
```

### Usage

```
crypto2

Usage:
  crypto2 [options] [command]

Options:
  --outfile <outfile>  (optional) output file base path [default: outputs/result]
  --version            Show version information
  -?, -h, --help       Show help and usage information

Commands:
  generate <config>           Generate a new X509 certificate
  validate <certificate>      Validate a self-signed X509 certificate
  encrypt <plaintext> <cert>  Encrypt file using RSA and an X509 certificate
  decrypt <cyphertext> <key>  Decrypt an RSA-encrypted file with the private key
```

### Commands

**NOTE: the output file base path is provided with the --outfile option for all cases**


**Generate**: creates a new x509 certificate. If no RSA private key file provided, generates a new one. Both the certificate and the key (if a new one is generated) are stored to files. Right now the config file only contains the issuer/subject name.

```
generate
  Generate a new X509 certificate

Usage:
  crypto2 [options] generate <config>

Arguments:
  <config>  path to configuration file (currently: only issuer name)

Options:
  --priv-key <priv-key>  (optional) existing .PEM encoded RSA key [default: ]
  -?, -h, --help         Show help and usage information
```

**Validate**: verify that the issuer and subject are the same, and the signature matches the contents of the certificate.

```
validate
  Validate a self-signed X509 certificate

Usage:
  crypto2 [options] validate <certificate>

Arguments:
  <certificate>  path to .PEM encoded certificate

Options:
  -?, -h, --help  Show help and usage information
```


**Encrypt**: Encrypt a file byte-wise using the RSA public key in an x509 certificate.

```
encrypt
  Encrypt file using RSA and an X509 certificate

Usage:
  crypto2 [options] encrypt <plaintext> <cert>

Arguments:
  <plaintext>  path to plaintext file
  <cert>       path to .PEM encoded certificate

Options:
  -?, -h, --help  Show help and usage information
```

**Decrypt**: Decrypt a file with the RSA private key in a file.

```
decrypt
  Decrypt an RSA-encrypted file with the private key

Usage:
  crypto2 [options] decrypt <cyphertext> <key>

Arguments:
  <cyphertext>  path to cyphertext file
  <key>         path to .PEM encoded private key

Options:
  -?, -h, --help  Show help and usage information
```



