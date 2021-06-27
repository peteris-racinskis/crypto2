using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;
using System.CommandLine;
using System.CommandLine.Invocation;
using System.Security.Cryptography.X509Certificates;
using System.Collections.Generic;
using crypto2.Tools;

namespace crypto2
{
    class Program
    {
        static void Main(string[] args)
        {   
            /*
            var dir = "outputs/";
            var keyPath = dir+"private.pem";
            var certPath = dir+"cert.pem";
            var plaintext = dir+"original.txt";
            var cyphertext = dir+"encrypted.bin";
            var resultPath = dir+"decrypted.txt";
            X509Certificate2 cert;
            using (RSA rsa = RSA.Create(2048))
            { 
                cert = CertificateWrapper.CreateCertificate("foobar",rsa);
                CertificateWrapper.WriteCertificateToFile(certPath, cert);
                CertificateWrapper.WriteKeyToFile(keyPath,rsa);
            }
            var msg = File.ReadAllBytes(plaintext);
            var certFromFile = CertificateWrapper.GetCertificateFromFile(certPath);
            var valid = CertificateWrapper.VerifyCert(cert);
            var encrypted = CertificateWrapper.EncryptFile(certPath,plaintext);
            File.WriteAllBytes(cyphertext,encrypted);
            var decrypted = CertificateWrapper.DecryptFile(keyPath,cyphertext);
            File.WriteAllBytes(resultPath,decrypted);
            */
            // Set up the commands and global flags
            var rootCommand = new RootCommand{
                new Option<string>(
                    "--outfile",
                    getDefaultValue: () => "outputs/result",
                    "(optional) output file base path"
                ),
                new Command(
                    "generate",
                    "Generate a new X509 certificate"
                ),
                new Command(
                    "validate",
                    "Validate a self-signed X509 certificate"
                ),
                new Command(
                    "encrypt",
                    "Encrypt file using RSA and an X509 certificate"
                ),
                new Command(
                    "decrypt",
                    "Decrypt an RSA-encrypted file with the private key"
                ),
            };

            // Configure generate command handler and arguments
            var generateCommand = (Command)rootCommand.Children.GetByAlias("generate");
            generateCommand.AddOption(new Option<string>(
                "--priv-key",
                getDefaultValue: () => "",
                "(optional) existing .PEM encoded RSA key"
            ));
            generateCommand.AddArgument(new Argument<string>(
                "config",
                "path to configuration file (currently: only issuer name)"
            ));
            generateCommand.Handler = CommandHandler.Create<string, string, string>(
                (outfile, privKey, config) => { 
                    using (RSA rsa = RSA.Create(2048))
                    { 
                        var issuerName = File.ReadAllText(config).Trim();
                        var certificatePath = outfile+"-cert.pem";
                        if(!String.IsNullOrEmpty(privKey)) 
                        {
                            var pemText = File.ReadAllText(privKey);
                            rsa.ImportFromPem(pemText);
                        }
                        else 
                        {
                            var privateKeyPath = outfile+"-private-key.pem";
                            CertificateWrapper.WriteKeyToFile(privateKeyPath,rsa);
                        }
                        var cert = CertificateWrapper.CreateCertificate(issuerName,rsa);
                        CertificateWrapper.WriteCertificateToFile(certificatePath, cert);
                    }
                }
            );

            // Configure validate command handler and arguments
            var validateCommand = (Command)rootCommand.Children.GetByAlias("validate");
            validateCommand.AddArgument(new Argument<string>(
                "certificate",
                "path to .PEM encoded certificate"
            ));
            validateCommand.Handler = CommandHandler.Create<string>(
                (certificate) => { 
                    Console.WriteLine($"Verifying...");
                    var cert = CertificateWrapper.GetCertificateFromFile(certificate);
                    var result = CertificateWrapper.VerifyCert(cert);
                    Console.WriteLine($"Certificate valid: {result}");
                }
            );

            // Configure encrypt command handler and arguments
            var encryptCommand = (Command)rootCommand.Children.GetByAlias("encrypt");
            encryptCommand.AddArgument(new Argument<string>(
                "plaintext",
                "path to plaintext file"
            ));
            encryptCommand.AddArgument(new Argument<string>(
                "cert",
                "path to .PEM encoded certificate"
            ));
            encryptCommand.Handler = CommandHandler.Create<string, string,string>(
                (outfile, plaintext, cert) => { 
                    var encrypted = CertificateWrapper.EncryptFile(cert,plaintext);
                    File.WriteAllBytes(outfile,encrypted);
                }
            );

            // Configure decrypt command handler and arguments
            var decryptCommand = (Command)rootCommand.Children.GetByAlias("decrypt");
            decryptCommand.AddArgument(new Argument<string>(
                "cyphertext",
                "path to cyphertext file"
            ));
            decryptCommand.AddArgument(new Argument<string>(
                "key",
                "path to .PEM encoded private key"
            ));
            decryptCommand.Handler = CommandHandler.Create<string, string,string>(
                (outfile, cyphertext, key) => { 
                    var decrypted = CertificateWrapper.DecryptFile(key,cyphertext);
                    File.WriteAllBytes(outfile,decrypted);
                }
            );

            // Execute the handler
            rootCommand.Invoke(args);
        }
    }
}
