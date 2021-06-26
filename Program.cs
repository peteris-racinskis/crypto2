using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using crypto2.Tools;

namespace crypto2
{
    class Program
    {
        static void Main(string[] args)
        {   
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
        }
    }
}
