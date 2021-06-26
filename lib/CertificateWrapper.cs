using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace crypto2.Tools
{
    class CertificateWrapper
    {
        public static X509Certificate2 CreateCertificate(string issuerName, RSA rsa)
        {
            X509Certificate2 cert;
            var req = new CertificateRequest($"cn={issuerName}", rsa, 
                            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            cert = req.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(5));
            return cert;
        }

        public static void WriteCertificateToFile(string filename, X509Certificate2 cert)
        {
            var pemCoded = PemEncoding.Write("CERTIFICATE",cert.GetRawCertData());
            File.WriteAllText(filename,new string(pemCoded));
        }

        public static void WriteKeyToFile(string filename, RSA rsa)
        {
            var pemCoded = PemEncoding.Write("RSA PRIVATE KEY",rsa.ExportRSAPrivateKey());
            File.WriteAllText(filename,new string(pemCoded));
        }

        public static X509Certificate2 GetCertificateFromFile(string filename)
        {
            return new X509Certificate2(ReadFile(filename));
        }

        public static bool VerifyCert(X509Certificate2 cert)
        {
            var chain = new X509Chain();
            X509ChainPolicy chainPolicy = new X509ChainPolicy()
            {
                TrustMode = X509ChainTrustMode.CustomRootTrust
            };
            chainPolicy.CustomTrustStore.Add(cert);
            chain.ChainPolicy = chainPolicy;
            var result = chain.Build(cert);
            if (!result)
            {
                foreach (X509ChainElement chainElement in chain.ChainElements)
                {
                    foreach (X509ChainStatus chainStatus in chainElement.ChainElementStatus)
                    {
                        Console.WriteLine(chainStatus.StatusInformation);
                    }
                }
            }
            return result;
        }

        public static byte[] Encrypt(X509Certificate2 cert, byte[] data)
        {
            byte[] output;
            using(RSA rsa = cert.GetRSAPublicKey())
            {
                output = rsa.Encrypt(data,RSAEncryptionPadding.Pkcs1);
            }
            return output;
        }

        public static byte[] Decrypt(string pemText, byte[] data)
        {
            byte[] output;
            using(RSA rsa = RSA.Create())
            {
                rsa.ImportFromPem(pemText);
                output = rsa.Decrypt(data,RSAEncryptionPadding.Pkcs1);
            }
            return output;
        }

        public static byte[] EncryptFile(string certificatePath, string filePath)
        {
            var plaintext = File.ReadAllBytes(filePath);
            var cert = GetCertificateFromFile(certificatePath);
            var output = Encrypt(cert, plaintext);
            return output;
        }

        public static byte[] DecryptFile(string privateKeyPath, string filePath)
        {
            byte[] output;
            var plaintext = File.ReadAllBytes(filePath);
            var key = File.ReadAllText(privateKeyPath);
            output = Decrypt(key, plaintext);
            return output;
        }

        internal static byte[] ReadFile(string fileName)
        {
           FileStream f = new FileStream(fileName, FileMode.Open, FileAccess.Read);
           int size = (int)f.Length;
           byte[] data = new byte[size];
           size = f.Read(data, 0, size);
           f.Close();
           return data;
        }

    }
}