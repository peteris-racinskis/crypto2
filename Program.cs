using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using bouncy = Org.BouncyCastle.X509;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;

namespace crypto2
{
    class Program
    {
        
        public static X509Certificate2 CreateCertificate(string issuerName, RSA rsa)
        {
            X509Certificate2 cert;
            var req = new CertificateRequest($"cn={issuerName}", rsa, 
                            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            cert = req.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(5));
            return cert;
        }


        public static void WriteCertToFile(X509Certificate2 cert, string certPath, string keyPath)
        {
            var pemCoded = PemEncoding.Write("CERTIFICATE",cert.GetRawCertData());
            File.WriteAllText(certPath,new string(pemCoded));

            var key  = cert.GetRSAPrivateKey();         
            if (key != null && !string.IsNullOrEmpty(keyPath)){
                var pemCodedKey = PemEncoding.Write("RSA PRIVATE KEY",key.ExportRSAPrivateKey());
                File.WriteAllText(keyPath,new string(pemCodedKey));
            }
        }

        public static void GenerateKeysAndCertificate(string issuerName, string certPath, string keyPath)
        {
            // generate ephemeral keypair rather than storing anything anywhere
            using(RSA rsa = RSA.Create(2048))
            {
                X509Certificate2 cert = CreateCertificate(issuerName, rsa);
                WriteCertToFile(cert, certPath, keyPath);
            }
        }

        public static bool ByteSpanCompare(ReadOnlySpan<byte> a1, ReadOnlySpan<byte> a2)
        {
            return a1.SequenceEqual(a2);
        }

        // Doesn't do any fancy chain stuff, just checks if the names and signatures match
        public static bool SimpleVerify(X509Certificate2 cert)
        {
            
            
            // have to use a third party library to work around microsoft's stupid decision to
            // not expose the actual signature anywhere on their x509 api
            var parser = new bouncy.X509CertificateParser();
            var bcert = parser.ReadCertificate(cert.GetRawCertData());
            var rawSignature = bcert.GetSignature();
            Array.Reverse(rawSignature);
            if (cert.IssuerName.Name != cert.SubjectName.Name) return false;
            
            var signer = SignerUtilities.GetSigner("SHA256withRSA");
            RSAParameters msparams;
            RsaKeyParameters bouncyparams;
            var data = cert.GetRawCertData()[..^256];
            var data_full = cert.GetRawCertData();
            var ds = cert.GetRawCertDataString();
            Console.WriteLine(Encoding.Default.GetString(data));
            using(RSA rsa = cert.GetRSAPrivateKey())
            {
                msparams = rsa.ExportParameters(false);
                var exp = new BigInteger(msparams.Exponent);
                var mod = new BigInteger(1,msparams.Modulus);
                bouncyparams = new RsaKeyParameters(true,mod,exp);
                signer.Init(true,bouncyparams);
                signer.BlockUpdate(data,0,data.Length);
                var output = signer.GenerateSignature();
                //var first = rsa.DecryptValue(rawSignature);
                var first = rsa.VerifyData(data,rawSignature,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
                var second = rsa.VerifyData(data_full,rawSignature,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
            }
            return false;
        }

        public static bool VerifyCert(X509Certificate2 cert)
        {
            // Create a chain object
            var chain = new X509Chain();
            // Create a policy that allows using custom root cert
            X509ChainPolicy chainPolicy = new X509ChainPolicy()
            {
                TrustMode = X509ChainTrustMode.CustomRootTrust
            };
            // put the chain policy in the chain object
            chain.ChainPolicy = chainPolicy;
            // Put the cert in the custom root
            chain.ChainPolicy.CustomTrustStore.Add(cert);
            // build the chain - verify self signed cert in the process
            if (!chain.Build(cert))
            {
                foreach (X509ChainElement chainElement in chain.ChainElements)
                {
                    foreach (X509ChainStatus chainStatus in chainElement.ChainElementStatus)
                    {
                        Console.WriteLine(chainStatus.StatusInformation);
                    }
                }
            }
            return chain.Build(cert);
        }

        static void Main(string[] args)
        {
            Console.WriteLine($"args {args[0]}");
            X509Certificate2 cert;
            using (RSA rsa = RSA.Create())
            {
                rsa.KeySize = 2048;
                var req = new CertificateRequest("cn=foobar", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                cert = req.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(5));
                var certBytes = cert.GetRawCertData();
                var key  = cert.GetRSAPrivateKey().ExportRSAPrivateKey();
                var pemCoded = PemEncoding.Write("CERTIFICATE",certBytes);
                var pemCodedKey = PemEncoding.Write("RSA PRIVATE KEY",key);
                File.WriteAllText("coded.pem",new string(pemCoded));
                File.WriteAllText("private_key.pem",new string(pemCodedKey));
                var cert_from_file = X509Certificate2.CreateFromPemFile("coded.pem", "private_key.pem");
                var cert_from_chararr = X509Certificate2.CreateFromPem(pemCoded,pemCodedKey);
                var expCert = cert.Export( X509ContentType.Cert );
                var pemCodedCert = PemEncoding.Write("CERTIFICATE",certBytes);
                //File.WriteAllText("coded-cert.pem",new string(pemCoded));
                //var cert_from_file_exp = X509Certificate2.CreateFromPemFile("coded-cert.pem", "private_key.pem");
                //var res = SimpleVerify(cert_from_file_exp);
            };
            //Create X509Certificate2 object from .cer file.
            byte[] rawData = ReadFile("coded-cert.pem");
            byte[] garbledData = ReadFile("garbled.pem");
            X509Certificate2 x509 = new X509Certificate2(rawData);
            X509Certificate2 garbled = new X509Certificate2(garbledData);
            //x509.Import(rawData);
            var pkey = x509.GetRSAPrivateKey();
            //Print to console information contained in the certificate.
            Console.WriteLine("{0}Subject: {1}{0}", Environment.NewLine, x509.Subject);
            Console.WriteLine("{0}Issuer: {1}{0}", Environment.NewLine, x509.Issuer);
            Console.WriteLine("{0}Version: {1}{0}", Environment.NewLine, x509.Version);
            Console.WriteLine("{0}Valid Date: {1}{0}", Environment.NewLine, x509.NotBefore);
            Console.WriteLine("{0}Expiry Date: {1}{0}", Environment.NewLine, x509.NotAfter);
            Console.WriteLine("{0}Thumbprint: {1}{0}", Environment.NewLine, x509.Thumbprint);
            Console.WriteLine("{0}Serial Number: {1}{0}", Environment.NewLine, x509.SerialNumber);
            Console.WriteLine("{0}Friendly Name: {1}{0}", Environment.NewLine, x509.PublicKey.Oid.FriendlyName);
            Console.WriteLine("{0}Public Key Format: {1}{0}", Environment.NewLine, x509.PublicKey.EncodedKeyValue.Format(true));
            Console.WriteLine("{0}Raw Data Length: {1}{0}", Environment.NewLine, x509.RawData.Length);
            Console.WriteLine("{0}Certificate to string: {1}{0}", Environment.NewLine, x509.ToString(true));
            Console.WriteLine("{0}Certificate to XML String: {1}{0}", Environment.NewLine, x509.PublicKey.Key.ToXmlString(false));
            
            
            var x = VerifyCert(x509);
            var y = VerifyCert(cert);
            var z = VerifyCert(garbled); // <-certificate signature failure!

            // Create a chain object
            var chain = new X509Chain();
            // Create a policy that allows using custom root cert
            X509ChainPolicy chainPolicy = new X509ChainPolicy()
            {
                TrustMode = X509ChainTrustMode.CustomRootTrust
            };
            // put the chain policy in the chain object
            chain.ChainPolicy = chainPolicy;
            // Put the cert in the custom root
            chain.ChainPolicy.CustomTrustStore.Add(x509);
            // build the chain - verify self signed cert in the process
            var result = chain.Build(x509);
            if (!chain.Build(x509))
            {
                foreach (X509ChainElement chainElement in chain.ChainElements)
                {
                    foreach (X509ChainStatus chainStatus in chainElement.ChainElementStatus)
                    {
                        Console.WriteLine(chainStatus.StatusInformation);
                    }
                }
            }
            var whatever = x509.Verify();
            using (RSA rsa = RSA.Create(2048)){
                Console.WriteLine(Convert.ToBase64String(rsa.ExportRSAPrivateKey()));
                Console.WriteLine(Convert.ToBase64String(rsa.ExportRSAPublicKey()));
                var pemChars = File.ReadAllText("private_key.pem").ToCharArray();
                rsa.ImportFromPem(pemChars);
                Console.WriteLine(Convert.ToBase64String(rsa.ExportRSAPrivateKey()));
                Console.WriteLine(Convert.ToBase64String(rsa.ExportRSAPublicKey()));
                int bytesRead;
                rsa.ImportRSAPublicKey(x509.GetRSAPublicKey().ExportRSAPublicKey(),out bytesRead);
                Console.WriteLine(Convert.ToBase64String(rsa.ExportRSAPublicKey()));
            }
        }

        internal static byte[] ReadFile (string fileName)
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
