using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace crypto2
{
    class Program
    {
        
       
        static void Main(string[] args)
        {
            Console.WriteLine($"args {args[0]}");
            using (RSA rsa = RSA.Create())
            {
                rsa.KeySize = 2048;
                var req = new CertificateRequest("cn=foobar", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                var cert = req.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(5));
                var certBytes = cert.GetRawCertData();
                var key  = cert.GetRSAPrivateKey().ExportRSAPrivateKey();
                var pemCoded = PemEncoding.Write("CERTIFICATE",certBytes);
                var pemCodedKey = PemEncoding.Write("RSA PRIVATE KEY",key);
                File.WriteAllText("coded.pem",new string(pemCoded));
                File.WriteAllText("private_key.pem",new string(pemCodedKey));
                var cert_from_file = X509Certificate2.CreateFromPemFile("coded.pem", "private_key");
                var cert_from_chararr = X509Certificate2.CreateFromPem(pemCoded,pemCodedKey);
            };
        }
    }
}
