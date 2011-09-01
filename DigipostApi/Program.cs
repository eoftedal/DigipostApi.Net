using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace DigipostApi
{
    class Program
    {
        private const int _avsenderId = 1;
        private const bool _smsVarsling = false;
        private const string _hostnavn = "https://api.digipost.no";

        static void Main(string[] args)
        {
            X509Certificate2 sertifikat = GetCert();

            var sender = new DigipostSender(_hostnavn, sertifikat, _avsenderId, _smsVarsling);

            var forsendelsesId = Guid.NewGuid().ToString();
            var digipostAdresse = "ola.nordmann#123";
            var emne = "Tittel på forsendelsen";
            var pdf = File.ReadAllBytes(@"c:\path\til\pdf");

            sender.Send(forsendelsesId, digipostAdresse, emne, pdf);

        }

        private static X509Certificate2 GetCert()
        {
           return new X509Certificate2(@"c:\path\til\sertifikat.p12", "Passord", X509KeyStorageFlags.Exportable);

        }
        
    }
}
