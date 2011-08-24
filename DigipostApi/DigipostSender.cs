using System;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Web;
using System.Xml;
using System.Xml.Linq;
using System.Xml.XPath;

namespace DigipostApi
{


    public class DigipostSender
    {
        private readonly bool _smsVarsling;
        private readonly X509Certificate2 _sertifikat;
        private readonly int _avsenderId;
        private readonly XmlNamespaceManager _namespaceMgr;
        private readonly string _host;
        public DigipostSender(string host, X509Certificate2 sertifikat, int avsenderId, bool smsVarsling)
        {
            _smsVarsling = smsVarsling;
            _sertifikat = sertifikat;
            _avsenderId = avsenderId;
            _namespaceMgr = new XmlNamespaceManager(new NameTable());
            _namespaceMgr.AddNamespace("dp", "http://www.digipost.no/xsd/avsender1_3");
            _host = host;
        }


        public bool Send(string forsendelsesId, string kundeId, string digipostAdresse, string emne, byte[] fil)
        {
            var url = OpprettForsendelse(forsendelsesId, kundeId, digipostAdresse, emne);
            var request = (HttpWebRequest)WebRequest.Create(url);
            SetHeaders(request, "application/octet-stream", fil);
            using (var stream = request.GetRequestStream())
            {
                stream.Write(fil, 0, fil.Length);
            }
            var xml = PostAndGetXml(request);
            return xml.XPathSelectElement("//dp:status[.='LEVERT']", _namespaceMgr) != null;

        }

        private string OpprettForsendelse(string forsendelsesId, string kundeId, string digipostAdresse, string emne)
        {
            var request = (HttpWebRequest)WebRequest.Create(_host + "/forsendelse");
            var forsendelse = GetXml(forsendelsesId, kundeId, digipostAdresse, emne);
            var body = Encoding.UTF8.GetBytes(forsendelse.Declaration + "\n" + forsendelse);
            SetHeaders(request, "application/vnd.digipost+xml", body);
            using (var stream = request.GetRequestStream())
            {
                stream.Write(body, 0, body.Length);
            }
            var xml = PostAndGetXml(request);
            return xml.XPathSelectElement("//dp:links/dp:rel[.='Legg til innhold']/../dp:uri", _namespaceMgr).Value;
        }
        private XDocument PostAndGetXml(HttpWebRequest request)
        {
            try
            {
                using (var response = request.GetResponse())
                {
                    using (var reader = new StreamReader(response.GetResponseStream()))
                    {
                        return XDocument.Parse(reader.ReadToEnd());
                    }
                }
            }
            catch (WebException we)
            {
                if (we.Response != null)
                {
                    using (var response = we.Response)
                    {
                        using (var reader = new StreamReader(response.GetResponseStream()))
                        {
                            string s = reader.ReadToEnd();
                            throw new Exception(s, we);
                        }
                    }
                }
                throw;
            }
        }



        private XDocument GetXml(string forsendelsesId, string kundeId, string digipostAdresse, string emne)
        {
            XNamespace xmlns = "http://www.digipost.no/xsd/avsender1_3";
            var doc = new XDocument(new XDeclaration("1.0", "UTF-8", "yes"),
                new XElement(xmlns + "enkeltforsendelse",
                        new XElement(xmlns + "forsendelseId", forsendelsesId),
                        new XElement(xmlns + "emne", emne),
                        new XElement(xmlns + "mottaker",
                            new XElement(xmlns + "kunde-id", kundeId),
                            new XElement(xmlns + "digipostadresse", digipostAdresse)
                        ),
                        new XElement(xmlns + "smsVarsling", _smsVarsling)
                    )
                );
            return doc;
        }


        private void SetHeaders(HttpWebRequest request, string contentType, byte[] body)
        {
            request.Method = "POST";
            request.ContentType = contentType;
            request.Headers.Add("X-Digipost-UserId", _avsenderId.ToString());
            request.Headers.Add("X-Digipost-Date", DateTime.Now.AddHours(-2).ToString("r"));
            request.Headers.Add("Content-MD5", Convert.ToBase64String(MD5.Create().ComputeHash(body)));
            SignRequest(request, _sertifikat);
        }
        private void SignRequest(HttpWebRequest request, X509Certificate2 cert)
        {
            String s = request.Method.ToUpper() + "\n" +
                       request.RequestUri.AbsolutePath.ToLower() + "\n" +
                       "content-md5: " + request.Headers["Content-MD5"] + "\n" +
                       "x-digipost-date: " + request.Headers["X-Digipost-Date"] + "\n" +
                       "x-digipost-userid: " + request.Headers["X-Digipost-UserId"] + "\n" +
                       HttpUtility.UrlEncode(request.RequestUri.Query).ToLower() + "\n";

            var rsa = cert.PrivateKey as RSACryptoServiceProvider;
            byte[] privateKeyBlob = rsa.ExportCspBlob(true);
            var rsa2 = new RSACryptoServiceProvider();
            rsa2.ImportCspBlob(privateKeyBlob);

            var sha = SHA256.Create();
            var hash = sha.ComputeHash(Encoding.UTF8.GetBytes(s));
            var signature = rsa2.SignHash(hash, CryptoConfig.MapNameToOID("SHA256"));
            request.Headers.Add("X-Digipost-Signature", Convert.ToBase64String(signature));
        }

    }
}

