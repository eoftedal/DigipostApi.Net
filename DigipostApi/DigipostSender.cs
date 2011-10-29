using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Web;
using System.Xml;
using System.Xml.Linq;
using System.Xml.XPath;
using System.Diagnostics;

namespace DigipostApi
{
    public class DigipostSender
    {
        private readonly bool _smsVarsling;
        private readonly X509Certificate2 _sertifikat;
        private readonly int _avsenderId;
        private readonly XmlNamespaceManager _namespaceMgr;
        private readonly string _host;
        private const String _digipostXml = "application/vnd.digipost-v1+xml";
        private const String _namespace = "http://api.digipost.no/schema/v1";

        public DigipostSender(string host, X509Certificate2 sertifikat, int avsenderId, bool smsVarsling)
        {
            _smsVarsling = smsVarsling;
            _sertifikat = sertifikat;
            _avsenderId = avsenderId;
            _namespaceMgr = new XmlNamespaceManager(new NameTable());
            _namespaceMgr.AddNamespace("dp", _namespace);
            _host = host;
        }


        public bool Send(string forsendelsesId, string digipostAdresse, string emne, byte[] fil)
        {
            var forsendelsesUrl = GetUrlForCreatingMessage();
            var url = CreateMessage(forsendelsesUrl, forsendelsesId, digipostAdresse, emne);
            var request = (HttpWebRequest)WebRequest.Create(url);
            SetHeaders("POST", request, "application/octet-stream", fil);
            using (var stream = request.GetRequestStream())
            {
                stream.Write(fil, 0, fil.Length);
            }
            var xml = SendAndGetXml(request);
            return xml.XPathSelectElement("//dp:status[.='DELIVERED']", _namespaceMgr) != null;

        }
        private string GetUrlForCreatingMessage()
        {
            var request = (HttpWebRequest)WebRequest.Create(_host + "/");
            SetHeaders("GET", request, _digipostXml, new byte[0]);
            var xml = SendAndGetXml(request);
            return ExtractUriFromLink("/relations/create_message", xml);
        }


        private string CreateMessage(string forsendelsesUrl, string forsendelsesId, string digipostAdresse, string emne)
        {
            var request = (HttpWebRequest)WebRequest.Create(forsendelsesUrl);
            var forsendelse = GetXml(forsendelsesId, digipostAdresse, emne);
            var body = Encoding.UTF8.GetBytes(forsendelse.Declaration + "\n" + forsendelse);
            SetHeaders("POST", request, _digipostXml, body);
            using (var stream = request.GetRequestStream())
            {
                stream.Write(body, 0, body.Length);
            }
            var xml = SendAndGetXml(request);
            return ExtractUriFromLink("/relations/add_content_and_send", xml);
        }

        private String ExtractUriFromLink(String relEndsWith, XDocument xml)
        {
            var uriValue = xml.Descendants(XName.Get("link", _namespace))
                              .Where(l => l.Attribute("rel").Value.EndsWith(relEndsWith))
                              .Attributes("uri")
                              .First()
                              .Value;
            return uriValue;
        }

        private static XDocument SendAndGetXml(HttpWebRequest request)
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
                            throw new Exception(reader.ReadToEnd(), we);
                        }
                    }
                }
                throw;
            }
        }



        private XDocument GetXml(string forsendelsesId, string digipostAdresse, string emne)
        {
            XNamespace xmlns = _namespace;
            var doc = new XDocument(new XDeclaration("1.0", "UTF-8", "yes"),
                new XElement(xmlns + "message",
                        new XElement(xmlns + "messageId", forsendelsesId),
                        new XElement(xmlns + "subject", emne),
                        new XElement(xmlns + "digipostAddress", digipostAdresse),
                        new XElement(xmlns + "smsNotification", _smsVarsling)
                    )
                );
            return doc;
        }


        private void SetHeaders(String method, HttpWebRequest request, string contentType, byte[] body)
        {
            request.Method = method;
            request.ContentType = contentType;
            request.Accept = _digipostXml;
            request.Headers.Add("X-Digipost-UserId", _avsenderId.ToString());
            request.Date = DateTime.Now;
            request.Headers.Add("Content-MD5", Convert.ToBase64String(MD5.Create().ComputeHash(body)));
            SignRequest(request, _sertifikat);
        }
        private static void SignRequest(HttpWebRequest request, X509Certificate2 cert)
        {
            var s = request.Method.ToUpper() + "\n" +
                    request.RequestUri.AbsolutePath.ToLower() + "\n" +
                    "content-md5: " + request.Headers["Content-MD5"] + "\n" +
                    "date: " + request.Date.ToUniversalTime().ToString("r") + "\n" +
                    "x-digipost-userid: " + request.Headers["X-Digipost-UserId"] + "\n" +
                    HttpUtility.UrlEncode(request.RequestUri.Query).ToLower() + "\n";

            var rsa = cert.PrivateKey as RSACryptoServiceProvider;
            var privateKeyBlob = rsa.ExportCspBlob(true);
            var rsa2 = new RSACryptoServiceProvider();
            rsa2.ImportCspBlob(privateKeyBlob);

            var sha = SHA256.Create();
            var hash = sha.ComputeHash(Encoding.UTF8.GetBytes(s));
            var signature = rsa2.SignHash(hash, CryptoConfig.MapNameToOID("SHA256"));
            request.Headers.Add("X-Digipost-Signature", Convert.ToBase64String(signature));
        }
    }
}

