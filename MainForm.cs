﻿using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Security.Cryptography.Xml;
using System.Net.Http;
using System.Net.Http.Headers;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.IO;

namespace TestHDFC
{

    /// <summary>
    /// {
    ///     "RequestSignatureEncryptedValue": "",   -----This will contain the base64 encoded encrypted value of IV + digitally signed XML request sample.
    ///     "SymmetricKeyEncryptedValue": "",       -----This will contain the base64 encoded encrypted value of a 32 byte symmetric key used for encrypting above parameter.
    ///     "Scope": "",                            -----This field should be the exact value which was set on the HDFC Bank’s API portal while registering the consumer 
    ///                                                  application and indicates which external partner is invoking the API.
    ///     "TransactionId": "",                    -----External partners need to set a transaction ID to uniquely identify every request, in order to retrieve it from 
    ///                                                  an audit trail at a later date.
    ///     "OAuthTokenValue": ""                   -----This value can be obtained by invoking HDFC Bank token generator service.
    /// }

    /// </summary>
    public partial class MainForm : Form
    {
        //////////////////////////////////////////
        //UnicodeEncoding _encoder = new UnicodeEncoding();
        //ASCIIEncoding _encoder = new ASCIIEncoding();
        UTF8Encoding _encoder = new UTF8Encoding();

        XmlDocument xmlBeforeSign = null;
        //XmlDocument xmlAfterSign = null;


        //* declaring instance variables here for limiting key to a-z, A-Z, 0-9
        private int VAR1 = 'a';
        private int VAR2 = 'z';
        private int VAR3 = 'A';
        private int VAR4 = 'Z';
        private int ZERO = '0';
        private int NINE = '9';

        //Declaring IV(16 Bytes)
        private byte[] IVECTOR = Encoding.UTF8.GetBytes("1234567890123456");

        String pfxcertificatePassword = "3ULgZwn4dFM5xqmWsU2S";
        String pfxcertificateFile = AppDomain.CurrentDomain.BaseDirectory + "elantas-sap-hdfc-bank.altana.com-20220517.pfx";
        String pemcertificateFile = AppDomain.CurrentDomain.BaseDirectory + "elantas-sap-hdfc-bank.altana.com-20220517.pem";
        //Does not work  when checking for signing
        //elantas-sap-hdfc-bank.altana.com__0.pem
        //elantas-sap-hdfc-bank.altana.com.pem
        //elantas-sap-hdfc-bank.altana.com_.pem
        //elantas-sap-hdfc-bank.altana.com-20220517.pem
        //cert3.cer
        //Cert3-Leaf certificate.txt

        //For following public & private key do not match
        //api-uat_hdfcbank_com_Leaf.txt
        //api-uat_hdfcbank_com_intermidiate.txt
        //Cert3-Leaf certificate.txt
        //api-uat_hdfcbank_com_Root.txt
        //cert1.cer
        //cert2.cer
        //Cert1.txt
        //Cert2.txt
        //Certificate (2).txt

        String keyFile = AppDomain.CurrentDomain.BaseDirectory + "elantas-sap-hdfc-bank.altana.com-20220517.key";
        String rootcertificateFile = AppDomain.CurrentDomain.BaseDirectory + "api-uat_hdfcbank_com_Root.txt";
        String leafcertificateFile = AppDomain.CurrentDomain.BaseDirectory + "api-uat_hdfcbank_com_Leaf.txt"; //"Cert3-Leaf certificate.txt";
        String intermediatecertificateFile = AppDomain.CurrentDomain.BaseDirectory + "api-uat_hdfcbank_com_intermidiate.txt";


        string client_id = "vsb6C5H4tWS5hFjI2c6CpVlCETb3Je9L6jALpG1qBDuA8QW4";
        string client_secret = "aSt1b5W31nrIHMsYYuwPb7rJAPWKqG8CA5Zh7p0OZa3nOwI91aI335CgW7egoPaM";

        String oAuthTokenURL = @"https://api-uat.hdfcbank.com:443/auth/oauth/v2/token?grant_type=client_credentials&scope=FCAT_ELANTA";
        String neftTransferURL = @"https://api-uat.hdfcbank.com:443/API/NEFTPayment";
        String neftInquiryURL = @"https://api-uat.hdfcbank.com/API/NEFTInquiry";

        //this is RequestSignatureEncryptedValue
        private byte[] encryptedData;
        String encodedData = String.Empty;

        //this is SymmetricKeyEncryptedValue
        byte[] encryptionKeyBytes = new byte[32];
        String encryptedencodedKey = String.Empty;
        //this is scope
        String Scope = "FCAT_ELANTAS";
        //this is TransactionId
        String TransactionId = "1111";
        //this is OAuthTokenValue
        OAuthToken oAuthToken;

        public MainForm()
        {
            InitializeComponent();
        }

        public X509Certificate2 GetCertificateFromPEM_KEY(string pass = "")
        {
            X509Certificate2 certificate = null;
            try
            {
                string pemText = string.Empty;
                string keyText = string.Empty;

                using (TextReader tr = new StreamReader(pemcertificateFile))
                {
                    pemText = tr.ReadToEnd();
                }

                using (TextReader tr = new StreamReader(keyFile))
                {
                    keyText = tr.ReadToEnd();
                }
                Certificate cert = new Certificate(pemText, keyText, pass);

                certificate = cert.GetCertificateFromPEMstring(false);
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }
            return certificate;
        }

        public RSACryptoServiceProvider ReadPrivateKeyFile()
        {
            string keyText = string.Empty;
            using (TextReader tr = new StreamReader(keyFile))
            {
                keyText = tr.ReadToEnd();
            }
            Certificate cert = new Certificate("", keyText, "");
            RSACryptoServiceProvider rsa = cert.GetPrivateKeyData(keyText);

            return rsa;
        }

        //public  XmlDocument SignXml()
        //{
        //    XmlDocument doc = new XmlDocument();

        //    String idString = RandomString(32); //GenerateAlphaNumericId(32);

        //    //Now get the faxml node from beforesignxml to add id attribute as well as signatureElement
        //    XmlNode faxmlNode = xmlBeforeSign.SelectSingleNode("//faxml");
        //    XmlAttribute idAttr = xmlBeforeSign.CreateAttribute("Id");
        //    idAttr.Value = idString;
        //    faxmlNode.Attributes.Append(idAttr);

        //    RSACryptoServiceProvider rsa = ReadPrivateKeyFile();

        //    var signedXml = new SignedXml(xmlBeforeSign);
        //    signedXml.SigningKey = cert.PrivateKey; //cert.GetRSAPrivateKey();
        //    signedXml.SignedInfo.SignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
        //    signedXml.SignedInfo.CanonicalizationMethod = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";

        //}

        public void NewSignPayloadXML()
        {
            if (xmlBeforeSign == null)
                throw new ArgumentException(nameof(xmlBeforeSign));

            String idString = RandomString(32); //GenerateAlphaNumericId(32);

            //Add the request node as root node
            XmlElement requestAfterElement = xmlBeforeSign.CreateElement("request");

            //Now get the faxml node from beforesignxml to add id attribute as well as signatureElement
            XmlNode faxmlNode = xmlBeforeSign.SelectSingleNode("//faxml");
            XmlAttribute idAttr = xmlBeforeSign.CreateAttribute("Id");
            idAttr.Value = idString;
            faxmlNode.Attributes.Append(idAttr);

            //add the faxml node to request element
            requestAfterElement.AppendChild(faxmlNode);
            xmlBeforeSign.AppendChild(requestAfterElement);
            //X509Certificate2 cert = new X509Certificate2(pfxcertificateFile, pfxcertificatePassword);
            X509Certificate2 cert = GetCertificateFromPEM_KEY(pfxcertificatePassword);

            //RSA prov = ReadPrivateKeyFile();

            var signedXml = new SignedXml(xmlBeforeSign); //(xmlBeforeSign.DocumentElement);
            signedXml.SigningKey = cert.GetRSAPrivateKey();

            Signature XMLSignature = signedXml.Signature;

            signedXml.SignedInfo.SignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
            signedXml.SignedInfo.CanonicalizationMethod = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";

            var reference = new Reference();
            reference.Uri = "#" + idString;

            //signedXml.AddReference(reference);
            XMLSignature.SignedInfo.AddReference(reference);

            var keyInfo = new KeyInfo();
            var keyData = new KeyInfoX509Data(cert);
            keyData.AddSubjectName(cert.SubjectName.Name);

            //keyInfo.AddClause(new KeyInfoX509Data(cert));
            keyInfo.AddClause(keyData);

            XMLSignature.KeyInfo = keyInfo;
            //signedXml.KeyInfo = keyInfo;

            signedXml.ComputeSignature();

            XmlElement xmlDigitalSignature = signedXml.GetXml();

            // Append the element to the XML document.
            xmlBeforeSign.DocumentElement.InsertAfter(xmlBeforeSign.ImportNode(xmlDigitalSignature, true), faxmlNode);

            //XmlElement requestAfterElement = xmlBeforeSign.CreateElement("request");
            //add the faxml node to request element
            //requestAfterElement.AppendChild(faxmlNode);
            //xmlBeforeSign.AppendChild(requestAfterElement);

            //xmlBeforeSign.DocumentElement?.AppendChild(signedXml.GetXml());
        }

        public void GenerateSymmetricKey()
        {
            //RandomNumberGenerator random = RandomNumberGenerator.Create();
            //random.GetBytes(encryptionKeyBytes, 0, 32);
            Random random = new Random();
            StringBuilder key = new StringBuilder();
            while (key.Length < 32)
            {
                int character = random.Next(128);
                if ((character <= VAR2 && character >= VAR1) || (character <= VAR4 && character >= VAR3) || (character <= NINE && character >= ZERO))
                {
                    key.Append((char)character);
                }
            }
            Array.Copy(_encoder.GetBytes(key.ToString()), encryptionKeyBytes, 32);
        }

        private string RandomString(int StringLength)
        {

            Random RNG = new Random();
            int length = StringLength;
            var rString = "";
            for (var i = 0; i < length; i++)
            {
                rString += ((char)(RNG.Next(1, 26) + 64)).ToString().ToLower();
            }
            return rString;
        }

        /// <summary>
        /// This alphanumeric key will be used to encrypt the data. It will also be sent to HDFC in 2nd parameter of JSON
        /// We generate random integer that is less than the specified maximum
        ///     We make sure that this number lies in a-z or A-Z or 0-9. We have to make sure that there are no special characters. Only allowed are a-z or A-Z or 0-9
        ///     We append each valid number to key
        ///  We return the generate string as key to be used in encryption
        ///  This key is also added as value of ID attribute faxml/faml tag (refer to HDFC doc page 9
        ///  
        ///  The same key is also sent to API in 2nd parameter
        /// </summary>
        /// <param name="keySize">size of the key</param>
        /// <returns>gnerated random number of keySize length</returns>
        public String GenerateAlphaNumericId(int keySize = 32)
        {
            Random random = new Random();
            StringBuilder key = new StringBuilder();
            while (key.Length < keySize)
            {
                int character = random.Next(128);
                if ((character <= VAR2 && character >= VAR1) || (character <= VAR4 && character >= VAR3) || (character <= NINE && character >= ZERO))
                {
                    key.Append((char)character);
                }
            }
            return key.ToString();
        }



        public byte[] NewEncryptSignedXML(String toEncrypt, byte[] key)
        {
            if (string.IsNullOrEmpty(toEncrypt)) throw new ArgumentException("toEncrypt");
            if (key == null || key.Length == 0) throw new ArgumentException("key");
            var toEncryptBytes = Encoding.UTF8.GetBytes(toEncrypt);

            using (var provider = new AesCryptoServiceProvider())
            {
                provider.Key = key;
                //provider.GenerateIV();
                provider.IV = _encoder.GetBytes(RandomString(16));
                provider.Mode = CipherMode.CBC;
                provider.Padding = PaddingMode.PKCS7;
                using (var encryptor = provider.CreateEncryptor(provider.Key, provider.IV))
                {
                    using (var ms = new MemoryStream())
                    {
                        ms.Write(provider.IV, 0, 16);
                        using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                        {
                            cs.Write(toEncryptBytes, 0, toEncryptBytes.Length);
                            cs.FlushFinalBlock();
                        }
                        return ms.ToArray();
                    }
                }
            }

        }

        public static string NewDecryptSignedXML(byte[] encryptedString, byte[] encryptionKey)
        {
            using (var provider = new AesCryptoServiceProvider())
            {
                provider.Key = encryptionKey;
                provider.Mode = CipherMode.CBC;
                provider.Padding = PaddingMode.PKCS7;
                using (var ms = new MemoryStream(encryptedString))
                {
                    byte[] buffer = new byte[16];
                    ms.Read(buffer, 0, 16);
                    provider.IV = buffer;
                    using (var decryptor = provider.CreateDecryptor(provider.Key, provider.IV))
                    {
                        using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                        {
                            byte[] decrypted = new byte[encryptedString.Length];
                            var byteCount = cs.Read(decrypted, 0, encryptedString.Length);
                            return Encoding.UTF8.GetString(decrypted, 0, byteCount);
                        }
                    }
                }
            }
        }
        public String EncodeByteArrayToBase64String(byte[] value)
        {
            String encryptedText = Convert.ToBase64String(value);
            return encryptedText;
        }

        private void btnSign_Click(object sender, EventArgs e)
        {
            if (xmlBeforeSign != null)
            {
                NewSignPayloadXML();
                //NewSignPayloadXML();
                tbSignedXml.Text = xmlBeforeSign.InnerXml;
            }
        }
        private void btnEncryptEncodeData_Click(object sender, EventArgs e)
        {
            //Now generate a key for encryption
            //GenerateSymmetricKey();
            encryptionKeyBytes = _encoder.GetBytes(RandomString(32));
            tbKey.Text = EncodeByteArrayToBase64String(encryptionKeyBytes);

            encryptedData = NewEncryptSignedXML(xmlBeforeSign.InnerXml, encryptionKeyBytes);

            //tbEncrypted.Text = Encoding.ASCII.GetString(encryptedData);
            tbEncrypted.Text = _encoder.GetString(encryptedData);

            //encode encrypted data
            encodedData = EncodeByteArrayToBase64String(encryptedData);
            tbEncoded.Text = encodedData.ToString();


            //Verify
            //Decode
            byte[] decodedData = Convert.FromBase64String(encodedData);
            if(decodedData.Equals(encryptedData))
            {
                MessageBox.Show("Decoding matches");
            }

            string tmpDecryptedXML = NewDecryptSignedXML(decodedData, encryptionKeyBytes);

            if (tmpDecryptedXML.Equals(xmlBeforeSign.InnerXml) == true)
            {
                MessageBox.Show("Encryption = decryption");
            }
            else
            {
                MessageBox.Show("Encryption != Decryption");
            }

            //Check signature 
            XmlDocument xmlSigndDocument = new XmlDocument();
            xmlSigndDocument.PreserveWhitespace = true;
            xmlSigndDocument.LoadXml(tmpDecryptedXML);
            var signedXml = new SignedXml(xmlSigndDocument);
            // double-check the schema
            // usually we would validate using XPath
            XmlNodeList signatureElement = xmlSigndDocument.GetElementsByTagName("Signature");
            if (signatureElement.Count != 1)
            {
                MessageBox.Show("Too many signatures");
            }

            signedXml.LoadXml((XmlElement)signatureElement[0]);

            // validate references here!
            XmlNode faxmlNode = xmlSigndDocument.SelectSingleNode("//faxml");
            string idattrib = "#" + faxmlNode.Attributes["Id"].Value;

            if ((signedXml.SignedInfo.References[0] as Reference)?.Uri != idattrib)
            { 
                MessageBox.Show("Check your references!");
            }

            //X509Certificate2 cert = new X509Certificate2(pfxcertificateFile, pfxcertificatePassword);
            X509Certificate2 cert = GetCertificateFromPEM_KEY();
            bool isValid = signedXml.CheckSignature(cert, true);

            if(isValid == false)
            {
                MessageBox.Show("Signature verification failed");
            }
            else
            {
                MessageBox.Show("Signature verification passed");
            }
        }

        public void OldNewEncryptionEncodeSymmetricKey()
        {
            X509Certificate2 cert = new X509Certificate2(leafcertificateFile);

            RSA rsa = cert.GetRSAPublicKey();
            byte[] encryptedKey = rsa.Encrypt(encryptionKeyBytes, RSAEncryptionPadding.Pkcs1);

            tbEncryptedKey.Text = _encoder.GetString(encryptedKey);

            encryptedencodedKey = EncodeByteArrayToBase64String(encryptedKey);
            tbEncodedKey.Text = encryptedencodedKey;

        }

        public void NewEncryptionEncodeSymmetricKey()
        {
            string certName = leafcertificateFile; //@"D:\OneDrive - onamagroup.com\HDFC_Integration\Certificates\NEW_21_July_2022\Certificates\cert3.cer";
            string pass = "";  //pfxcertificatePassword;
            X509Certificate2 cert = new X509Certificate2(certName, pass);

            RSACryptoServiceProvider csp = new RSACryptoServiceProvider();
            RSAParameters rsaParam = cert.GetRSAPublicKey().ExportParameters(false);

            csp.ImportParameters(rsaParam);

            byte[] encryptedKey = csp.Encrypt(encryptionKeyBytes, RSAEncryptionPadding.Pkcs1);
            tbEncryptedKey.Text = _encoder.GetString(encryptedKey);

            encryptedencodedKey = EncodeByteArrayToBase64String(encryptedKey);
            tbEncodedKey.Text = encryptedencodedKey;

        }

        public String DecryptDecodeSymmetricKey()
        {
            byte[] decodedKey = Convert.FromBase64String(encryptedencodedKey);

            X509Certificate2 cert = new X509Certificate2(pemcertificateFile);

            RSACryptoServiceProvider _rsaprovider = new RSACryptoServiceProvider();
            _rsaprovider.ImportParameters(cert.GetRSAPublicKey().ExportParameters(false));

            byte[] decryptedKey = _rsaprovider.Decrypt(decodedKey, RSAEncryptionPadding.Pkcs1);

            return EncodeByteArrayToBase64String(decryptedKey);
        }

        private void btnEncryptGeneratedKey_Click(object sender, EventArgs e)
        {
            NewEncryptionEncodeSymmetricKey();
            //string decryptedKey = DecryptDecodeSymmetricKey();
            //tbDecryptedKey.Text = decryptedKey;
            return;

            //X509Certificate2 cert = new X509Certificate2(pfxcertificateFile, pfxcertificatePassword);
            X509Certificate2 cert = new X509Certificate2(pemcertificateFile);

            //RSACryptoServiceProvider _rsaprovider = (RSACryptoServiceProvider)cert.PublicKey.Key;
            //byte[] encryptedKey = _rsaprovider.Encrypt(_encoder.GetBytes(encryptionKey), RSAEncryptionPadding.Pkcs1);

            //trial works so keeping this
            RSA rsaEncrypt = cert.GetRSAPublicKey();
            byte[] encryptedKey = rsaEncrypt.Encrypt(encryptionKeyBytes, RSAEncryptionPadding.Pkcs1);


            tbEncryptedKey.Text = _encoder.GetString(encryptedKey);

            encryptedencodedKey = EncodeByteArrayToBase64String(encryptedKey);
            tbEncodedKey.Text = encryptedencodedKey;


            //verifying by decding & decrypting
            //decode the key
            byte[] tempdecodedkey = Convert.FromBase64String(encryptedencodedKey);

            //decrypt the key
            RSA rsaDecrypt = cert.GetRSAPrivateKey();

            byte[] temdecryptedkey = rsaDecrypt.Decrypt(tempdecodedkey, RSAEncryptionPadding.Pkcs1);
            string tempdecryptdecodeKey = _encoder.GetString(temdecryptedkey);
            tbDecryptedKey.Text = tempdecryptdecodeKey;
        }

        private void btnOpenXMLFile_Click(object sender, EventArgs e)
        {
            OpenFileDialog fileDialog = new OpenFileDialog();
            if (fileDialog.ShowDialog() == DialogResult.OK)
            {
                string sfileName = fileDialog.FileName;
                xmlBeforeSign = new XmlDocument();

                // Load an XML file into the XmlDocument object.
                //xmlBeforeSign.PreserveWhitespace = true;
                xmlBeforeSign.Load(sfileName);
                tbData.Text = xmlBeforeSign.InnerXml;
            }
        }


        private void btnOAuth_Click(object sender, EventArgs e)
        {
            try
            {
                var authenticationString = $"{client_id}:{client_secret}";
                //var base64EncodedAuthenticationString = Convert.ToBase64String(Encoding.UTF8.GetBytes(authenticationString));
                var base64EncodedAuthenticationString = EncodeByteArrayToBase64String(_encoder.GetBytes(authenticationString));

                //var certPassword = "3ULgZwn4dFM5xqmWsU2S";

                //X509Certificate2 cert = new X509Certificate2(AppDomain.CurrentDomain.BaseDirectory + "elantas-sap-hdfc-bank.altana.com-20220517.pfx", certPassword);
                X509Certificate2 cert = new X509Certificate2(pfxcertificateFile, pfxcertificatePassword);
                HttpClientHandler handler = new HttpClientHandler();
                handler.ClientCertificates.Add(cert);
                var client = new HttpClient(handler);
                //GetATokenToTestMyRestApiUsingHttpClient(client);
                //return;

                client.DefaultRequestHeaders.Clear();

                var postData = new List<KeyValuePair<string, string>>();
                //postData.Add(new KeyValuePair<string, string>("grant_type", "client_credentials"));
                //postData.Add(new KeyValuePair<string, string>("scope", "FCAT_ELANTA"));


                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", base64EncodedAuthenticationString);

                HttpContent content = new FormUrlEncodedContent(postData);
                content.Headers.ContentType = new MediaTypeHeaderValue("application/x-www-form-urlencoded");

                //var responseResult = client.PostAsync(@"https://api-uat.hdfcbank.com:443/auth/oauth/v2/token?grant_type=client_credentials&scope=FCAT_ELANTA", content).Result;
                var responseResult = client.PostAsync(oAuthTokenURL, content).Result;
                if (!responseResult.IsSuccessStatusCode)
                {
                    MessageBox.Show(responseResult.Content.ReadAsStringAsync().Result);
                    throw new HttpRequestException(responseResult.Content.ReadAsStringAsync().Result);
                }
                var jsonContent = responseResult.Content.ReadAsStringAsync().Result;
                oAuthToken = JsonConvert.DeserializeObject<TestHDFC.OAuthToken>(jsonContent);
                tbOauthToken.Text = "Access Token: " + oAuthToken.AccessToken.ToString() + Environment.NewLine + "Token Type: " + oAuthToken.TokenType.ToString() + Environment.NewLine +
                                    "Scope: " + oAuthToken.Scope.ToString() + Environment.NewLine + "Expires In: " + oAuthToken.ExpiresIn.ToString();
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }
        }

        /// <summary>
        /// THIS METHOD IS NOT USED. BUT THIS ALSO WORKS TO GET oAuth token
        /// See the implementation of button click which also works
        /// </summary>
        /// <param name="client"></param>
        /// <exception cref="HttpRequestException"></exception>
        private void GetATokenToTestMyRestApiUsingHttpClient(HttpClient client)
        {
            /* this code has lots of commented out stuff with different permutations of tweaking the request  */

            /* this is a version of asking for token using HttpClient.  aka, an alternate to using default libraries instead of RestClient */

            string grant_type = "client_credentials";
            string client_id = "vsb6C5H4tWS5hFjI2c6CpVlCETb3Je9L6jALpG1qBDuA8QW4";
            string client_secret = "aSt1b5W31nrIHMsYYuwPb7rJAPWKqG8CA5Zh7p0OZa3nOwI91aI335CgW7egoPaM";
            var authenticationString = $"{client_id}:{client_secret}";
            //var base64EncodedAuthenticationString = Convert.ToBase64String(System.Text.ASCIIEncoding.ASCII.GetBytes(authenticationString));
            var base64EncodedAuthenticationString = EncodeByteArrayToBase64String(_encoder.GetBytes(authenticationString));

            string scope = "FCAT_ELANTA";
            string url = @"https://api-uat.hdfcbank.com:443/auth/oauth/v2/token?grant_type=client_credentials&scope=FCAT_ELANTA";
            var form = new Dictionary<string, string>
                {
                    { "grant_type", grant_type},
                    { "scope", scope}
                };

            /* now tweak the http client */
            client.DefaultRequestHeaders.Clear();
            client.DefaultRequestHeaders.Add("cache-control", "no-cache");


            HttpRequestMessage req = new HttpRequestMessage(HttpMethod.Post, url);

            req.Content = new FormUrlEncodedContent(form);

            //following was not required, but i have kept it commented
            //req.Content.Headers.ContentType = new MediaTypeHeaderValue("application/x-www-form-urlencoded");
            req.Headers.Authorization = new AuthenticationHeaderValue("Basic", base64EncodedAuthenticationString);

            /* now make the request */
            ////HttpResponseMessage tokenResponse = await client.PostAsync(baseAddress, new FormUrlEncodedContent(form));
            HttpResponseMessage tokenResponse = client.SendAsync(req).Result;
            MessageBox.Show(string.Format("HttpResponseMessage.ReasonPhrase='{0}'", tokenResponse.ReasonPhrase));

            if (!tokenResponse.IsSuccessStatusCode)
            {
                throw new HttpRequestException(tokenResponse.Content.ReadAsStringAsync().Result);
            }

            var jsonContent = tokenResponse.Content.ReadAsStringAsync().Result;
            oAuthToken = JsonConvert.DeserializeObject<TestHDFC.OAuthToken>(jsonContent);

            //return tok;
        }

        private void btnCallHDFCApi_Click(object sender, EventArgs e)
        {
            TestHDFC.ResponsePayload responseData;

            var requestPayload = new RequestPayload
            {
                RequestSignatureEncryptedValue = encodedData,
                SymmetricKeyEncryptedValue = encryptedencodedKey,
                Scope = oAuthToken.Scope,
                TransactionId = TransactionId,
                OAuthTokenValue = oAuthToken.AccessToken
            };
            // Serialize our concrete class into a JSON String
            var stringPayload = JsonConvert.SerializeObject(requestPayload);

            // Wrap our JSON inside a StringContent which then can be used by the HttpClient class
            //var httpContent = new StringContent(stringPayload, Encoding.ASCII, "application/json");
            var httpContent = new StringContent(stringPayload);
            //httpContent.Headers.ContentType = new MediaTypeHeaderValue("application/x-www-form-urlencoded");
            httpContent.Headers.ContentType = new MediaTypeHeaderValue("application/json");


            X509Certificate2 cert = new X509Certificate2(pfxcertificateFile, pfxcertificatePassword);
            //X509Certificate2 cert = new X509Certificate2(pemcertificateFile);
            HttpClientHandler handler = new HttpClientHandler();
            handler.ClientCertificates.Add(cert);
            var client = new HttpClient(handler);

            client.DefaultRequestHeaders.Add("apikey", client_id);
            // Do the actual request and await the response
            var httpResponse = client.PostAsync(neftTransferURL, httpContent).Result;
            // If the response contains content we want to read it!
            if (httpResponse.Content != null)
            {
                var responseContent = httpResponse.Content.ReadAsStringAsync();

                // From here on you could deserialize the ResponseContent back again to a concrete C# type using Json.Net
                var jsonContent = httpResponse.Content.ReadAsStringAsync().Result;
                responseData = JsonConvert.DeserializeObject<TestHDFC.ResponsePayload>(jsonContent);

                tbHDFCResponse.Text = "ResponseSignatureEncryptedValue: " + responseData.ResponseSignatureEncryptedValue.ToString() + Environment.NewLine +
                    "GWSymmetricKeyEncryptedValue: " + responseData.GWSymmetricKeyEncryptedValue.ToString() + Environment.NewLine +
                    "Scope: " + responseData.Scope.ToString() + Environment.NewLine +
                    "TransactionId: " + responseData.TransactionId.ToString() + Environment.NewLine +
                    "Status" + responseData.Status.ToString();
            }
        }
        //public void SignPayloadXml()
        //{
        //    try
        //    {
        //        //you can use certificate2 or certificate. 
        //        //X509Certificate2 cert = new X509Certificate2(AppDomain.CurrentDomain.BaseDirectory + "elantas-sap-hdfc-bank.altana.com_.pem");
        //        //X509Certificate2 cert = new X509Certificate2(pemcertificateFile);
        //        X509Certificate2 cert = new X509Certificate2(pfxcertificateFile, pfxcertificatePassword);
        //        CspParameters cspParams = new CspParameters();
        //        cspParams.KeyContainerName = "XML_DSIG_RSA_KEY";

        //        // Create a new RSA signing key and save it in the container.
        //        RSACryptoServiceProvider rsaKey = new RSACryptoServiceProvider(32, cspParams);
        //        //RSACryptoServiceProvider rsaKey = new RSACryptoServiceProvider(cert.PublicKey.Key.KeySize, cspParams);
        //        String idString = GenerateAlphaNumericId(32);
        //        // Check arguments.
        //        if (xmlBeforeSign == null)
        //            throw new ArgumentException(nameof(xmlBeforeSign));

        //        // Create a SignedXml object.
        //        SignedXml signedXml = new SignedXml(xmlBeforeSign);

        //        // Add the key to the SignedXml document.
        //        //signedXml.SigningKey = rsaKey;// cert.PublicKey.Key;
        //        signedXml.SigningKey = cert.PublicKey.Key;// cert.PublicKey.Key;

        //        // Create a reference to be signed.
        //        Reference reference = new Reference();
        //        reference.Uri = "";

        //        //Add an enveloped transformation to the reference.
        //        //XmlDsigEnvelopedSignatureTransform env = new XmlDsigEnvelopedSignatureTransform();
        //        //reference.AddTransform(env);

        //        // Add the reference to the SignedXml object.
        //        signedXml.AddReference(reference);


        //        var keyInfo = new KeyInfo();
        //        keyInfo.AddClause(new KeyInfoX509Data(cert));
        //        signedXml.KeyInfo = keyInfo;

        //        // Compute the signature.
        //        signedXml.ComputeSignature();

        //        // Get the XML representation of the signature and save
        //        // it to an XmlElement object.
        //        XmlElement xmlDigitalSignature = signedXml.GetXml();

        //        // Append the element to the XML document. This appends the signature element to source xmls document.
        //        // but we will not use this construct as we need to add Id and then create a new xml document
        //        //xmlAfterSign.DocumentElement.AppendChild(xmlAfterSign.ImportNode(xmlDigitalSignature, true));

        //        //Create new xml document in which we will save the orginal paylong and signature
        //        xmlAfterSign = new XmlDocument();

        //        //XmlElement rootAfterElement = xmlAfterSign.DocumentElement;

        //        //add the first node - <?xml version="1.0" encoding="UTF-8"?>
        //        XmlDeclaration xmlDeclaration = xmlAfterSign.CreateXmlDeclaration("1.0", "UTF-8", null);
        //        xmlAfterSign.AppendChild(xmlDeclaration);

        //        //Now create request element inside which we will append original faxml(payload) and signature elements
        //        XmlElement requestAfterElement = xmlAfterSign.CreateElement("request");


        //        //Now get the signture node from signedXML
        //        //XmlElement signatureElement = xmlDigitalSignature["Signature"];
        //        //get the reference node from the signature element
        //        XmlElement referenceElement = xmlDigitalSignature["SignedInfo"]["Reference"];
        //        //get the attribute URI from reference element
        //        XmlAttribute idAttr = referenceElement.Attributes["URI"];
        //        //update the value of URI to 32 byte id
        //        idAttr.Value = "#" + idString;
        //        //With above we have a signature element that has URI = 32 byte id


        //        //Now get the faxml node from beforesignxml to add id attribute as well as signatureElement
        //        XmlNode faxmlNode = xmlBeforeSign.SelectSingleNode("//faxml");
        //        idAttr = xmlBeforeSign.CreateAttribute("Id");
        //        idAttr.Value = idString;
        //        faxmlNode.Attributes.Append(idAttr);

        //        //at this point we have xmlaftersigndoc with declarationnode

        //        //add the faxml node to request element
        //        requestAfterElement.AppendChild(xmlAfterSign.ImportNode(faxmlNode, true));
        //        //add the signature element to request element
        //        requestAfterElement.AppendChild(xmlAfterSign.ImportNode(xmlDigitalSignature, true));

        //        //now add the request to rootafterelement to complete the xml
        //        xmlAfterSign.AppendChild(requestAfterElement);

        //        //We have to add subject cn name in the signature/keyinfo
        //        XmlElement x509DataElement = xmlAfterSign["request"]["Signature"]["KeyInfo"]["X509Data"];
        //        XmlElement subjectElement = xmlAfterSign.CreateElement("X509SubjectName", x509DataElement.NamespaceURI);
        //        subjectElement.InnerText = cert.SubjectName.Name; // cert.Subject; this is certificate //cert.SubjectName.Name Available in certificate2;
        //        if (subjectElement.HasAttribute("xmlns"))
        //        {
        //            subjectElement.RemoveAttribute("xmlns");
        //        }

        //        x509DataElement.InsertBefore(subjectElement, xmlAfterSign["request"]["Signature"]["KeyInfo"]["X509Data"]["X509Certificate"]);
        //    }
        //    catch (Exception ex)
        //    {
        //        Console.WriteLine(ex.Message);
        //    }
        //}

        //public byte[] EncryptSignedXML(String data, byte[] key)
        //{
        //    byte[] cipher = null;
        //    try
        //    //System.Text.UTF8Encoding UTF8 = new System.Text.UTF8Encoding();
        //    {
        //        AesManaged tdes = new AesManaged();
        //        tdes.Key = key;//UTF8.GetBytes(keyValue);
        //        tdes.Mode = CipherMode.CBC; //.ECB;
        //        tdes.Padding = PaddingMode.PKCS7;
        //        //tdes.GenerateIV();
        //        //tdes.IV = _encoder.GetBytes(Convert.ToBase64String(tdes.IV));
        //        tdes.IV = IVECTOR;

        //        ICryptoTransform crypt = tdes.CreateEncryptor();

        //        //byte[] dataArr = Encoding.UTF8.GetBytes(data);
        //        byte[] dataArr = _encoder.GetBytes(data);
        //        byte[] ivAndData = new byte[IVECTOR.Length + dataArr.Length];
        //        //byte[] ivAndData = new byte[tdes.IV.Length + dataArr.Length];

        //        Array.Copy(IVECTOR, 0, ivAndData, 0, IVECTOR.Length);
        //        //Array.Copy(tdes.IV, 0, ivAndData, 0, tdes.IV.Length);
        //        Array.Copy(dataArr, 0, ivAndData, IVECTOR.Length, dataArr.Length);
        //        //Array.Copy(dataArr, 0, ivAndData, tdes.IV.Length, dataArr.Length);

        //        cipher = crypt.TransformFinalBlock(ivAndData, 0, ivAndData.Length);

        //        //decrypt
        //        ICryptoTransform decrypt = tdes.CreateDecryptor();
        //        byte[] tempdecrypt = decrypt.TransformFinalBlock((byte[])cipher, 0, cipher.Length);
        //        byte[] tempiv = new byte[IVECTOR.Length];
        //        byte[] tempdata = new byte[tempdecrypt.Length - tempiv.Length];

        //        Array.Copy(tempdecrypt, 0, tempiv, 0, IVECTOR.Length);
        //        Array.Copy(tempdecrypt, IVECTOR.Length, tempdata, 0, tempdecrypt.Length - tempiv.Length);


        //    }
        //    catch (Exception ex)
        //    {
        //        MessageBox.Show(ex.Message);
        //    }
        //    return cipher;
        //    //String encryptedText = Convert.ToBase64String(cipher);
        //}

        //public void EncryptEncodeSymmetricKey()
        //{
        //    X509Certificate2 cert = new X509Certificate2(pemcertificateFile);
        //    //CspParameters csp = new CspParameters();
        //    //csp.KeyContainerName = "HDFCKey";

        //    RSACryptoServiceProvider _rsaprovider = new RSACryptoServiceProvider();

        //    string rsaXml = cert.GetRSAPublicKey().ToXmlString(false);

        //    _rsaprovider.FromXmlString(rsaXml);
        //    //_rsaprovider.PersistKeyInCsp = true;

        //    byte[] encryptedKey = _rsaprovider.Encrypt(encryptionKeyBytes, false);
        //    tbEncryptedKey.Text = _encoder.GetString(encryptedKey);

        //    encryptedencodedKey = EncodeByteArrayToBase64String(encryptedKey);
        //    tbEncodedKey.Text = encryptedencodedKey;
        //}

        //public void NewSignPayloadXML()
        //{
        //    if (xmlBeforeSign == null)
        //        throw new ArgumentException(nameof(xmlBeforeSign));

        //    String idString = GenerateAlphaNumericId(32);

        //    //we have to use pfx as the document says the signing needs to happen using partner private key
        //    X509Certificate2 cert = new X509Certificate2(pfxcertificateFile, pfxcertificatePassword);

        //    //var rsa = RSA.Create(cert.PrivateKey.KeySize);
        //    var signedXml = new SignedXml(xmlBeforeSign);

        //    signedXml.SigningKey = cert.GetRSAPrivateKey();
        //    signedXml.SignedInfo.SignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
        //    signedXml.SignedInfo.CanonicalizationMethod = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";

        //    var reference = new Reference { Uri = String.Empty };
        //    //reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
        //    //reference.AddTransform(new XmlDsigC14NTransform());

        //    signedXml.AddReference(reference);

        //    var keyInfo = new KeyInfo();
        //    keyInfo.AddClause(new KeyInfoX509Data(cert));
        //    signedXml.KeyInfo = keyInfo;

        //    signedXml.ComputeSignature();

        //    XmlElement xmlDigitalSignature = signedXml.GetXml();

        //    // Append the element to the XML document. This appends the signature element to source xmls document.
        //    // but we will not use this construct as we need to add Id and then create a new xml document
        //    //xmlAfterSign.DocumentElement.AppendChild(xmlAfterSign.ImportNode(xmlDigitalSignature, true));

        //    //Create new xml document in which we will save the orginal paylong and signature
        //    xmlAfterSign = new XmlDocument();

        //    //XmlElement rootAfterElement = xmlAfterSign.DocumentElement;

        //    //add the first node - <?xml version="1.0" encoding="UTF-8"?>
        //    XmlDeclaration xmlDeclaration = xmlAfterSign.CreateXmlDeclaration("1.0", "UTF-8", null);
        //    xmlAfterSign.AppendChild(xmlDeclaration);

        //    //Now create request element inside which we will append original faxml(payload) and signature elements
        //    XmlElement requestAfterElement = xmlAfterSign.CreateElement("request");


        //    //Now get the signture node from signedXML
        //    //XmlElement signatureElement = xmlDigitalSignature["Signature"];
        //    //get the reference node from the signature element
        //    XmlElement referenceElement = xmlDigitalSignature["SignedInfo"]["Reference"];
        //    //get the attribute URI from reference element
        //    XmlAttribute idAttr = referenceElement.Attributes["URI"];
        //    //update the value of URI to 32 byte id
        //    idAttr.Value = "#" + idString;
        //    //With above we have a signature element that has URI = 32 byte id


        //    //Now get the faxml node from beforesignxml to add id attribute as well as signatureElement
        //    XmlNode faxmlNode = xmlBeforeSign.SelectSingleNode("//faxml");
        //    idAttr = xmlBeforeSign.CreateAttribute("Id");
        //    idAttr.Value = idString;
        //    faxmlNode.Attributes.Append(idAttr);

        //    //at this point we have xmlaftersigndoc with declarationnode

        //    //add the faxml node to request element
        //    requestAfterElement.AppendChild(xmlAfterSign.ImportNode(faxmlNode, true));
        //    //add the signature element to request element
        //    requestAfterElement.AppendChild(xmlAfterSign.ImportNode(xmlDigitalSignature, true));

        //    //now add the request to rootafterelement to complete the xml
        //    xmlAfterSign.AppendChild(requestAfterElement);

        //    //We have to add subject cn name in the signature/keyinfo
        //    XmlElement x509DataElement = xmlAfterSign["request"]["Signature"]["KeyInfo"]["X509Data"];
        //    XmlElement subjectElement = xmlAfterSign.CreateElement("X509SubjectName", x509DataElement.NamespaceURI);
        //    subjectElement.InnerText = cert.SubjectName.Name; // cert.Subject; this is certificate //cert.SubjectName.Name Available in certificate2;
        //    if (subjectElement.HasAttribute("xmlns"))
        //    {
        //        subjectElement.RemoveAttribute("xmlns");
        //    }

        //    x509DataElement.InsertBefore(subjectElement, xmlAfterSign["request"]["Signature"]["KeyInfo"]["X509Data"]["X509Certificate"]);
        //}

    }
    internal class OAuthToken
    {
        [JsonProperty("access_token")]
        public string AccessToken { get; set; }

        [JsonProperty("token_type")]
        public string TokenType { get; set; }

        [JsonProperty("expires_in")]
        public int ExpiresIn { get; set; }

        [JsonProperty("scope")]
        public string Scope { get; set; }
    }

    internal class RequestPayload
    {
        public string RequestSignatureEncryptedValue { get; set; }
        public string SymmetricKeyEncryptedValue { get; set; }
        public string Scope { get; set; }
        public string TransactionId { get; set; }
        public string OAuthTokenValue { get; set; }
    }

    internal class ResponsePayload
    {
        public string ResponseSignatureEncryptedValue { get; set; }
        public string GWSymmetricKeyEncryptedValue { get; set; }
        public string Scope { get; set; }
        public string TransactionId { get; set; }
        public string Status { get; set; }
    }
}
