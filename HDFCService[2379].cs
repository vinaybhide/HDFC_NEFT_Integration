using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Linq;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using System.Configuration;
using System.Net;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Microsoft.IdentityModel.Tokens;

using Newtonsoft.Json;
using Microsoft.IdentityModel.JsonWebTokens;

using System.IO;

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace HDFCRestServer
{
    public partial class HDFCService : ServiceBase
    {
        LogFileDetails fleEZR;
        DataAccess objDataAccessEZR = new DataAccess();
        DataAccess objDataAccessEZRInquiry = new DataAccess();
        bool EZRREMServiceStarted;
        bool EZRREMENQServiceStarted;

        Thread EZRREMServiceThread;
        Thread BFCREMENQServiceThread;

        public HDFCService()
        {
            InitializeComponent();
        }
        static void Main()
        {

            //System.ServiceProcess.ServiceBase[] ServicesToRun;
            //ServicesToRun = new System.ServiceProcess.ServiceBase[] { new HDFCService() };
            //System.ServiceProcess.ServiceBase.Run(ServicesToRun);


            HDFCService x = new HDFCService();
           // x.Getsymvalue();
            //x.GenerateRSAEncryption();
            // x.CreateKEY();
            //  x.GetPrivateKeyFromPemFile();
            // x.GetPublicKeyFromPemFile();
            //x.CreateAuthToken();
            x.EZRGeneratePayment();
            //x.CreateJWTSingnature();

            // x.CreateToken("");
            // x.GenerateJWTToken("");
            //   x.CreateAuthToken();
            //string key=   x.RandomString(32);
            // string enncrypt = x.GenerateAESEncryption();
            // x.CreateEncryption();



        }

        protected override void OnStart(string[] args)
        {
        }

        protected override void OnStop()
        {
        }
        private void EZRGeneratePayment()
        {
            EZRREMServiceStarted = true;

            string EZRShortCompName = string.Empty;
            DateTime EZRSysDate = DateTime.Today;
            string EZRCompName = string.Empty;
            string EZRCompTelNo = string.Empty;
            string EZRFName = string.Empty;
            string EZRCompAddress = string.Empty;

            while (EZRREMServiceStarted)
            {
                try
                {
                    fleEZR = new LogFileDetails(@"C:\\HDFC\\HDFCLOGS\EZR\" + DateTime.Now.ToString("dd.MM.yyyy") + "\\");
                    objDataAccessEZR.ReadSettings("EZR");
                    string username = string.Empty;
                    string password = string.Empty;
                    string DomainId = string.Empty;
                    string pBANKCODE = string.Empty;
                    string TRANCODE = string.Empty;
                    string TRANSNO = string.Empty;
                    string pFLG = string.Empty;
                    EZRShortCompName = "EZR";
                    decimal EZRVEAmount = 0; // VOSTRO Account Amount Variable 
                    bool EZRVEFlg = false; // VOSTRO Account Flg
                    username = objDataAccessEZR.UserName;
                    password = objDataAccessEZR.Password;
                    pBANKCODE = objDataAccessEZR.BANKCODE;

                    if (objDataAccessEZR.FLAG.ToUpper().Equals("FALSE"))
                        fleEZR.writeToLog(EZRShortCompName + " HDFC Service is in De-Activated Mode (FALSE), so Posting action will not be triggered");

                    if (objDataAccessEZR.FLAG.ToUpper().Equals("TRUE"))
                    {
                        DataSet dsCompInfo = objDataAccessEZR.GetCompanyInf();
                        if (dsCompInfo.Tables[0].Rows.Count > 0 && dsCompInfo.Tables[0] != null)
                        {
                            EZRCompName = dsCompInfo.Tables[0].Rows[0][1].ToString().ToUpper();
                            EZRCompAddress = dsCompInfo.Tables[0].Rows[0][3].ToString().ToUpper();
                            EZRCompTelNo = dsCompInfo.Tables[0].Rows[0][4].ToString().ToUpper();
                        }
                        else
                        {
                            EZRCompName = string.Empty;
                            EZRCompAddress = string.Empty;
                            EZRCompTelNo = string.Empty;
                        }

                        DataSet dsHDFCEZR = new DataSet();
                        DataSet dsEZRFund = new DataSet();
                        dsHDFCEZR = objDataAccessEZR.GetPaymentProcess(pBANKCODE);
                       
                            if (dsHDFCEZR.Tables[0].Rows.Count > 0 && dsHDFCEZR.Tables[0] != null)
                            {


                                for (int Row = 0; Row <= dsHDFCEZR.Tables[0].Rows.Count - 1; Row++)
                                {
                                HDFCEntity.HDFRequest Hdfcrequest = new HDFCEntity.HDFRequest();
                                    HDFCEntity.Initiatepaymentrequest initiatepaymentrequest = new HDFCEntity.Initiatepaymentrequest();
                                    HDFCEntity.Header header = new HDFCEntity.Header();
                                    HDFCEntity.TransactionData transactionData = new HDFCEntity.TransactionData();

                                List<HDFCEntity.TransactionData> lsttransactionDatas = new List<HDFCEntity.TransactionData>();

                                string plainPassword = ConfigurationManager.AppSettings["PASSWORD"].ToString();
                                string EncryptedPassword = "";
                                AESEncrytption aESEncrytption = new AESEncrytption();
                                using (AesManaged aes = new AesManaged())
                                {
                                    // Encrypt string    
                                    byte[] encrypted = aESEncrytption.EncryptStringToBytes_Aes(plainPassword, aes.Key, aes.IV);
                                    EncryptedPassword = Convert.ToBase64String(encrypted);
                                }


                                    header.ClientCode = ConfigurationManager.AppSettings["CLIENTCODE"].ToString();
                                    header.UserId= ConfigurationManager.AppSettings["USERID"].ToString();
                                    header.Password = EncryptedPassword;
                                    header.ReqId = dsHDFCEZR.Tables[0].Rows[Row]["ClientRefId"].ToString();
                                    header.ReservedFieldH1 = dsHDFCEZR.Tables[0].Rows[Row]["RESFIELDHEAD1"].ToString();
                                    header.ReservedFieldH2 = dsHDFCEZR.Tables[0].Rows[Row]["RESFIELDHEAD2"].ToString();
                                    header.ReservedFieldH3 = dsHDFCEZR.Tables[0].Rows[Row]["RESFIELDHEAD3"].ToString();
                                    TRANSNO = dsHDFCEZR.Tables[0].Rows[Row]["ClientRefId"].ToString();

                                    transactionData.CorporateRefNo = dsHDFCEZR.Tables[0].Rows[Row]["ClientRefId"].ToString();
                                    transactionData.PaymentType = dsHDFCEZR.Tables[0].Rows[Row]["PAYMENTMODE"].ToString();
                                    transactionData.TransferAmount = dsHDFCEZR.Tables[0].Rows[Row]["TXNAMT"].ToString();
                                    transactionData.TransactionDate = dsHDFCEZR.Tables[0].Rows[Row]["TXNDATE"].ToString();
                                    transactionData.BeneficiaryIFSC = dsHDFCEZR.Tables[0].Rows[Row]["BENEIFSCCODE"].ToString();
                                    transactionData.BeneficiaryAccountType = dsHDFCEZR.Tables[0].Rows[Row]["BENEACCTYPE"].ToString();
                                    transactionData.BeneficiaryAccountNo = dsHDFCEZR.Tables[0].Rows[Row]["BENEACCNO"].ToString();
                                    transactionData.BeneficiaryName = dsHDFCEZR.Tables[0].Rows[Row]["BENENAME"].ToString();
                                    transactionData.BeneficiaryAddress1 = dsHDFCEZR.Tables[0].Rows[Row]["BENEADD1"].ToString();
                                    transactionData.BeneficiaryAddress2 = dsHDFCEZR.Tables[0].Rows[Row]["BENEADD2"].ToString();
                                    transactionData.BeneficiaryAddress3 = dsHDFCEZR.Tables[0].Rows[Row]["BENEADD3"].ToString();
                                    transactionData.BeneficiaryZIPCode = dsHDFCEZR.Tables[0].Rows[Row]["BENPIN"].ToString();
                                    transactionData.BeneficiaryEmail = dsHDFCEZR.Tables[0].Rows[Row]["BENEMAIL"].ToString();
                                    transactionData.BeneficiaryMobileNo = dsHDFCEZR.Tables[0].Rows[Row]["BENEMOB"].ToString();
                                    transactionData.ShipmentDate = dsHDFCEZR.Tables[0].Rows[Row]["SHIPMENTDATE"].ToString();
                                    transactionData.VpaAddress = dsHDFCEZR.Tables[0].Rows[Row]["VPAADDRESS"].ToString();
                                    transactionData.IECode = dsHDFCEZR.Tables[0].Rows[Row]["IECODE"].ToString();
                                    transactionData.PanCard = dsHDFCEZR.Tables[0].Rows[Row]["PANCARD"].ToString();
                                    transactionData.PurposeID = dsHDFCEZR.Tables[0].Rows[Row]["SENDTORECEIVER"].ToString();
                                    transactionData.InvoiceNumber = dsHDFCEZR.Tables[0].Rows[Row]["SECURITYNO"].ToString();
                                    transactionData.ServiceUtilizeCntry = dsHDFCEZR.Tables[0].Rows[Row]["BENCOUNTRY"].ToString();
                                    transactionData.RemitterName = dsHDFCEZR.Tables[0].Rows[Row]["RMTRNAME"].ToString();
                                    transactionData.RemitterID = dsHDFCEZR.Tables[0].Rows[Row]["RMTIDNO"].ToString();
                                    transactionData.RemitterAddress1 = dsHDFCEZR.Tables[0].Rows[Row]["RMTRADD1"].ToString();
                                    transactionData.RemitterAddress2 = dsHDFCEZR.Tables[0].Rows[Row]["RMTRADD2"].ToString();
                                    transactionData.RemitterAddress3 = dsHDFCEZR.Tables[0].Rows[Row]["RMTRADD3"].ToString();
                                    transactionData.RemitterZIPCode = dsHDFCEZR.Tables[0].Rows[Row]["BENEACCNO"].ToString();
                                    transactionData.RemitterEmail = dsHDFCEZR.Tables[0].Rows[Row]["RMTEMAIL"].ToString();
                                    transactionData.RemitterMobileNo = dsHDFCEZR.Tables[0].Rows[Row]["RMTMOB"].ToString();
                                    transactionData.RemitterCountry = dsHDFCEZR.Tables[0].Rows[Row]["REMITTERCOUNTRY"].ToString();
                                    transactionData.ReservedFieldD1 = dsHDFCEZR.Tables[0].Rows[Row]["RESFIELD1"].ToString();
                                    transactionData.ReservedFieldD2 = dsHDFCEZR.Tables[0].Rows[Row]["RESFIELD2"].ToString();
                                    transactionData.ReservedFieldD3 = dsHDFCEZR.Tables[0].Rows[Row]["RESFIELD3"].ToString();
                                    transactionData.ReservedFieldD4 = dsHDFCEZR.Tables[0].Rows[Row]["RESFIELD4"].ToString();
                                    transactionData.ReservedFieldD5 = dsHDFCEZR.Tables[0].Rows[Row]["RESFIELD5"].ToString();
                                    initiatepaymentrequest.header = header;
                                    lsttransactionDatas.Add(transactionData);
                                initiatepaymentrequest.TransactionData = lsttransactionDatas;
                                Hdfcrequest.initiatepaymentrequest = initiatepaymentrequest;


                                var json = new JavaScriptSerializer().Serialize(Hdfcrequest);
                                string token = "";
                                string response = CreateHDFCEncryptedRequest(TRANSNO, json);

                            }
                            }
                       
                    }
                }
                catch (Exception ex)
                {
                }
            }
        }

        private string CreateHDFCEncryptedRequest(string Transno, string Payload)
        {
            string OAuthTokenValue = CreateAuthToken();
            string jwsSingnautre = CreateJWTSingnature(Payload);
             string KEY = RandomString(32);
            //string KEY = "cYE2NQZrByCZ30rKmsSEcadc33TnEJZ2";
            string IVString = RandomString(16);
            string RequestSignatureEncryptedValue = GenerateAESEncryption(KEY, IVString, IVString + jwsSingnautre);
            string SymmetricKeyEncryptedValue = CreateRSASymmterickeyEncryption(KEY);
            string TransactionId = Transno;
            string SCOPE = ConfigurationManager.AppSettings["SCOPE"].ToString();
            string Scope = SCOPE;
            string Id_token_jwt = jwsSingnautre;
            string PaymentURL = ConfigurationManager.AppSettings["PAYMENTURL"].ToString();
            HDFCRequest hdfcrequest = new HDFCRequest();
            hdfcrequest.RequestSignatureEncryptedValue =RequestSignatureEncryptedValue;
            hdfcrequest.SymmetricKeyEncryptedValue  = SymmetricKeyEncryptedValue; //=Base64UrlEncoder.Encode(SymmetricKeyEncryptedValue);
            //hdfcrequest.SymmetricKeyEncryptedValue = "dyql07vp6h5VIfWF+XsSjYusTv3H+XZMiJkWdCNnrCWO+mh0IvmyjBcO9LTnWyOWaXYL5uHC96xKu20oXlxkJOCygU69/X/Tdcd3L3onXF+hgrsHOiE3r9iRGjo+y8H4rFFgQG0CPHZcE+QBMVhDO5CXA9Z8Mz8F7M6oebwElgFL+UkOTaAHiCP6RHxqCoFS6rjBT+xCxHwBq3/3tXtX/nz5JEYFBJt7DuLDDUrA9+DOIhyoKAJKhEUSLMEyeV6duqnNmbWBIiqlZJfkdzTJ17gExHzPp8cksu2lEGJokFppg2eM/J4W82LF6wur4r2TXjET6d0NqaBWy8evrU7NZw==";
            hdfcrequest.OAuthTokenValue = OAuthTokenValue;
            hdfcrequest.IdTokenJwt = "";//Id_token_jwt;
            hdfcrequest.Scope = Scope;
            hdfcrequest.TransactionId = TransactionId;
            string apikey = ConfigurationManager.AppSettings["CLIENTID"].ToString();
            var json = new JavaScriptSerializer().Serialize(hdfcrequest);
            try
            {


                LogFileDetails fleRippleBankLogRequest = new LogFileDetails(@"C:\\HDFC\HDFCRequest\Payment\" + DateTime.Now.ToString("dd.MM.yyyy") + "\\");
                string Request = "\r\n---------------- Start - Plain Text for Transaction Posting ----------------";
                Request += "\r\n\tTxn No. " + Transno + "\r\n";
                Request += json;
                Request += "\r\n------------------------------------End-------------------------------------\r\n";
                fleRippleBankLogRequest.writeToLog(Request);


                ServicePointManager.CheckCertificateRevocationList = false;
                ServicePointManager.ServerCertificateValidationCallback = (a, b, c, d) => true;
                ServicePointManager.Expect100Continue = true;
                var request = (HttpWebRequest)WebRequest.Create(PaymentURL);
                string PrivateKey = System.IO.Path.GetDirectoryName(new System.Uri(System.Reflection.Assembly.GetExecutingAssembly().CodeBase).LocalPath);
                PrivateKey += "\\bfcapis.bfccirrus.com.pfx";

                request.ClientCertificates.Add(new System.Security.Cryptography.X509Certificates.X509Certificate(PrivateKey, "123123123"));
                // request.Headers.Add("Content-type", "application/json");
                request.Headers.Add("apikey", apikey);
                request.Method = "POST";
                request.ContentType = "application/json";

                using (var streamWriter = new StreamWriter(request.GetRequestStream()))
                {
                    

                    streamWriter.Write(json);
                }

                var httpResponse = (HttpWebResponse)request.GetResponse();
                using (var streamReader = new StreamReader(httpResponse.GetResponseStream()))
                {
                    var ss = streamReader.ReadToEnd();



                    if (ss != null)
                    {
                        //    var json_serializer = new JavaScriptSerializer();
                        //    string sret = System.Text.Encoding.ASCII.GetString(ss.ToString());
                        HDFCResponse hdfcResponse = Newtonsoft.Json.JsonConvert.DeserializeObject<HDFCResponse>(ss);
                        //;
                        string DecryptedSymtericKey = CreateRSASymmterickeyDecryption(hdfcResponse.GWSymmetricKeyEncryptedValue);
                        string DecryptedJWTSingnature = GenerateAESDescryption(DecryptedSymtericKey, IVString, hdfcResponse.ResponseSignatureEncryptedValue);
                        // string singnature = Base64UrlEncoder.Decode(hdfcResponse.ResponseSignatureEncryptedValue);
                        string TransactionDecryptedValue="";
                        string TransactionResponse ="";
                        string[] JWTArray = DecryptedJWTSingnature.Split('.');
                        if (JWTArray.Length > 0)
                        {
                            TransactionDecryptedValue = JWTArray[1].ToString();

                            TransactionResponse = Base64UrlEncoder.Decode(TransactionDecryptedValue);
                        }
                        HDFCTransStatusResponse hdfcTransStatusResponse = Newtonsoft.Json.JsonConvert.DeserializeObject<HDFCTransStatusResponse>(TransactionResponse);

                            //CreateJWTDecode(singnature, hdfcResponse.ResponseSignatureEncryptedValue);

                    }

                }
            }
             catch (WebException ex)
            {
                if (ex.Response != null)
                {
                    string response = new StreamReader(ex.Response.GetResponseStream()).ReadToEnd();
                }
            }

                    return  "";
        }
        public string GenerateAESEncryption( string KEY , string IVString, string JWSToken)
        {
            string EncryptedText = "";           
            AESEncrytption aESEncrytption = new AESEncrytption();
            byte[] encrpyted = aESEncrytption.EncryptStringToBytes_Aes((JWSToken), Encoding.UTF8.GetBytes(KEY), Encoding.UTF8.GetBytes(IVString));

            EncryptedText = Convert.ToBase64String(encrpyted);
            return EncryptedText;
        }
        public string GenerateAESDescryption(string KEY, string IVString, string EncryptedText)
        {
           
            AESEncrytption aESEncrytption = new AESEncrytption();
            byte[] EncryptedByte = Convert.FromBase64String(EncryptedText);
            string DecryptedString = aESEncrytption.DecryptStringFromBytes_Aes(EncryptedByte, Convert.FromBase64String(KEY), Encoding.UTF8.GetBytes(IVString));
            return DecryptedString;
        }
        public  string CreateJWTSingnature(string payload)
        {
            //string payload = "{\"header\":{\"ReqId\":\"\",\"ClientCode\":\"\",\"UserId\":null,\"Password\":\"\",\"ReservedFieldH1\":\"\",\"ReservedFieldH2\":\"\",\"ReservedFieldH3\":\"\"},\"TransactionData\":[{\"CorporateRefNo\":\"EZB1000111034300\",\"PaymentType\":\"5\",\"TransferAmount\":\"3500\",\"TransactionDate\":\"8/19/0010 12:00:00 AM\",\"BeneficiaryIFSC\":\"ANDB0CG7118\",\"BeneficiaryAccountType\":\"10\",\"BeneficiaryAccountNo\":\"3040458238\",\"BeneficiaryName\":\"KULDEEP Y\",\"BeneficiaryAddress1\":\"TESTER\",\"BeneficiaryAddress2\":\"\",\"BeneficiaryAddress3\":\".\",\"BeneficiaryZIPCode\":\"\",\"BeneficiaryEmail\":\"\",\"BeneficiaryMobileNo\":\"\",\"ShipmentDate\":\"\",\"VpaAddress\":\"\",\"IECode\":\"\",\"PanCard\":\"\",\"PurposeID\":\"CRENRE \",\"InvoiceNumber\":\"1000111034300\",\"ServiceUtilizeCntry\":\"IN\",\"RemitterName\":\"JAMES ANDERSON\",\"RemitterID\":\"OTH H1859810\",\"RemitterAddress1\":\"TEST\",\"RemitterAddress2\":\"\",\"RemitterAddress3\":\".\",\"RemitterZIPCode\":\"3040458238\",\"RemitterEmail\":\"\",\"RemitterMobileNo\":\"79610948521\",\"RemitterCountry\":\"GB\",\"ReservedFieldD1\":\"\",\"ReservedFieldD2\":\"\",\"ReservedFieldD3\":\"\",\"ReservedFieldD4\":\"\",\"ReservedFieldD5\":\"\"}]}";
            string header = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
            string jwt = string.Empty;
            RsaPrivateCrtKeyParameters keyPair;

            var jss = new JavaScriptSerializer();
            var dict = jss.Deserialize<Dictionary<string, string>>(header);
            var headers = new Dictionary<string, object>()
            {
                { "alg", "RS256" },
                { "typ", "JWT" }
            };         
       

            string PrivateKey = System.IO.Path.GetDirectoryName(new System.Uri(System.Reflection.Assembly.GetExecutingAssembly().CodeBase).LocalPath);
            //PrivateKey += "\\ss.hdfc.bfccirrus.com.private.key.pem";
           string  BFCPrivateKeyFileName= ConfigurationManager.AppSettings["BFCPrivateKeyFileName"].ToString();
            PrivateKey += @"\\" + BFCPrivateKeyFileName; // bfcapis.bfccirrus.com.private.key.pem";
            
            keyPair = GetPrivateKey(PrivateKey);
            /// cert begins -----BEGIN PRIVATE KEY----- and ends with -END PRIVATE KEY-----";
            try
            {
                RSAParameters rsaParams = DotNetUtilities.ToRSAParameters(keyPair);
                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                {
                    rsa.ImportParameters(rsaParams);                
                    jwt = Jose.JWT.Encode(pay
                        load,rsa, Jose.JwsAlgorithm.RS256, extraHeaders: headers);                  
                }                
            }
            catch (Exception ex)
            {
            }
            return jwt;
        }
        public static RsaPrivateCrtKeyParameters GetPrivateKey(String pemFile)
        {
            try
            {
                if (string.IsNullOrEmpty(pemFile)) throw new ArgumentNullException("pemFile");

                string privateKey = File.Exists(pemFile) ? File.ReadAllText(pemFile) : pemFile;

                var reader = new PemReader(new StringReader(privateKey));
                RsaPrivateCrtKeyParameters privkey = null;
                Object obj = reader.ReadObject();
                if (obj is AsymmetricCipherKeyPair)
                {
                    privkey = (RsaPrivateCrtKeyParameters)((AsymmetricCipherKeyPair)obj).Private;
                }
                return privkey;
            }
            
            catch (Exception ex) { return null; }
        }
        public string CreateRSASymmterickeyEncryption(string strKEY)
        {
            // string strKEY1 = "T2ZwQldTaURlUDZrSWpieVlGREd1M1RuQnF4VEVwTE0="; //RandomString(32);
            //strKEY = strKEY1;

            string filePath = System.IO.Path.GetDirectoryName(new System.Uri(System.Reflection.Assembly.GetExecutingAssembly().CodeBase).LocalPath);
            string HDFCPublicKeyFileName = ConfigurationManager.AppSettings["HDFCPublicKeyFileName"].ToString();
            filePath += @"\\" + HDFCPublicKeyFileName;
           // filePath += "\\hdfc.txt";

            using (TextReader publicKeyTextReader = new StringReader(File.ReadAllText(filePath)))
            {
                RsaKeyParameters publicKeyParam = (RsaKeyParameters)new PemReader(publicKeyTextReader).ReadObject();

                RSAParameters rsaParams = DotNetUtilities.ToRSAParameters((RsaKeyParameters)publicKeyParam);

                RSACryptoServiceProvider csp = new RSACryptoServiceProvider();// cspParams);             
                csp.ImportParameters(rsaParams);                
                byte[] strKEYByte = Encoding.UTF8.GetBytes(strKEY);              
                byte[] encryptedKey = csp.Encrypt(strKEYByte, RSAEncryptionPadding.Pkcs1);
                return Convert.ToBase64String(encryptedKey);
               
            }
          

        }
        public string CreateRSASymmterickeyDecryption(string EncryptedText)
        {
            string BFCPrivateKeyFileName = ConfigurationManager.AppSettings["BFCPrivateKeyFileName"].ToString();
            string PrivateKey = System.IO.Path.GetDirectoryName(new System.Uri(System.Reflection.Assembly.GetExecutingAssembly().CodeBase).LocalPath);
            PrivateKey += "\\" + BFCPrivateKeyFileName; // bfcapis.bfccirrus.com.private.key.pem";
            RsaPrivateCrtKeyParameters keyPair;
            keyPair = GetPrivateKey(PrivateKey);
            /// cert begins -----BEGIN PRIVATE KEY----- and ends with -END PRIVATE KEY-----";
            string DecryptedTextKey = "";
            try
            {

                RSAParameters rsaParams = DotNetUtilities.ToRSAParameters(keyPair);

                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                {
                 rsa.ImportParameters(rsaParams);               
                 byte[] EncryptedTextByte = Encoding.UTF8.GetBytes(EncryptedText);
                 byte[] DecryptedKey = rsa.Decrypt(Convert.FromBase64String(EncryptedText), RSAEncryptionPadding.Pkcs1);
                 DecryptedTextKey = Convert.ToBase64String(DecryptedKey);
                }
               
            }
            catch (Exception ex)
            {

            }
            return DecryptedTextKey;
                //rsaParams.Modulus
                // return csp;
        }          
        private string CreateAuthToken()
        {
            string ReceiverToken = "";
            try
            {
                string AuthTokenURL = ConfigurationManager.AppSettings["AUTHTOKENURL"].ToString();
                string ClientID = ConfigurationManager.AppSettings["CLIENTID"].ToString();
                string CLIENTSECRET = ConfigurationManager.AppSettings["CLIENTSECRET"].ToString();
                string Scope = ConfigurationManager.AppSettings["SCOPE"].ToString();

                ServicePointManager.CheckCertificateRevocationList = false;
                ServicePointManager.ServerCertificateValidationCallback = (a, b, c, d) => true;
                ServicePointManager.Expect100Continue = true;
                //  ServicePointManager.SecurityProtocol = (SecurityProtocolType)3072;
                //  System.Net.ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls11 | SecurityProtocolType.Tls12;
                var request = (HttpWebRequest)WebRequest.Create(AuthTokenURL+ "?grant_type=client_credentials&scope=BFCUK");

                string BFCPFXFileName = ConfigurationManager.AppSettings["BFCPFXFileName"].ToString();
               string BFCPFXFilePassword  = ConfigurationManager.AppSettings["BFCPFXFilePassword"].ToString();

                string PrivateKey = System.IO.Path.GetDirectoryName(new System.Uri(System.Reflection.Assembly.GetExecutingAssembly().CodeBase).LocalPath);

                PrivateKey += @"\\" + BFCPFXFileName;
                request.ClientCertificates.Add(new System.Security.Cryptography.X509Certificates.X509Certificate(PrivateKey, BFCPFXFilePassword));
                var bytes = Encoding.UTF8.GetBytes($"{ClientID}:{CLIENTSECRET}");
                request.Headers.Add("Authorization", $"Basic {Convert.ToBase64String(bytes)}");
               // request.Headers["Authorization"] = "Basic " + credentials;
                request.Method = "POST";
                request.ContentType = "application/x-www-form-urlencoded";               
                var response = (HttpWebResponse)request.GetResponse();

                var responseString = new StreamReader(response.GetResponseStream()).ReadToEnd();
                string appToken="";
                var dic = new JavaScriptSerializer().Deserialize<Dictionary<string, string>>(responseString);
                appToken = dic["access_token"].ToString();
                return appToken;
            }
            catch (WebException ex)
            {
                if (ex.Response != null)
                {
                    string response = new StreamReader(ex.Response.GetResponseStream()).ReadToEnd();
                }
            }
            return ReceiverToken;
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

    }
}
