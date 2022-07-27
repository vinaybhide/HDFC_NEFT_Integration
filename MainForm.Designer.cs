namespace TestHDFC
{
    partial class MainForm
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.tbKey = new System.Windows.Forms.TextBox();
            this.btnEncryptEncode = new System.Windows.Forms.Button();
            this.tbData = new System.Windows.Forms.TextBox();
            this.tbSignedXml = new System.Windows.Forms.TextBox();
            this.label2 = new System.Windows.Forms.Label();
            this.btnEncryptGeneratedKey = new System.Windows.Forms.Button();
            this.btnSign = new System.Windows.Forms.Button();
            this.btnOpenXMLFile = new System.Windows.Forms.Button();
            this.label4 = new System.Windows.Forms.Label();
            this.tbEncrypted = new System.Windows.Forms.TextBox();
            this.tbEncoded = new System.Windows.Forms.TextBox();
            this.label5 = new System.Windows.Forms.Label();
            this.label3 = new System.Windows.Forms.Label();
            this.tbEncodedKey = new System.Windows.Forms.TextBox();
            this.tbEncryptedKey = new System.Windows.Forms.TextBox();
            this.label1 = new System.Windows.Forms.Label();
            this.label6 = new System.Windows.Forms.Label();
            this.label7 = new System.Windows.Forms.Label();
            this.btnOAuth = new System.Windows.Forms.Button();
            this.tbOauthToken = new System.Windows.Forms.TextBox();
            this.label8 = new System.Windows.Forms.Label();
            this.btnCallHDFCApi = new System.Windows.Forms.Button();
            this.tbHDFCResponse = new System.Windows.Forms.TextBox();
            this.tbDecryptedKey = new System.Windows.Forms.TextBox();
            this.label9 = new System.Windows.Forms.Label();
            this.label10 = new System.Windows.Forms.Label();
            this.tbDecodedKey = new System.Windows.Forms.TextBox();
            this.label11 = new System.Windows.Forms.Label();
            this.label12 = new System.Windows.Forms.Label();
            this.tbDecodedXML = new System.Windows.Forms.TextBox();
            this.label13 = new System.Windows.Forms.Label();
            this.tbDecryptedXML = new System.Windows.Forms.TextBox();
            this.label14 = new System.Windows.Forms.Label();
            this.tbResponseXML = new System.Windows.Forms.TextBox();
            this.SuspendLayout();
            // 
            // tbKey
            // 
            this.tbKey.Location = new System.Drawing.Point(170, 368);
            this.tbKey.Name = "tbKey";
            this.tbKey.Size = new System.Drawing.Size(386, 31);
            this.tbKey.TabIndex = 1;
            // 
            // btnEncryptEncode
            // 
            this.btnEncryptEncode.Location = new System.Drawing.Point(273, 12);
            this.btnEncryptEncode.Name = "btnEncryptEncode";
            this.btnEncryptEncode.Size = new System.Drawing.Size(141, 29);
            this.btnEncryptEncode.TabIndex = 4;
            this.btnEncryptEncode.Text = "Encrypt+Encode";
            this.btnEncryptEncode.UseVisualStyleBackColor = true;
            this.btnEncryptEncode.Click += new System.EventHandler(this.btnEncryptEncodeData_Click);
            // 
            // tbData
            // 
            this.tbData.Location = new System.Drawing.Point(16, 72);
            this.tbData.Multiline = true;
            this.tbData.Name = "tbData";
            this.tbData.ScrollBars = System.Windows.Forms.ScrollBars.Both;
            this.tbData.Size = new System.Drawing.Size(754, 126);
            this.tbData.TabIndex = 5;
            // 
            // tbSignedXml
            // 
            this.tbSignedXml.Location = new System.Drawing.Point(778, 72);
            this.tbSignedXml.Multiline = true;
            this.tbSignedXml.Name = "tbSignedXml";
            this.tbSignedXml.ScrollBars = System.Windows.Forms.ScrollBars.Both;
            this.tbSignedXml.Size = new System.Drawing.Size(739, 126);
            this.tbSignedXml.TabIndex = 6;
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.Location = new System.Drawing.Point(3, 49);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(136, 25);
            this.label2.TabIndex = 7;
            this.label2.Text = "Source XML:";
            // 
            // btnEncryptGeneratedKey
            // 
            this.btnEncryptGeneratedKey.Location = new System.Drawing.Point(420, 12);
            this.btnEncryptGeneratedKey.Name = "btnEncryptGeneratedKey";
            this.btnEncryptGeneratedKey.Size = new System.Drawing.Size(377, 29);
            this.btnEncryptGeneratedKey.TabIndex = 10;
            this.btnEncryptGeneratedKey.Text = "Encrypt Encode Add Generated Encryption Key";
            this.btnEncryptGeneratedKey.UseVisualStyleBackColor = true;
            this.btnEncryptGeneratedKey.Click += new System.EventHandler(this.btnEncryptGeneratedKey_Click);
            // 
            // btnSign
            // 
            this.btnSign.Location = new System.Drawing.Point(164, 12);
            this.btnSign.Name = "btnSign";
            this.btnSign.Size = new System.Drawing.Size(103, 29);
            this.btnSign.TabIndex = 11;
            this.btnSign.Text = "Sign XML";
            this.btnSign.UseVisualStyleBackColor = true;
            this.btnSign.Click += new System.EventHandler(this.btnSign_Click);
            // 
            // btnOpenXMLFile
            // 
            this.btnOpenXMLFile.Location = new System.Drawing.Point(29, 12);
            this.btnOpenXMLFile.Name = "btnOpenXMLFile";
            this.btnOpenXMLFile.Size = new System.Drawing.Size(129, 29);
            this.btnOpenXMLFile.TabIndex = 12;
            this.btnOpenXMLFile.Text = "Open XML File";
            this.btnOpenXMLFile.UseVisualStyleBackColor = true;
            this.btnOpenXMLFile.Click += new System.EventHandler(this.btnOpenXMLFile_Click);
            // 
            // label4
            // 
            this.label4.AutoSize = true;
            this.label4.Location = new System.Drawing.Point(852, 49);
            this.label4.Name = "label4";
            this.label4.Size = new System.Drawing.Size(135, 25);
            this.label4.TabIndex = 13;
            this.label4.Text = "Signed XML:";
            // 
            // tbEncrypted
            // 
            this.tbEncrypted.Location = new System.Drawing.Point(16, 230);
            this.tbEncrypted.Multiline = true;
            this.tbEncrypted.Name = "tbEncrypted";
            this.tbEncrypted.ScrollBars = System.Windows.Forms.ScrollBars.Both;
            this.tbEncrypted.Size = new System.Drawing.Size(754, 126);
            this.tbEncrypted.TabIndex = 14;
            // 
            // tbEncoded
            // 
            this.tbEncoded.Location = new System.Drawing.Point(778, 230);
            this.tbEncoded.Multiline = true;
            this.tbEncoded.Name = "tbEncoded";
            this.tbEncoded.ScrollBars = System.Windows.Forms.ScrollBars.Both;
            this.tbEncoded.Size = new System.Drawing.Size(739, 126);
            this.tbEncoded.TabIndex = 15;
            // 
            // label5
            // 
            this.label5.AutoSize = true;
            this.label5.Location = new System.Drawing.Point(712, 207);
            this.label5.Name = "label5";
            this.label5.Size = new System.Drawing.Size(503, 25);
            this.label5.TabIndex = 16;
            this.label5.Text = "Encoded XML (RequestSignatureEncryptedValue) :";
            // 
            // label3
            // 
            this.label3.AutoSize = true;
            this.label3.Location = new System.Drawing.Point(3, 374);
            this.label3.Name = "label3";
            this.label3.Size = new System.Drawing.Size(161, 25);
            this.label3.TabIndex = 17;
            this.label3.Text = "Symmetric Key:";
            // 
            // tbEncodedKey
            // 
            this.tbEncodedKey.Location = new System.Drawing.Point(1150, 365);
            this.tbEncodedKey.Name = "tbEncodedKey";
            this.tbEncodedKey.Size = new System.Drawing.Size(367, 31);
            this.tbEncodedKey.TabIndex = 18;
            // 
            // tbEncryptedKey
            // 
            this.tbEncryptedKey.Location = new System.Drawing.Point(685, 368);
            this.tbEncryptedKey.Name = "tbEncryptedKey";
            this.tbEncryptedKey.Size = new System.Drawing.Size(350, 31);
            this.tbEncryptedKey.TabIndex = 19;
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(564, 371);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(115, 25);
            this.label1.TabIndex = 20;
            this.label1.Text = "Encrypted:";
            // 
            // label6
            // 
            this.label6.AutoSize = true;
            this.label6.Location = new System.Drawing.Point(1041, 371);
            this.label6.Name = "label6";
            this.label6.Size = new System.Drawing.Size(103, 25);
            this.label6.TabIndex = 21;
            this.label6.Text = "Encoded:";
            // 
            // label7
            // 
            this.label7.AutoSize = true;
            this.label7.Location = new System.Drawing.Point(25, 207);
            this.label7.Name = "label7";
            this.label7.Size = new System.Drawing.Size(171, 25);
            this.label7.TabIndex = 22;
            this.label7.Text = "Encrypted XML :";
            // 
            // btnOAuth
            // 
            this.btnOAuth.Location = new System.Drawing.Point(803, 12);
            this.btnOAuth.Name = "btnOAuth";
            this.btnOAuth.Size = new System.Drawing.Size(189, 29);
            this.btnOAuth.TabIndex = 23;
            this.btnOAuth.Text = "Generate OAuth Key";
            this.btnOAuth.UseVisualStyleBackColor = true;
            this.btnOAuth.Click += new System.EventHandler(this.btnOAuth_Click);
            // 
            // tbOauthToken
            // 
            this.tbOauthToken.Location = new System.Drawing.Point(170, 405);
            this.tbOauthToken.Multiline = true;
            this.tbOauthToken.Name = "tbOauthToken";
            this.tbOauthToken.ScrollBars = System.Windows.Forms.ScrollBars.Both;
            this.tbOauthToken.Size = new System.Drawing.Size(338, 83);
            this.tbOauthToken.TabIndex = 24;
            // 
            // label8
            // 
            this.label8.AutoSize = true;
            this.label8.Location = new System.Drawing.Point(8, 412);
            this.label8.Name = "label8";
            this.label8.Size = new System.Drawing.Size(156, 25);
            this.label8.TabIndex = 25;
            this.label8.Text = "OAuth2 Token:";
            // 
            // btnCallHDFCApi
            // 
            this.btnCallHDFCApi.Location = new System.Drawing.Point(998, 12);
            this.btnCallHDFCApi.Name = "btnCallHDFCApi";
            this.btnCallHDFCApi.Size = new System.Drawing.Size(189, 29);
            this.btnCallHDFCApi.TabIndex = 26;
            this.btnCallHDFCApi.Text = "Call HDFC API";
            this.btnCallHDFCApi.UseVisualStyleBackColor = true;
            this.btnCallHDFCApi.Click += new System.EventHandler(this.btnCallHDFCApi_Click);
            // 
            // tbHDFCResponse
            // 
            this.tbHDFCResponse.Location = new System.Drawing.Point(685, 405);
            this.tbHDFCResponse.Multiline = true;
            this.tbHDFCResponse.Name = "tbHDFCResponse";
            this.tbHDFCResponse.ScrollBars = System.Windows.Forms.ScrollBars.Both;
            this.tbHDFCResponse.Size = new System.Drawing.Size(845, 83);
            this.tbHDFCResponse.TabIndex = 27;
            // 
            // tbDecryptedKey
            // 
            this.tbDecryptedKey.Location = new System.Drawing.Point(729, 494);
            this.tbDecryptedKey.Name = "tbDecryptedKey";
            this.tbDecryptedKey.Size = new System.Drawing.Size(386, 31);
            this.tbDecryptedKey.TabIndex = 28;
            // 
            // label9
            // 
            this.label9.AutoSize = true;
            this.label9.Location = new System.Drawing.Point(564, 408);
            this.label9.Name = "label9";
            this.label9.Size = new System.Drawing.Size(115, 25);
            this.label9.TabIndex = 29;
            this.label9.Text = "Response:";
            // 
            // label10
            // 
            this.label10.AutoSize = true;
            this.label10.Location = new System.Drawing.Point(12, 491);
            this.label10.Name = "label10";
            this.label10.Size = new System.Drawing.Size(147, 25);
            this.label10.TabIndex = 30;
            this.label10.Text = "Decoded Key:";
            // 
            // tbDecodedKey
            // 
            this.tbDecodedKey.Location = new System.Drawing.Point(170, 494);
            this.tbDecodedKey.Name = "tbDecodedKey";
            this.tbDecodedKey.Size = new System.Drawing.Size(386, 31);
            this.tbDecodedKey.TabIndex = 31;
            // 
            // label11
            // 
            this.label11.AutoSize = true;
            this.label11.Location = new System.Drawing.Point(564, 497);
            this.label11.Name = "label11";
            this.label11.Size = new System.Drawing.Size(159, 25);
            this.label11.TabIndex = 32;
            this.label11.Text = "Decrypted Key:";
            // 
            // label12
            // 
            this.label12.AutoSize = true;
            this.label12.Location = new System.Drawing.Point(8, 541);
            this.label12.Name = "label12";
            this.label12.Size = new System.Drawing.Size(160, 25);
            this.label12.TabIndex = 33;
            this.label12.Text = "Decoded XML :";
            // 
            // tbDecodedXML
            // 
            this.tbDecodedXML.Location = new System.Drawing.Point(12, 569);
            this.tbDecodedXML.Multiline = true;
            this.tbDecodedXML.Name = "tbDecodedXML";
            this.tbDecodedXML.ScrollBars = System.Windows.Forms.ScrollBars.Both;
            this.tbDecodedXML.Size = new System.Drawing.Size(739, 126);
            this.tbDecodedXML.TabIndex = 34;
            // 
            // label13
            // 
            this.label13.AutoSize = true;
            this.label13.Location = new System.Drawing.Point(773, 541);
            this.label13.Name = "label13";
            this.label13.Size = new System.Drawing.Size(172, 25);
            this.label13.TabIndex = 35;
            this.label13.Text = "Decrypted XML :";
            // 
            // tbDecryptedXML
            // 
            this.tbDecryptedXML.Location = new System.Drawing.Point(763, 569);
            this.tbDecryptedXML.Multiline = true;
            this.tbDecryptedXML.Name = "tbDecryptedXML";
            this.tbDecryptedXML.ScrollBars = System.Windows.Forms.ScrollBars.Both;
            this.tbDecryptedXML.Size = new System.Drawing.Size(754, 126);
            this.tbDecryptedXML.TabIndex = 36;
            // 
            // label14
            // 
            this.label14.AutoSize = true;
            this.label14.Location = new System.Drawing.Point(8, 707);
            this.label14.Name = "label14";
            this.label14.Size = new System.Drawing.Size(171, 25);
            this.label14.TabIndex = 37;
            this.label14.Text = "Response XML :";
            // 
            // tbResponseXML
            // 
            this.tbResponseXML.Location = new System.Drawing.Point(178, 701);
            this.tbResponseXML.Multiline = true;
            this.tbResponseXML.Name = "tbResponseXML";
            this.tbResponseXML.ScrollBars = System.Windows.Forms.ScrollBars.Both;
            this.tbResponseXML.Size = new System.Drawing.Size(999, 146);
            this.tbResponseXML.TabIndex = 38;
            // 
            // MainForm
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(12F, 25F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(1706, 877);
            this.Controls.Add(this.tbResponseXML);
            this.Controls.Add(this.label14);
            this.Controls.Add(this.tbDecryptedXML);
            this.Controls.Add(this.label13);
            this.Controls.Add(this.tbDecodedXML);
            this.Controls.Add(this.label12);
            this.Controls.Add(this.label11);
            this.Controls.Add(this.tbDecodedKey);
            this.Controls.Add(this.label10);
            this.Controls.Add(this.label9);
            this.Controls.Add(this.tbDecryptedKey);
            this.Controls.Add(this.tbHDFCResponse);
            this.Controls.Add(this.btnCallHDFCApi);
            this.Controls.Add(this.label8);
            this.Controls.Add(this.tbOauthToken);
            this.Controls.Add(this.btnOAuth);
            this.Controls.Add(this.label7);
            this.Controls.Add(this.label6);
            this.Controls.Add(this.label1);
            this.Controls.Add(this.tbEncryptedKey);
            this.Controls.Add(this.tbEncodedKey);
            this.Controls.Add(this.label3);
            this.Controls.Add(this.label5);
            this.Controls.Add(this.tbEncoded);
            this.Controls.Add(this.tbEncrypted);
            this.Controls.Add(this.label4);
            this.Controls.Add(this.btnOpenXMLFile);
            this.Controls.Add(this.btnSign);
            this.Controls.Add(this.btnEncryptGeneratedKey);
            this.Controls.Add(this.label2);
            this.Controls.Add(this.tbSignedXml);
            this.Controls.Add(this.tbData);
            this.Controls.Add(this.btnEncryptEncode);
            this.Controls.Add(this.tbKey);
            this.Font = new System.Drawing.Font("Microsoft Sans Serif", 10.2F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.Margin = new System.Windows.Forms.Padding(4);
            this.Name = "MainForm";
            this.Text = "Form1";
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion
        private System.Windows.Forms.TextBox tbKey;
        private System.Windows.Forms.Button btnEncryptEncode;
        private System.Windows.Forms.TextBox tbData;
        private System.Windows.Forms.TextBox tbSignedXml;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.Button btnEncryptGeneratedKey;
        private System.Windows.Forms.Button btnSign;
        private System.Windows.Forms.Button btnOpenXMLFile;
        private System.Windows.Forms.Label label4;
        private System.Windows.Forms.TextBox tbEncrypted;
        private System.Windows.Forms.TextBox tbEncoded;
        private System.Windows.Forms.Label label5;
        private System.Windows.Forms.Label label3;
        private System.Windows.Forms.TextBox tbEncodedKey;
        private System.Windows.Forms.TextBox tbEncryptedKey;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.Label label6;
        private System.Windows.Forms.Label label7;
        private System.Windows.Forms.Button btnOAuth;
        private System.Windows.Forms.TextBox tbOauthToken;
        private System.Windows.Forms.Label label8;
        private System.Windows.Forms.Button btnCallHDFCApi;
        private System.Windows.Forms.TextBox tbHDFCResponse;
        private System.Windows.Forms.TextBox tbDecryptedKey;
        private System.Windows.Forms.Label label9;
        private System.Windows.Forms.Label label10;
        private System.Windows.Forms.TextBox tbDecodedKey;
        private System.Windows.Forms.Label label11;
        private System.Windows.Forms.Label label12;
        private System.Windows.Forms.TextBox tbDecodedXML;
        private System.Windows.Forms.Label label13;
        private System.Windows.Forms.TextBox tbDecryptedXML;
        private System.Windows.Forms.Label label14;
        private System.Windows.Forms.TextBox tbResponseXML;
    }
}

