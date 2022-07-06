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
            this.SuspendLayout();
            // 
            // tbKey
            // 
            this.tbKey.Location = new System.Drawing.Point(324, 556);
            this.tbKey.Name = "tbKey";
            this.tbKey.Size = new System.Drawing.Size(386, 27);
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
            this.tbData.Size = new System.Drawing.Size(754, 221);
            this.tbData.TabIndex = 5;
            // 
            // tbSignedXml
            // 
            this.tbSignedXml.Location = new System.Drawing.Point(778, 72);
            this.tbSignedXml.Multiline = true;
            this.tbSignedXml.Name = "tbSignedXml";
            this.tbSignedXml.ScrollBars = System.Windows.Forms.ScrollBars.Both;
            this.tbSignedXml.Size = new System.Drawing.Size(739, 221);
            this.tbSignedXml.TabIndex = 6;
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.Location = new System.Drawing.Point(3, 49);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(107, 20);
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
            this.label4.Size = new System.Drawing.Size(105, 20);
            this.label4.TabIndex = 13;
            this.label4.Text = "Signed XML:";
            // 
            // tbEncrypted
            // 
            this.tbEncrypted.Location = new System.Drawing.Point(16, 324);
            this.tbEncrypted.Multiline = true;
            this.tbEncrypted.Name = "tbEncrypted";
            this.tbEncrypted.ScrollBars = System.Windows.Forms.ScrollBars.Both;
            this.tbEncrypted.Size = new System.Drawing.Size(754, 221);
            this.tbEncrypted.TabIndex = 14;
            // 
            // tbEncoded
            // 
            this.tbEncoded.Location = new System.Drawing.Point(778, 324);
            this.tbEncoded.Multiline = true;
            this.tbEncoded.Name = "tbEncoded";
            this.tbEncoded.ScrollBars = System.Windows.Forms.ScrollBars.Both;
            this.tbEncoded.Size = new System.Drawing.Size(739, 221);
            this.tbEncoded.TabIndex = 15;
            // 
            // label5
            // 
            this.label5.AutoSize = true;
            this.label5.Location = new System.Drawing.Point(712, 301);
            this.label5.Name = "label5";
            this.label5.Size = new System.Drawing.Size(391, 20);
            this.label5.TabIndex = 16;
            this.label5.Text = "Encoded XML (RequestSignatureEncryptedValue) :";
            // 
            // label3
            // 
            this.label3.AutoSize = true;
            this.label3.Location = new System.Drawing.Point(12, 556);
            this.label3.Name = "label3";
            this.label3.Size = new System.Drawing.Size(310, 20);
            this.label3.TabIndex = 17;
            this.label3.Text = "Generated Key used for data encryption:";
            // 
            // tbEncodedKey
            // 
            this.tbEncodedKey.Location = new System.Drawing.Point(573, 589);
            this.tbEncodedKey.Name = "tbEncodedKey";
            this.tbEncodedKey.Size = new System.Drawing.Size(526, 27);
            this.tbEncodedKey.TabIndex = 18;
            // 
            // tbEncryptedKey
            // 
            this.tbEncryptedKey.Location = new System.Drawing.Point(110, 590);
            this.tbEncryptedKey.Name = "tbEncryptedKey";
            this.tbEncryptedKey.Size = new System.Drawing.Size(350, 27);
            this.tbEncryptedKey.TabIndex = 19;
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(15, 593);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(89, 20);
            this.label1.TabIndex = 20;
            this.label1.Text = "Encrypted:";
            // 
            // label6
            // 
            this.label6.AutoSize = true;
            this.label6.Location = new System.Drawing.Point(488, 593);
            this.label6.Name = "label6";
            this.label6.Size = new System.Drawing.Size(79, 20);
            this.label6.TabIndex = 21;
            this.label6.Text = "Encoded:";
            // 
            // label7
            // 
            this.label7.AutoSize = true;
            this.label7.Location = new System.Drawing.Point(25, 301);
            this.label7.Name = "label7";
            this.label7.Size = new System.Drawing.Size(134, 20);
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
            this.tbOauthToken.Location = new System.Drawing.Point(138, 632);
            this.tbOauthToken.Multiline = true;
            this.tbOauthToken.Name = "tbOauthToken";
            this.tbOauthToken.ScrollBars = System.Windows.Forms.ScrollBars.Both;
            this.tbOauthToken.Size = new System.Drawing.Size(338, 124);
            this.tbOauthToken.TabIndex = 24;
            // 
            // label8
            // 
            this.label8.AutoSize = true;
            this.label8.Location = new System.Drawing.Point(15, 635);
            this.label8.Name = "label8";
            this.label8.Size = new System.Drawing.Size(120, 20);
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
            this.tbHDFCResponse.Location = new System.Drawing.Point(573, 622);
            this.tbHDFCResponse.Multiline = true;
            this.tbHDFCResponse.Name = "tbHDFCResponse";
            this.tbHDFCResponse.ScrollBars = System.Windows.Forms.ScrollBars.Both;
            this.tbHDFCResponse.Size = new System.Drawing.Size(845, 124);
            this.tbHDFCResponse.TabIndex = 27;
            // 
            // Form1
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(10F, 20F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(1706, 768);
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
            this.Name = "Form1";
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
    }
}

