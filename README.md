<h1>HDFC_NEFT_Integration</h1>
The project is developed to enable HDFC customers to initiate NEFT transactions, for credit and/or debit.
You have to register with HDFC to get API access and required certificates
<br>
<h3>The highlevel process to achieve the end to end integration is as follow</h3>
A] Digitally sign the payload
<ol>
	<li>Create payload XML is HDFC format</li>
	<li>Use the client certificate (pem file) to sign the payload</li>
	<li>Add the certificate to the payload XML</li>
	</ol>
B] Encrypt the payload
	<ol>
	<li>Generate 32 byte key</li>
	<li>Use this key to encrypt the above XML (payload+signature)</li>
	</ol>
C] Encode the payload
	<ol>
	<li>Using base64 encode the encrypted XML</li>
	<li>This completes the data preparation to be sent to HDFC</li>
	</ol>
D] Key encryption & encoding
<ol>
	<li>Use the client certificate (pem file)</li>
	<li>Genrate RSA object using the above certificate</li>
	<li>Use RSA object to encrypt the key generated in B.1</li>
	<li>This completes the step to send key to HDFC</li>
	</ol>
E] Get oAuth2 token from HDFC API
<ol>
	<li>Use the client certificate (pfx file along with password)</li>
	<li>Use the username (client id) and password (client secrete) provided by HDFC</li>
	<li>Using HTTP client add all information in their respective place holders</li>
	<li>Call HDFC API URL using post</li>
	<li>You will get oAuth token as response</li>
	<li>This completes the oAuth generation step</li>
	</ol>
F] Call HDFC NEFT API
<ol>
	<li>Create a json to hold values from C.1, D.4, E.6</li>
	<li>Also include scope variable, whoose value is provided by HDFC alon with a transaction id (generated by us to track the status of request post it is submitted)</li>
	<li>Using HTTPClient call HDFC NEFT API and send the serialized json object</li>
	<li>You will get response back which wil indicate success or failuere code</li>
	</ol>
