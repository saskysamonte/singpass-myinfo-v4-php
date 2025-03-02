# Singpass Myinfo v4 PHP
This is the PHP version of the MyInfo demo app, originally built in Node.js, showcasing integration with SingPass and usage of the MyInfo API.


### Install Dependencies
To install the necessary dependencies, navigate to the folder where the application was unzipped and run:

```
composer install
```

### Start PHP Server
Run the following command to start the PHP built-in server on localhost at port 3001:

```
php -S localhost:3001
```

### API Access
The Singpass API can only be accessed locally on port 3001. Ensure that your local environment is set up correctly to interact with the API through this port.
For more detailed instructions, troubleshooting, and setup, refer to the official Singpass API FAQ:

```
https://api.singpass.gov.sg/library/myinfo/developers/FAQ
```

### Accessing the Application
Once the server is running, you can access the sample application in your browser using the following URL:

```
http://localhost:3001
```

### Callback URL Information
Your callback URL must be registered in your Singpass Developer account. Please note that http://localhost:3001/callback is only for testing purposes. Custom callback URLs cannot be used for testing.

### Handling Encrypted User Information After Authorization
After successfully authorizing and receiving a token from SingPass, you will receive the user information in an encrypted format through the callback URL. 

### Callback URL and Decryption
After you authorize and receive a token from SingPass, the user information will be sent to your callback URL in an encrypted format. To decrypt the information, follow these steps:

- <b>Session Initialization:</b> Start a PHP session to handle the incoming data and maintain the state during the decryption process.

- <b>Load Dependencies:</b> Make sure the necessary libraries are included by using composer to install the required dependencies. These libraries will allow you to work with the encryption and decryption process.

- <b>Import Required Classes:</b> You’ll need to import various classes that help manage JSON Web Encryption (JWE) and JSON Web Signatures (JWS). Some of the key classes include:

- <b>JWK:</b> JSON Web Key, used to represent cryptographic keys.
- <b>JWSBuilder & JWSVerifier:</b> Used to build and verify JSON Web Signatures.
- <b>JWEDecrypter:</b> This class is responsible for decrypting the encrypted information.
- <b>Algorithm classes:</b> For managing different algorithms like ES256, RS256, and encryption algorithms like A256GCM and A256KW.
- <b>Decryption:</b> Once you have the encrypted user data from SingPass, use the appropriate decryption classes to decrypt it. The decryption process uses the JWEDecrypter to load the encrypted payload, decrypt it, and then extract the user information in a readable format.

- <b>Handling Errors and Security:</b> Ensure that you handle any errors related to encryption/decryption carefully, and also ensure that your server and libraries are securely configured to avoid potential vulnerabilities when dealing with sensitive user data.

### How It Works:
- Encryption and Decryption: The SingPass API uses industry-standard encryption algorithms (like A256GCM for content encryption and A256KW for key encryption) to securely send user information. These encryption algorithms ensure that the information is only accessible to authorized parties.

- Key Management: You will need to verify the signature and decrypt the payload using the right keys, which are managed through the JWK (JSON Web Key) system.
  
- PHP Libraries: The libraries (such as Jose\Component\Encryption) help with all of this by providing functionality for signing, verifying, and encrypting/decrypting data.

## Sample Screenshots
![Authorize API](https://github.com/saskysamonte/singpass-myinfo-v4-php/blob/main/screenshot_1.png)
![Authorize Singpass](https://github.com/saskysamonte/singpass-myinfo-v4-php/blob/main/screenshot_2.png)
![Callback Response](https://github.com/saskysamonte/singpass-myinfo-v4-php/blob/main/screenshot_3.png)
