<?php 
session_start();
require 'vendor/autoload.php'; 

use Jose\Component\Core\JWK;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Encryption\JWEDecrypter;
use Jose\Component\Encryption\JWELoader;
use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Encryption\JWE;  
use Jose\Component\Encryption\Algorithm\AlgorithmManager as EncryptionAlgorithmManager;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A256GCM;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A256KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHESA256KW;
use Jose\Component\Encryption\Serializer\CompactSerializer as JWECompactSerializer;


use GuzzleHttp\Client;

class SingpassAPI {

    private $tokenUrl = 'https://test.api.myinfo.gov.sg/com/v4/token';
    private $authApiUrl = 'https://test.api.myinfo.gov.sg/com/v4/authorize';
    private $clientId = 'STG2-MYINFO-SELF-TEST';
    private $scope = 'uinfin name sex race nationality dob email mobileno regadd housingtype hdbtype marital edulevel noa-basic ownerprivate cpfcontributions cpfbalances';
    private $purposeId = 'demonstration';
    private $method = "S256";
    private $redirectUrl = 'http://localhost:3001/callback';
    private $clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    public function generateClientAssertion($url, $clientId, $privateSigningKey, $jktThumbprint) {
        $now = time();
        $payload = [
            'sub' => $clientId,
            'jti' => bin2hex(random_bytes(20)),
            'aud' => $url,
            'iss' => $clientId,
            'iat' => $now,
            'exp' => $now + 300,
            'cnf' => [
                'jkt' => $jktThumbprint,
            ],
        ];

        $jwk = JWKFactory::createFromKey($privateSigningKey, null, [
            'kid' => 'aQPyZ72NM043E4KEioaHWzixt0owV99gC9kRK388WoQ',
            'use' => 'sig', // Use key for signing
            'alg' => 'ES256' // Specify algorithm
        ]);

        // Define the algorithm manager with the RS256 algorithm
        $algorithmManager = new AlgorithmManager([
            new ES256(),
        ]);

        $jwsBuilder = new JWSBuilder($algorithmManager);

        $headers = [
            'alg' => 'ES256',
            'typ' => 'JWT',
            'kid' => 'aQPyZ72NM043E4KEioaHWzixt0owV99gC9kRK388WoQ',
        ];

        // Create the JWS
        $jws = $jwsBuilder
            ->create()  // Create the JWS object
            ->withPayload(json_encode($payload)) // Set the payload
            ->addSignature($jwk, $headers) // Add the signature with the header
            ->build();    

        $serializer = new CompactSerializer();
        $request_token = $serializer->serialize($jws);

        return $request_token;
    }

    public function generateRandomString($length = 40) {
        return bin2hex(random_bytes($length / 2));
    }

    public function generateSessionKeyPair() {
        $config = [
            "curve_name" => "prime256v1",
            "private_key_type" => OPENSSL_KEYTYPE_EC,
        ];
        $res = openssl_pkey_new($config);
        if (!$res) {
            throw new Exception('Failed to generate key pair: ' . openssl_error_string());
        }

        openssl_pkey_export($res, $privateKey);
        $keyDetails = openssl_pkey_get_details($res);
        $publicKey = $keyDetails['key'];

        return [
            'privateKey' => $privateKey,
            'publicKey' => $publicKey,
        ];
    }

    public function getAccessToken($authCode, $codeVerifier, $sessionEphemeralKeyPair, $privateSigningKey) {
        return $this->callTokenAPI($authCode, $codeVerifier, $sessionEphemeralKeyPair, $privateSigningKey);
    }

    public function getPersonData($accessToken, $sessionEphemeralKeyPair, $privateEncryptionKeys) {
        $callPersonRequestResult = $this->getPersonDataWithToken($accessToken, $sessionEphemeralKeyPair, $privateEncryptionKeys);
        return $callPersonRequestResult;
    }

    private function getPersonDataWithToken($accessToken, $sessionEphemeralKeyPair, $privateEncryptionKeys){
        $jwksUrl = 'https://test.authorise.singpass.gov.sg/.well-known/keys.json';
        $decodedToken = $this->verifyJWS($accessToken, $jwksUrl);
        $uinfin = $decodedToken['sub'];
        $personResult = $this->callPersonAPI($uinfin, $accessToken, $sessionEphemeralKeyPair);
        if($personResult){
            print("<pre>".print_r('personResult: ' . $personResult,true)."</pre>");
            foreach ($privateEncryptionKeys as $key) {
                $jws = $this->decryptJWEWithKey($personResult, $key);
                // print("<pre>".print_r('jws: ' . $jws,true)."</pre>");
            }
        }
    }

    private function createJWKFromPEM($pemkey) {
        $keyData = str_replace(
            ['-----BEGIN EC PRIVATE KEY-----', '-----END EC PRIVATE KEY-----', "\n"],
            '',
            $pemkey
        );
        // Decode the base64 key data
        $keyData = base64_decode($keyData);

        // Create JWK from the key data
        $jwk = JWK::createFromKeyData($keyData, 'pem');

        return $jwk;
    }

    private function base64url_decode($data) {
        // Add padding if necessary
        $data = str_pad($data, strlen($data) % 4, '=', STR_PAD_RIGHT);
        // Replace URL-safe characters with standard base64 characters
        $data = strtr($data, '-_', '+/');
        // Decode base64
        return base64_decode($data);
    }
    
    private function decryptJWEWithKey($compactJWE, $encryptionPrivateKey) {
        // Convert PEM key to JWK (assuming EC private key in PEM format)
        $jwk = JWKFactory::createFromKey($encryptionPrivateKey, null, [
            'use' => 'enc',
            'alg' => 'ECDH-ES+A256KW'
        ]);

        // Split the JWE compact serialization into its 5 parts
        $jweParts = explode('.', $compactJWE);
        if (count($jweParts) != 5) {
             throw new Exception('Invalid JWE format');
        }

        // Deserialize JWE compact string
        $serializer = new JWECompactSerializer();
        $jwe = $serializer->unserialize($compactJWE);

         // Create an AlgorithmManager with supported algorithms
        $algorithmManager = new AlgorithmManager([
            new ECDHESA256KW(), // Key Encryption algorithm
            new A256GCM()       // Content Encryption algorithm
        ]);

        $jweDecrypter = new JWEDecrypter($algorithmManager);
        $isDecrypted = $jweDecrypter->decryptUsingKey($jwe, $jwk, 0);
        if ($isDecrypted) {
            $payload = $jwe->getPayload();
            $decodedPayload = $this->decodeJWT($payload);
            print("<pre>".print_r($decodedPayload,true)."</pre>");
        }
        
    }

    private function decodeJWT($jwt) {
        // Split the JWT into its parts
        list($header, $payload, $signature) = explode('.', $jwt);
        // Decode the payload
        $payload = base64_decode(str_replace(['-', '_'], ['+', '/'], $payload));
        // Convert JSON to associative array
        $decodedPayload = json_decode($payload, true);
        return $decodedPayload;
    }
    
    public function verifyJWS($compactJWS, $jwksUrl)
    {
        $jwks = $this->getJwks($jwksUrl);
        $jwkSet = JWKSet::createFromKeyData($jwks);
        $serializer = new CompactSerializer();
        $jws = $serializer->unserialize($compactJWS);
        $algorithmManager = new AlgorithmManager([new ES256()]);
        $jwsVerifier = new JWSVerifier($algorithmManager);
        $isValid = $jwsVerifier->verifyWithKeySet($jws, $jwkSet, 0);
        $payload = json_decode($jws->getPayload(), true);
        return $payload;
    }

    private function getJwks($jwksUrl)
    {
        // Fetch JWKS from the URL
        $response = file_get_contents($jwksUrl);
        if ($response === false) {
            throw new Exception('Failed to fetch JWKS from URL');
        }
        return json_decode($response, true);
    }

    private function callTokenAPI($authCode, $codeVerifier, $sessionEphemeralKeyPair, $privateSigningKey) {
        $client = new Client();
        $jktThumbprint = $this->generateJwkThumbprint($sessionEphemeralKeyPair['publicKey']);
        // print("<pre>".print_r('jktThumbprint: ',true)."</pre>");
        // print("<pre>".print_r($jktThumbprint,true)."</pre>");

        $clientAssertion = $this->generateClientAssertion($this->tokenUrl, $this->clientId, $privateSigningKey, $jktThumbprint);

        // print("<pre>".print_r('clientAssertion: ',true)."</pre>");
        // print("<pre>".print_r($clientAssertion,true)."</pre>");

        $dPoP = $this->generateDpop($this->tokenUrl, '', 'POST', $sessionEphemeralKeyPair);

        // print("<pre>".print_r('dPoP: ',true)."</pre>");
        // print("<pre>".print_r($dPoP,true)."</pre>");

        $params = [
            'grant_type' => 'authorization_code',
            'code' => $authCode,
            'redirect_uri' => $this->redirectUrl,
            'client_id' => $this->clientId,
            'code_verifier' => $codeVerifier,
            'client_assertion_type' => $this->clientAssertionType,
            'client_assertion' => $clientAssertion,
        ];

        $headers = [
            'Content-Type' => 'application/x-www-form-urlencoded',
            'Cache-Control' => 'no-cache',
            'DPoP' => $dPoP,
        ];

        $response = $client->post($this->tokenUrl, [
            'headers' => $headers,
            'form_params' => $params,
        ]);

        $response_body = json_decode($response->getBody(), true);
        $accessToken = $response_body['access_token'];

        // $privateEncryptionKeys = $this->loadPrivateEncryptionKeys("./cert/encryption-private-keys/");

        $directoryPath = __DIR__ . '/cert/encryption-private-keys/';
        $privateEncryptionKeys = [];

        $files = scandir($directoryPath);
        foreach ($files as $file) {
            // Skip the special entries '.' and '..'
            if ($file === '.' || $file === '..') {
                continue;
            }
            $filePath = $directoryPath . $file;
            // Ensure it's a file
            if (is_file($filePath)) {
                $content = file_get_contents($filePath);
                if ($content === false) {
                    // Handle error - the file could not be read
                    die("Failed to read file: $filePath");
                }
                // Decode content if needed, for example, assuming utf8
                $privateEncryptionKeys[] = $content;
            }
        }

        //  print("<pre>".print_r($privateEncryptionKeys,true)."</pre>");

        $getPersonResponse = $this->getPersonData($accessToken, $sessionEphemeralKeyPair, $privateEncryptionKeys);
        return $getPersonResponse;
    }

    private function callPersonAPI($sub, $accessToken, $sessionEphemeralKeyPair) {
        $personURL = 'https://test.api.myinfo.gov.sg/com/v4/person';
        $urlLink = $personURL . '/' . $sub;

        $ath = $this->base64url_encode(hash('sha256', $accessToken, true));
        $dPoP = $this->generateDpop($urlLink, $ath, 'GET', $sessionEphemeralKeyPair);

        $app_scopes = "uinfin name sex race nationality dob email mobileno regadd housingtype hdbtype marital edulevel noa-basic ownerprivate cpfcontributions cpfbalances";
        $strParams = "scope=" . urlencode($app_scopes);

        $params = [
            'scope' => $app_scopes
        ];

        $headers = [
            'Content-Type' => 'application/x-www-form-urlencoded',
            'Cache-Control' => 'no-cache',
            'dpop' => $dPoP,
            'Authorization' => 'DPoP ' . $accessToken
        ];

        $parsedUrl = parse_url($personURL);
        $domain = $parsedUrl['host'];

        $requestPath = $parsedUrl['path'] . "/$sub?$strParams";

        // Full URL for the API request
        $fullUrl = "https://" . $domain . $requestPath;
        // print("<pre>".print_r("fullUrl: " . $fullUrl,true)."</pre>");
        // print("<pre>".print_r("Domain: " . $domain,true)."</pre>");
        // print("<pre>".print_r("Path: " . $requestPath,true)."</pre>");

        $client = new Client();

        $method = "GET"; 
        $response = $client->request($method, $fullUrl, [
            'headers' => $headers,
            // 'form_params' => $params,
        ]);
        $responseBody = $response->getBody();
        return $responseBody;
    }

    public function loadPrivateEncryptionKeys($directoryPath)
    {
        $privateEncryptionKeys = [];
        $files = glob($directoryPath . '/*'); // Retrieve all files from the directory

        if ($files === false) {
            throw new Exception('Failed to retrieve files from directory');
        }

        foreach ($files as $filename) {
            try {
                $content = file_get_contents($filename);

                if ($content === false) {
                    throw new Exception("Failed to read file: $filename");
                }

                // Decode content if necessary
                $decodedContent = mb_convert_encoding($content, 'UTF-8', mb_detect_encoding($content));
                
                $privateEncryptionKeys[] = $decodedContent;
            } catch (Exception $e) {
                error_log('Error reading file ' . $filename . ': ' . $e->getMessage());
                throw $e;
            }
        }
    }

    private function generateDpop($url, $ath, $method, $sessionEphemeralKeyPair) {
        $now = time();

        $privateKey = $sessionEphemeralKeyPair['privateKey'];
        $publicKey = $sessionEphemeralKeyPair['publicKey'];
        
        // Extract public key coordinates for JWK
        $publicKeyCoordinates = $this->extractPublicKeyCoordinates($publicKey);

        // Generate JWK (JSON Web Key) with the public key information
        $jwk = [
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => $publicKeyCoordinates['x'],
            'y' => $publicKeyCoordinates['y']
        ];

        // Generate a unique key ID (kid)
        // $kid = 'aQPyZ72NM043E4KEioaHWzixt0owV99gC9kRK388WoQ';
        $kid = $this->base64url_encode(hash('sha256', json_encode($jwk), true)); // Using SHA-256 hash for simplicity

        // Create the JWT header with the dpop+jwt type and include the JWK
        $header = [
            'typ' => 'dpop+jwt',
            'alg' => 'ES256',
            'jwk' => array_merge($jwk, ['kid' => $kid])
        ];

        // Create JWT payload
        $payload = [
            'jti' => $this->generateRandomString(40), // Unique identifier for the JWT
            'htu' => $url,                          // URL of the protected resource
            'htm' => $method,                       // HTTP method used for the request
            'iat' => $now,                         // Issued at time
            'exp' => $now + 120,                   // Expiration time (short-lived)
            'ath' => $ath // Example authorization token (may need adjustment)
        ];

        // Create JWK from the private key for signing
        $jwkPrivate = JWKFactory::createFromKey($privateKey, 'pem'); // Pass private key as PEM encoded string

        // Create Algorithm Manager with ES256
        $algorithmManager = new AlgorithmManager([
            new ES256(),
        ]);

        // Create JWS Builder
        $jwsBuilder = new JWSBuilder($algorithmManager);

        // Build JWS with header and payload
        $jws = $jwsBuilder->create()
            ->withPayload(json_encode($payload))
            ->addSignature($jwkPrivate, $header)  // Add the signature with the header
            ->build();

        // Serialize JWS to compact form
        $serializer = new CompactSerializer();
        $dPoPProof = $serializer->serialize($jws);

        return $dPoPProof;
    }

    private function generateJwkThumbprint($publickey) {
        // Extract public key coordinates
        $coordinates = $this->extractPublicKeyCoordinates($publickey);

        // Create JWK JSON object
        $jwk = [
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => $coordinates['x'],
            'y' => $coordinates['y'],
        ];

        // Convert JWK to JSON
        $jwkJson = json_encode($jwk, JSON_UNESCAPED_SLASHES);

        // Canonicalize the JSON by sorting keys
        $canonicalJwkJson = $this->canonicalizeJson($jwkJson);

        // Compute SHA-256 hash of the canonicalized JSON
        $hash = hash('sha256', $canonicalJwkJson, true);

        // Base64URL encode the hash
        $thumbprint = $this->base64url_encode($hash);

        return $thumbprint;
    }

    private function canonicalizeJson($json) {
        $data = json_decode($json, true);
        ksort($data);
        return json_encode($data, JSON_UNESCAPED_SLASHES);
    }

    private function extractPublicKeyCoordinates($publicKeyPem) {
        // Convert PEM to DER format
        $publicKeyDer = $this->pemToDer($publicKeyPem);
    
        // Parse the DER encoded public key
        $keyData = openssl_pkey_get_details(openssl_pkey_get_public($publicKeyPem));
        
        // Get the x and y coordinates
        $x = $this->base64url_encode($keyData['ec']['x']);
        $y = $this->base64url_encode($keyData['ec']['y']);
    
        return ['x' => $x, 'y' => $y];
    }

    private function pemToDer($pem) {
        $pem = trim($pem);
        $pem = str_replace(["-----BEGIN PUBLIC KEY-----", "-----END PUBLIC KEY-----", "\n"], '', $pem);
        return base64_decode($pem);
    }

    private function base64url_encode($data) {
        return str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($data));
    }
    
}

if (isset($_GET['code'])) {
    $api = new SingpassAPI();
    $authCode = $_GET['code'];
    $codeVerifier = $_SESSION['sessionIdCache'][$_COOKIE['sid']];

    // Output JavaScript to set sessionStorage
    echo "<script>
    // Set sessionStorage values from PHP
    window.sessionStorage.setItem('codeVerifier', '" . addslashes($codeVerifier) . "');
    </script>";
    $privateSigningKeyPath = __DIR__ . '/cert/your-sample-app-signing-private-key.pem';
    $privateSigningKey = file_get_contents($privateSigningKeyPath);
    $sessionEphemeralKeyPair = $api->generateSessionKeyPair();
    $response = $api->getAccessToken($authCode, $codeVerifier, $sessionEphemeralKeyPair, $privateSigningKey);
}

session_unset();
session_destroy();
?>


<!DOCTYPE html>
<html lang="en">

<head>
	<meta charset="utf-8">
	<title>Sample Application</title>
    <script src="http://code.jquery.com/jquery-3.7.1.min.js"></script>
	<script>
    // ---START---SETUP VARIABLES---
    var scrollToAppForm = false;
    var authApiUrl = 'https://test.api.myinfo.gov.sg/com/v4/authorize'; // URL for authorize API
    var clientId = 'STG2-MYINFO-SELF-TEST'; // your app_id/client_id provided to you during onboarding
    var redirectUrl = 'http://localhost:3001/callback'; // callback url for your application
    var purpose_id = 'demonstration'; // The purpose of your data retrieval
    var scope = "uinfin name sex race nationality dob email mobileno regadd housingtype hdbtype marital edulevel noa-basic ownerprivate cpfcontributions cpfbalances"; // the attributes you are retrieving for your application to fill the form
    var method = "S256"
    var securityEnable = true; // the auth level, determines the flow
    var clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    // ---END---SETUP VARIABLES---
    
	// ---START---MAIN HANDLER---
    $(function () {
        $("#formAuthorize").submit(function (event) {
            event.preventDefault();
            callAuthorizeApi();
        });
    });
    // ---END---MAIN HANDLER---	

    // ---START---AUTH API---
    function callAuthorizeApi() {
        //Call backend server to generate code challenge 
        $.ajax({
            url: "/generateCodeChallenge.php",
            data: {},
            type: "POST",
            success: function (result) {
                //Redirect to authorize url after generating code challenge
                var authorizeUrl = authApiUrl + "?client_id=" + clientId +
                    "&scope=" + scope +
                    "&purpose_id=" + purpose_id +
                    "&code_challenge=" + result +
                    "&code_challenge_method=" + method +
                    "&redirect_uri=" + redirectUrl;

                window.location = authorizeUrl;
            },
            error: function (result) {
                alert("ERROR:" + JSON.stringify(result.responseJSON.error));
            }
        });
    }
    // ---END---AUTH API---

    // ---END---CALL SERVER API - calling server side APIs (token & person) to get the person data for prefilling form

	</script>

</head>

<body>
    <form id="formAuthorize">
        <a href="#" onclick="$(this).closest('form').submit()" class="btn2">Retrieve MyInfo</a>
    </form>
</body>

</html>
