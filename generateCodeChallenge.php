<?php
session_start();

function generatePKCECodePair() {
    try {
        // Generate a cryptographically strong random string
        $codeVerifier = bin2hex(random_bytes(32));

        // Compute the SHA-256 hash of the code verifier
        $hash = hash('sha256', $codeVerifier, true);

        // Base64url encode the hash
        $codeChallenge = base64url_encode($hash);

        return [
            'codeVerifier' => $codeVerifier,
            'codeChallenge' => $codeChallenge,
        ];
    } catch (Exception $e) {
        error_log("generateCodeChallenge - Error: " . $e->getMessage());
        throw $e;
    }
}

// Function to Base64url encode a string
function base64url_encode($data) {
    // Encode the data with base64 and replace characters to be URL-safe
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

function generateCodeChallenge() {
    // Generate PKCE code pair
    $pkceCodePair = generatePKCECodePair();

    // Generate a unique session ID
    $sessionId = bin2hex(random_bytes(16));
    $_SESSION['sessionIdCache'][$sessionId] = $pkceCodePair['codeVerifier'];

    // Set a cookie with the session ID
    setcookie('sid', $sessionId, [
        'expires' => time() + 3600, // Cookie expires in 1 hour
        'path' => '/',
        'secure' => false, // Use true if you are using HTTPS
        'httponly' => false,
    ]);

    // Return code challenge to the client
    header('Content-Type: application/json');
    echo json_encode([$pkceCodePair['codeChallenge']]);
}

generateCodeChallenge();
