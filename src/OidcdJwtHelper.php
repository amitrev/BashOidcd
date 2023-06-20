<?php

namespace Bash\Bundle\OIDCDBundle;

use Bash\Bundle\OIDCDBundle\Exception\OidcdException;
use Bash\Bundle\OIDCDBundle\Model\OidcdTokens;
use Bash\Bundle\OIDCDBundle\Security\Exception\OidcdAuthenticationException;
use phpseclib3\Crypt\RSA;

class OidcdJwtHelper
{
    protected OidcdUrlFetcher $urlFetcher;
    protected OidcdSessionStorage $sessionStorage;
    private string $clientId;

    public function __construct(OidcdUrlFetcher $urlFetcher, OidcdSessionStorage $sessionStorage, string $clientId)
    {
        $this->clientId = $clientId;
        $this->sessionStorage = $sessionStorage;
        $this->urlFetcher = $urlFetcher;
    }

    /**
     * Per RFC4648, "base64 encoding with URL-safe and filename-safe
     * alphabet".  This just replaces characters 62 and 63.  None of the
     * reference implementations seem to restore the padding if necessary,
     * but we'll do it anyway.
     */
    private static function b64url2b64(string $base64url): string
    {
        $padding = strlen($base64url) % 4;
        if ($padding > 0) {
            $base64url .= str_repeat('=', 4 - $padding);
        }

        return strtr($base64url, '-_', '+/');
    }

    /**
     * A wrapper around base64_decode which decodes Base64URL-encoded data,
     * which is not the same alphabet as base64.
     */
    private static function base64url_decode(string $base64url)
    {
        return base64_decode(self::b64url2b64($base64url));
    }

    private static function urlEncode(string $str): string
    {
        $enc = base64_encode($str);
        $enc = rtrim($enc, '=');

        return strtr($enc, '+/', '-_');
    }

    /**
     * @throws OidcdException
     */
    public function decodeJwt(string $jwt, int $section = 0): ?object
    {
        if ($section < 0 || $section > 2) {
            throw new OidcdException('Invalid JWT section requested');
        }

        $parts = explode('.', $jwt);

        if (3 !== count($parts)) {
            // When there are not exactly three parts, the passed string is not a JWT
            return null;
        }

        try {
            return json_decode(self::base64url_decode($parts[$section]), false, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            return null;
        }
    }

    public function verifyJwtClaims(string $issuer, ?object $claims, OidcdTokens $tokens = null, bool $verifyNonce = true): bool
    {
        $expectedAtHash = '';

        if (null === $claims) {
            return false;
        }

        if (isset($claims->at_hash) && null !== $tokens->getAccessToken()) {
            $accessTokenHeader = $this->getAccessTokenHeader($tokens);
            if (isset($accessTokenHeader->alg) && 'none' !== $accessTokenHeader->alg) {
                $bit = substr($accessTokenHeader->alg, 2, 3);
            } else {
                // TODO: Error case. throw exception???
                $bit = '256';
            }
            $len = ((int) $bit) / 16;
            $expectedAtHash = self::urlEncode(substr(hash('sha'.$bit, $tokens->getAccessToken(), true), 0, $len));
        }

        // Get and remove nonce from session
        $nonce = $verifyNonce ? $this->sessionStorage->getNonce() : null;
        if (null !== $nonce) {
            $this->sessionStorage->clearNonce();
        }

        return ($claims->iss === $issuer)
            && (($claims->aud === $this->clientId) || in_array($this->clientId, $claims->aud, true))
            && (!$verifyNonce || $claims->nonce === $nonce)
            && (!isset($claims->exp) || $claims->exp >= time())
            && (!isset($claims->nbf) || $claims->nbf <= time())
            && (!isset($claims->at_hash) || $claims->at_hash === $expectedAtHash);
    }

    public function verifyJwtSignature(string $jwksUri, OidcdTokens $tokens): bool
    {
        // Check JWT information
        if (!$jwksUri) {
            throw new OidcdAuthenticationException('Unable to verify signature due to no jwks_uri being defined');
        }

        $parts = explode('.', $tokens->getIdToken());
        $signature = self::base64url_decode(array_pop($parts));
        try {
            $header = json_decode(self::base64url_decode($parts[0]), false, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            // TODO: Error case. throw exception???
            return false;
        }
        $payload = implode('.', $parts);
        try {
            $jwks = json_decode($this->urlFetcher->fetchUrl($jwksUri), false, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            // TODO: Error case. throw exception???
            return false;
        }
        if (null === $jwks) {
            throw new OidcdAuthenticationException('Error decoding JSON from jwks_uri');
        }

        // Check for supported signature types
        if (!in_array($header->alg, ['RS256', 'RS384', 'RS512'])) {
            throw new OidcdAuthenticationException('No support for signature type: '.$header->alg);
        }

        $hashType = 'sha'.substr($header->alg, 2);

        return $this->verifyRsaJwtSignature($hashType, $this->getKeyForHeader($jwks->keys, $header), $payload, $signature);
    }

    public function verifyRsaJwtSignature(string $hashtype, object $key, $payload, $signature): bool
    {
        if (!(property_exists($key, 'n') and property_exists($key, 'e'))) {
            throw new OidcdAuthenticationException('Malformed key object');
        }

        /**
         * We already have base64url-encoded data, so re-encode it as
         * regular base64 and use the XML key format for simplicity.
         */
        $public_key_xml = "<RSAKeyValue>\r\n".
            '  <Modulus>'.self::b64url2b64($key->n)."</Modulus>\r\n".
            '  <Exponent>'.self::b64url2b64($key->e)."</Exponent>\r\n".
            '</RSAKeyValue>';

        if (class_exists('\phpseclib3\Crypt\RSA')) {
            $rsa = RSA::load($public_key_xml)
                ->withPadding(RSA::ENCRYPTION_PKCS1 | RSA::SIGNATURE_PKCS1)
                ->withHash($hashtype);
        } else {
            throw new \RuntimeException('Unable to find phpseclib Crypt/RSA.php.  Ensure phpseclib/phpseclib is installed.');
        }

        return $rsa->verify($payload, $signature);
    }

    private function getAccessTokenHeader(OidcdTokens $tokens): ?object
    {
        try {
            return $this->decodeJwt($tokens->getAccessToken(), 0);
        } catch (OidcdException $e) {
            return null;
        }
    }

    private function getKeyForHeader($keys, $header): object
    {
        foreach ($keys as $key) {
            if ('RSA' === $key->kty) {
                if (!isset($header->kid) || $key->kid === $header->kid) {
                    return $key;
                }
            } elseif (isset($key->alg) && $key->alg === $header->alg && $key->kid === $header->kid) {
                return $key;
            }
        }
        if (isset($header->kid)) {
            throw new OidcdAuthenticationException(sprintf('Unable to find a key for (algorithm, kid): %s, %s', $header->alg, $header->kid));
        }

        throw new OidcdAuthenticationException('Unable to find a key for RSA');
    }
}
