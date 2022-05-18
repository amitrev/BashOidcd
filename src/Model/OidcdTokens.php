<?php

namespace Bash\Bundle\OIDCDBundle\Model;

use Bash\Bundle\OIDCDBundle\Exception\OidcdException;
use DateTimeImmutable;
use stdClass;

class OidcdTokens
{
    private string $accessToken;
    private string $idToken;
    private ?DateTimeImmutable $expiry = null;
    private ?string $refreshToken = null;
    private ?array $scope = null;

    /** @throws OidcdException */
    public function __construct(stdClass $tokens)
    {
        // These are the only required parameters per https://tools.ietf.org/html/rfc6749#section-4.2.2
        if (!isset($tokens->id_token, $tokens->access_token)) {
            throw new OidcdException('Invalid token object.');
        }

        $this->accessToken = $tokens->access_token;
        $this->idToken = $tokens->id_token;

        if (isset($tokens->expires_in)) {
            $this->expiry = DateTimeImmutable::createFromFormat('U', (string) (time() + $tokens->expires_in));
        }

        if (isset($tokens->refresh_token)) {
            $this->refreshToken = $tokens->refresh_token;
        }

        if (isset($tokens->scope)) {
            $this->scope = explode(' ', $tokens->scope);
        }
    }

    public function getAccessToken(): string
    {
        return $this->accessToken;
    }

    public function getExpiry(): ?DateTimeImmutable
    {
        return $this->expiry;
    }

    public function getIdToken(): string
    {
        return $this->idToken;
    }

    public function getRefreshToken(): ?string
    {
        return $this->refreshToken;
    }

    public function getScope(): ?array
    {
        return $this->scope;
    }
}
