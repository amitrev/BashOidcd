<?php

namespace Bash\Bundle\OIDCDBundle\Model;

use Symfony\Component\PropertyAccess\PropertyAccess;
use Symfony\Component\PropertyAccess\PropertyAccessor;

class OidcdUserData
{
    private static ?PropertyAccessor $accessor = null;
    private \stdClass $userData;

    public function __construct(array $userData)
    {
        $this->userData = (object) $userData;
    }

    public function getSub(): string
    {
        return $this->getUserDataString('sub');
    }

    public function getFields(): array
    {
        return $this->getUserDataArray('fields');
    }

    public function getEmail(): string
    {
        return $this->getUserDataString('email');
    }

    public function getEmailVerified(): bool
    {
        return $this->getUserDataBoolean('email_verified');
    }

    public function getRefreshToken(): string
    {
        return $this->getUserDataString('refresh_token');
    }

    public function getIsAnonymous(): int
    {
        return $this->getUserDataInt('is_anonymous');
    }

    public function getUserDataBoolean(string $key): bool
    {
        return $this->getUserData($key) ?: false;
    }

    public function getUserDataInt(string $key): int
    {
        return $this->getUserData($key) ?: 0;
    }

    public function getUserDataString(string $key): string
    {
        return $this->getUserData($key) ?: '';
    }

    public function getUserDataArray(string $key): array
    {
        return $this->getUserData($key) ?: [];
    }

    public function getUserData(string $propertyPath)
    {
        self::$accessor ??= PropertyAccess::createPropertyAccessorBuilder()
            ->disableExceptionOnInvalidIndex()
            ->disableExceptionOnInvalidPropertyPath()
            ->getPropertyAccessor();

        return self::$accessor->getValue($this->userData, $propertyPath);
    }
}
