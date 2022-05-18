<?php

namespace Bash\Bundle\OIDCDBundle;

use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Session\SessionInterface;

class OidcdSessionStorage
{
    private RequestStack $requestStack;
    private string $clientName;

    public function __construct(RequestStack $requestStack, string $clientName)
    {
        $this->clientName = $clientName;
        $this->requestStack = $requestStack;
    }

    public function clearNonce(): void
    {
        $this->getSession()->remove($this->nonceKey());
    }

    public function clearRememberMe(): void
    {
        $this->getSession()->remove($this->rememberKey());
    }

    public function clearState(): void
    {
        $this->getSession()->remove($this->stateKey());
    }

    public function getNonce(): ?string
    {
        return $this->getSession()->get($this->nonceKey());
    }

    public function getRememberMe(): bool
    {
        return $this->getSession()->get($this->rememberKey()) ?? false;
    }

    public function getState(): ?string
    {
        return $this->getSession()->get($this->stateKey());
    }

    public function storeNonce(string $value): void
    {
        $this->getSession()->set($this->nonceKey(), $value);
    }

    public function storeRememberMe(bool $value): void
    {
        $this->getSession()->set($this->rememberKey(), $value);
    }

    public function storeState(string $value): void
    {
        $this->getSession()->set($this->stateKey(), $value);
    }

    private function getSession(): SessionInterface
    {
        return $this->requestStack->getSession();
    }

    private function nonceKey(): string
    {
        return 'bash.oidcd.session.nonce.'.$this->clientName;
    }

    private function rememberKey(): string
    {
        return 'bash.oidcd.session.remember_me.'.$this->clientName;
    }

    private function stateKey(): string
    {
        return 'bash.oidcd.session.state.'.$this->clientName;
    }
}
