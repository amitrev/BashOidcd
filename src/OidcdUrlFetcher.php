<?php

namespace Bash\Bundle\OIDCDBundle;

use Bash\Bundle\OIDCDBundle\Security\Exception\OidcdAuthenticationException;

class OidcdUrlFetcher
{
    private array $customClientHeaders;

    public function __construct(array $customClientHeaders)
    {
        $this->customClientHeaders = $customClientHeaders;
    }

    public function fetchUrl(string $url, ?array $params = null, array $headers = []): string
    {
        // Create a new cURL resource handle
        $ch = curl_init();

        // Determine whether this is a GET or POST
        if (null !== $params) {
            if (!is_array($params)) {
                throw new OidcdAuthenticationException('The parameters should be specified as array!');
            }

            $params = http_build_query($params);

            curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');
            curl_setopt($ch, CURLOPT_POSTFIELDS, $params);

            $headers[] = 'Content-Type: application/x-www-form-urlencoded';
            $headers[] = 'Content-Length: '.strlen($params);
        }

        // Add a User-Agent header to prevent firewall blocks
        $curlVersion = curl_version()['version'];
        $headers[] = "User-Agent: curl/$curlVersion bash/oidcd-bundle";

        $headers = array_merge($headers, $this->customClientHeaders);

        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_HEADER, 0);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 20);

        $output = curl_exec($ch);

        if (false === $output) {
            throw new OidcdAuthenticationException('Curl error: '.curl_error($ch));
        }

        curl_close($ch);

        return $output;
    }
}
