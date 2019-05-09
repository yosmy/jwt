<?php

namespace Yosmy\Jwt;

use Lcobucci\JWT;

/**
 * @di\service()
 */
class ManageToken
{
    /**
     * @var string
     */
    private $secret;

    /**
     * @di\arguments({
     *     secret: "%jwt_secret%"
     * })
     *
     * @param string $secret
     */
    public function __construct(string $secret)
    {
        $this->secret = $secret;
    }

    /**
     * @param string $key
     * @param string $value
     *
     * @return string
     */
    public function create(
        string $key,
        string $value
    ): string {
        return (string) (new JWT\Builder())
            ->set($key, $value)
            ->sign(new JWT\Signer\Hmac\Sha256(), $this->secret)
            ->getToken();
    }

    /**
     * @param string $token
     * @param string $key
     *
     * @return string
     *
     * @throws InvalidTokenException
     */
    public function verify(
        string $token,
        string $key
    ): string {
        $token = (new JWT\Parser())->parse($token);

        if (!$token->verify((new JWT\Signer\Hmac\Sha256()), $this->secret)) {
            throw new InvalidTokenException();
        }

        return $token->getClaim($key);
    }
}