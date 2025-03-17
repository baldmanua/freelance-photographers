<?php

namespace App\Service;

use App\Entity\User;
use Firebase\JWT\Key;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Firebase\JWT\JWT;

class AuthService
{

    public function __construct(
        private string $jwtSecretKey,
        private string $alg
    )
    {
    }

    public function generateToken(User $user): string
    {

        $payload = [
            'sub' => (string)$user->getId(),
            'email' => $user->getEmail(),
            'iat' => time(),
            'exp' => time() + 3600,
        ];

        return JWT::encode($payload, $this->jwtSecretKey, $this->alg);
    }

    /**
     * @throws \Exception
     */
    public function refreshToken(string $refreshToken): string
    {
        try {
            $decoded = JWT::decode($refreshToken, new Key($this->jwtSecretKey, $this->alg));

            return JWT::encode([
                'sub' => $decoded->sub,
                'iat' => time(),
                'exp' => time() + 3600,
            ], $this->jwtSecretKey, $this->alg);
        } catch (\Exception $e) {
            throw new \Exception('Invalid refresh token');
        }
    }

    public function verifyToken(string $token): void
    {
        try {
            JWT::decode($token, new Key($this->jwtSecretKey, $this->alg));
        } catch (\Exception $e) {
            throw new AuthenticationException('Invalid token');
        }
    }
}