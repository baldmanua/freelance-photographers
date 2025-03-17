<?php

namespace App\Service;

use App\Entity\User;
use App\Repository\UserRepository;
use Exception;
use Firebase\JWT\Key;
use stdClass;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Firebase\JWT\JWT;

class AuthService
{

    public function __construct(
        private UserRepository $userRepository,
        private string $jwtSecretKey,
        private string $jwtRefreshKey,
        private string $alg,
        private int $accessTokenTTL,
        private int $refreshTokenTTL,
    )
    {
    }

    /**
     * @param User $user
     * @return string[] {}
     */
    public function generateTokens(User $user): array
    {
        return [
            'access_token'  => $this->generateAccessToken($user),
            'refresh_token' => $this->generateRefreshToken($user),
        ];
    }

    /**
     * @throws AuthenticationException
     */
    public function refreshToken(string $refreshToken): string
    {
        try {
            $decoded = $this->decode($refreshToken, $this->jwtRefreshKey);

            $user = $this->userRepository->find($decoded->sub);

            return $this->generateAccessToken($user);
        } catch (Exception $e) {
            throw new AuthenticationException('Invalid refresh token');
        }
    }

    /**
     * @throws AuthenticationException
     */
    public function verifyToken(string $token, bool $isRefresh = false): string
    {
        $key = $isRefresh? $this->jwtRefreshKey: $this->jwtSecretKey;
        try {
            $decodedToken = $this->decode($token, $key);
            return $decodedToken->sub;
        } catch (Exception $e) {
            throw new AuthenticationException('Invalid token');
        }
    }

    private function generateAccessToken(User $user): string
    {
        $payload = [
            'iss' => 'auth-service',
            'sub' => $user->getId(),
            'email' => $user->getEmail(),
            'roles' => $user->getRoles(),
            'iat' => time(),
            'exp' => time() + $this->accessTokenTTL,
        ];

        return JWT::encode($payload, $this->jwtSecretKey, $this->alg);
    }
    private function generateRefreshToken(User $user): string
    {
        $payload = [
            'iss' => 'auth-service',
            'sub' => $user->getId(),
            'iat' => time(),
            'exp' => time() + $this->refreshTokenTTL,
        ];

        return JWT::encode($payload, $this->jwtRefreshKey, $this->alg);
    }

    private function decode(string $token, string $key): stdClass
    {
        return JWT::decode($token, new Key($key, $this->alg));
    }
}