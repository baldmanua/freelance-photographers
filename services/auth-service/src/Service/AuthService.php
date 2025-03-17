<?php

namespace App\Service;

use App\Entity\RefreshToken;
use App\Entity\User;
use App\Repository\RefreshTokenRepository;
use DateTimeImmutable;
use Doctrine\ORM\EntityManagerInterface;
use Exception;
use Firebase\JWT\Key;
use stdClass;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Firebase\JWT\JWT;

class AuthService
{
    public function __construct(
        private RefreshTokenRepository $refreshTokenRepository,
        private EntityManagerInterface $entityManager,
        private string $jwtSecretKey,
        private string $jwtRefreshKey,
        private string $alg,
        private int $accessTokenTTL,
        private int $refreshTokenTTL,
    ) {}

    public function generateTokens(User $user): array
    {
        return [
            'access_token'  => $this->generateAccessToken($user),
            'refresh_token' => $this->generateRefreshToken($user),
        ];
    }

    public function refreshToken(string $refreshToken): array
    {
        try {
            $tokenEntity = $this->refreshTokenRepository->findOneByToken($refreshToken);

            if (!$tokenEntity || $tokenEntity->getExpiresAt() < new DateTimeImmutable()) {
                throw new AuthenticationException('Invalid or expired refresh token');
            }

            $user = $tokenEntity->getUser();

            $this->entityManager->remove($tokenEntity);
            $this->entityManager->flush();

            return $this->generateTokens($user);
        } catch (Exception $e) {
            throw new AuthenticationException('Invalid refresh token');
        }
    }

    /**
     * @throws AuthenticationException
     */
    public function verifyToken(string $token, bool $isRefresh = false): string
    {
        $key = $isRefresh ? $this->jwtRefreshKey : $this->jwtSecretKey;
        try {
            $decodedToken = $this->decode($token, $key);
            return $decodedToken->sub;
        } catch (Exception $e) {
            throw new AuthenticationException('Invalid token');
        }
    }

    public function removeAllTokens(string $userId): void
    {
        $tokens = $this->refreshTokenRepository->findByUserId($userId);

        foreach ($tokens as $token) {
            $this->entityManager->remove($token);
        }

        $this->entityManager->flush();
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
        $token = bin2hex(random_bytes(64));
        $expiresAt = new DateTimeImmutable('+' . $this->refreshTokenTTL . ' seconds');

        $refreshToken = new RefreshToken();
        $refreshToken->setUser($user);
        $refreshToken->setToken($token);
        $refreshToken->setExpiresAt($expiresAt);

        $this->entityManager->persist($refreshToken);
        $this->entityManager->flush();

        return $token;
    }

    private function decode(string $token, string $key): stdClass
    {
        return JWT::decode($token, new Key($key, $this->alg));
    }
}