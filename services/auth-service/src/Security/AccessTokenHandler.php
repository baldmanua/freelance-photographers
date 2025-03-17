<?php
namespace App\Security;

use App\Service\AuthService;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Http\AccessToken\AccessTokenHandlerInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;

class AccessTokenHandler implements AccessTokenHandlerInterface
{
    public function __construct(
        private AuthService $authService,
    )
    {
    }

    public function getUserBadgeFrom(string $accessToken): UserBadge
    {
        try {
            /** @ToDo Change logic for storing refresh token as random hash in DB */
            $userId = $this->authService->verifyToken($accessToken);
        } catch (AuthenticationException $e) {
            throw new BadCredentialsException('Invalid credentials.');
        }

        return new UserBadge($userId);
    }
}