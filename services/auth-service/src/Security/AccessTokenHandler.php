<?php
namespace App\Security;

use App\Service\AuthService;
use Exception;
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
            $userId = $this->authService->verifyToken($accessToken);
        } catch (AuthenticationException $e) {
            throw new BadCredentialsException('Invalid credentials.');
        } catch (Exception $e) {
            throw new BadCredentialsException('Invalid token structure.');
        }

        return new UserBadge($userId);
    }
}