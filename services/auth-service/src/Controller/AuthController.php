<?php

namespace App\Controller;

use App\Entity\User;
use Exception;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use App\Service\AuthService;
use App\Service\UserService;
use Symfony\Component\Security\Http\Attribute\CurrentUser;

class AuthController extends AbstractController
{
    private AuthService $authService;
    private UserService $userService;

    public function __construct(AuthService $authService, UserService $userService)
    {
        $this->authService = $authService;
        $this->userService = $userService;
    }

    #[Route('/auth/login', name: 'login', methods: ['POST'])]
    public function login(#[CurrentUser] ?User $user): Response
    {
        if (null === $user) {
            return $this->json([
                'message' => 'missing credentials',
            ], Response::HTTP_UNAUTHORIZED);
        }

        $tokens = $this->authService->generateTokens($user);

        return $this->json([
            'user' => $user->getUserIdentifier(),
            'tokens' => $tokens,
        ]);
    }

    #[Route('/auth/register', methods: ['POST'])]
    public function register(Request $request): JsonResponse
    {
        $data = json_decode($request->getContent(), true);
        $email = $data['email'] ?? '';
        $password = $data['password'] ?? '';
        $roles = $data['roles'] ?? ['client'];

        try {
            $user = $this->userService->registerUser($email, $password, $roles);
            return new JsonResponse(['message' => 'User registered successfully', 'user' => $user], JsonResponse::HTTP_CREATED);
        } catch (Exception $e) {
            return new JsonResponse(['error' => $e->getMessage()], JsonResponse::HTTP_BAD_REQUEST);
        }
    }

    #[Route('/auth/refresh', methods: ['POST'])]
    public function refresh(Request $request): JsonResponse
    {
        $data = json_decode($request->getContent(), true);
        $refreshToken = $data['refresh_token'] ?? '';

        try {
            $newTokens = $this->authService->refreshToken($refreshToken);
            return new JsonResponse(['tokens' => $newTokens]);
        } catch (Exception $e) {
            return new JsonResponse(['error' => $e->getMessage()], JsonResponse::HTTP_UNAUTHORIZED);
        }
    }

    #[Route('/auth/verify', methods: ['GET'])]
    public function verify(): JsonResponse
    {
        return new JsonResponse(['message' => 'AccessToken is valid']);
    }

    #[Route('/auth/logout', methods: ['POST'])]
    public function logout(): JsonResponse
    {
        /** @var User $user */
        $user = $this->getUser();
        $this->authService->removeAllTokens($user->getId());
        return new JsonResponse(['message' => "Logged out"]);
    }

}