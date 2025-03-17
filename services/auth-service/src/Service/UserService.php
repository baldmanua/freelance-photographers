<?php

namespace App\Service;

use App\Entity\User;
use App\Repository\UserRepository;
use Doctrine\ORM\EntityManagerInterface;
use Exception;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;

class UserService
{

    public function __construct(
        private EntityManagerInterface $_em,
        private UserRepository $userRepository,
        private UserPasswordHasherInterface $passwordHasher,
    )
    {
    }

    /**
     * @throws Exception
     */
    public function registerUser(string $email, string $password, array $roles): User
    {
        $existingUser = $this->userRepository->findOneByEmail($email);
        if ($existingUser) {
            throw new Exception('User already exists');
        }

        $user = new User();
        $user->setEmail($email);
        $user->setRoles($roles);
        $hashedPassword = $this->passwordHasher->hashPassword(
            $user,
            $password
        );
        $user->setPassword($hashedPassword);

        $this->_em->persist($user);
        $this->_em->flush();

        return $user;
    }
}