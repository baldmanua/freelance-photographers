<?php

namespace App\Repository;

use App\Entity\RefreshToken;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Persistence\ManagerRegistry;

/**
 * @extends ServiceEntityRepository<RefreshToken>
 */
class RefreshTokenRepository extends ServiceEntityRepository
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, RefreshToken::class);
    }

        public function findOneByToken($value): ?RefreshToken
        {
            return $this->createQueryBuilder('rt')
                ->andWhere('rt.token = :val')
                ->setParameter('val', $value)
                ->getQuery()
                ->getOneOrNullResult()
            ;
        }

    /**
     * @param string $userId
     * @return RefreshToken[]
     */
        public function findByUserId(string $userId): array
        {
            return $this->createQueryBuilder('rt')
                ->andWhere('rt.user = :user')
                ->setParameter('user', $userId)
                ->getQuery()
                ->getResult()
                ;
        }
}
