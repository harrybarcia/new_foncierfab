<?php

namespace App\Repository;

use App\Entity\Annonce;
use App\Entity\SearchData;
use Doctrine\ORM\QueryBuilder;
use Doctrine\Persistence\ManagerRegistry;
use Knp\Component\Pager\PaginatorInterface;
use Knp\Component\Pager\Pagination\PaginationInterface;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;

/**
 * @method Annonce|null find($id, $lockMode = null, $lockVersion = null)
 * @method Annonce|null findOneBy(array $criteria, array $orderBy = null)
 * @method Annonce[]    findAll()
 * @method Annonce[]    findBy(array $criteria, array $orderBy = null, $limit = null, $offset = null)
 */
class AnnonceRepository extends ServiceEntityRepository
{
    public function __construct(ManagerRegistry $registry, PaginatorInterface $paginator)
    {
        parent::__construct($registry, Annonce::class);
        $this->paginator = $paginator;
    }
    /**
     * Récupère les produits en lien avec une recherche
     * @return PaginationInterface
     */
    public function findSearch(SearchData $search): PaginationInterface
    {
        $query = $this
            ->createQueryBuilder('an')
            ->select('c', 'an')
            ->join('an.categorie', 'c');
            
            if (!empty($search->q)) {
                $query = $query
                ->andWhere('an.titre LIKE :q')
                ->setParameter('q', "%{$search->q}%");
            }

            if (!empty($search->min)) {
                $query = $query
                ->andWhere('an.prix >= :min')
                ->setParameter('min', $search->min);
            }
            
            if (!empty($search->max)) {
                $query = $query
                ->andWhere('an.prix <= :max')
                ->setParameter('max', $search->max);
            }
            
            
            
            if (!empty($search->categorie)) {
                $query = $query
                ->andWhere('c.id IN (:categorie)')
                ->setParameter('categorie', $search->categorie);
            }
            
            
        $query = $this->getSearchQuery($search)->getQuery();
        return $this->paginator->paginate(
            $query,
            $search->page,
            20
            
        );
    } 
    /**
     * Récupère le prix minimum et maximum correspondant à une recherche
     * @return integer[]
     */
    public function findMinMax(SearchData $search): array
    {
        $results = $this->getSearchQuery($search, true)
            ->select('MIN(an.prix) as min', 'MAX(an.prix) as max')
            ->getQuery()
            ->getScalarResult();
        return [(int)$results[0]['min'], (int)$results[0]['max']];
    }

    private function getSearchQuery(SearchData $search, $ignorePrice = false ): QueryBuilder
    {
        $query = $this
            ->createQueryBuilder('an')
            ->select('c', 'an')
            ->join('an.categorie', 'c');
            
            if (!empty($search->q)) {
                $query = $query
                ->andWhere('an.titre LIKE :q')
                ->setParameter('q', "%{$search->q}%");
            }

            if (!empty($search->min) && $ignorePrice === false) {
                $query = $query
                ->andWhere('an.prix >= :min')
                ->setParameter('min', $search->min);
            }
            
            if (!empty($search->max) && $ignorePrice === false) {
                $query = $query
                ->andWhere('an.prix <= :max')
                ->setParameter('max', $search->max);
            }
            
            
            
            if (!empty($search->categorie)) {
                $query = $query
                ->andWhere('c.id IN (:categorie)')
                ->setParameter('categorie', $search->categorie);
            }
            
            return $query;
        }
        
    /**
     * @return void
     * 
     */
    
    public function getTotalAnnonces(SearchData $search, $filters = null, $ignorePrice = false, ){
        $query = $this->createQueryBuilder('a')
            ->select('COUNT(a)')
            ->where('a.active=1');
            
        if($filters != null){
            $query->andWhere('a.categorie IN(:cats)')
                ->setParameter(':cats', array_values($filters));
        }

        if (!empty($search->min) && $ignorePrice === false) {
            $query = $query
            ->andWhere('a.prix >= :min')
            ->setParameter('min', $search->min);
        }
        
        if (!empty($search->max) && $ignorePrice === false) {
            $query = $query
            ->andWhere('a.prix <= :max')
            ->setParameter('max', $search->max);
        }
        if (!empty($search->q)) {
            $query = $query
            ->andWhere('a.titre LIKE :q')
            ->setParameter('q', "%{$search->q}%");
        }

        return $query->getQuery()->getSingleScalarResult();
    }
    
}
