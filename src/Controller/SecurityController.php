<?php

namespace App\Controller;

use App\Entity\SearchData;
use App\Form\SearchForm;
use App\Repository\CoordsRepository;
use App\Repository\AnnonceRepository;
use App\Repository\UserRepository;
use Doctrine\ORM\EntityManagerInterface;
use PharIo\Manifest\Email;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\Mime\Email as MimeEmail;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;
use Symfony\Component\Security\Http\LoginLink\LoginLinkHandler;
use Symfony\Component\Security\Http\LoginLink\LoginLinkHandlerInterface;


class SecurityController extends AbstractController
{
    private $manager;
    private $requestStack;
    private $request;

    public function __construct(AnnonceRepository $repoannonce, EntityManagerInterface $manager, RequestStack $requestStack)
    {
        $this->repoannonce = $repoannonce;
        $this->manager = $manager;
        $this->requestStack = $requestStack;
        $this->request = $this->requestStack->getCurrentRequest();
    }


    /**
     * @Route("/login", name="login")
     */
    public function login(AuthenticationUtils $authenticationUtils): Response
    {
        if ($this->getUser()) {
             return $this->redirectToRoute('accueil');
         }

        // get the login error if there is one
        $error = $authenticationUtils->getLastAuthenticationError();
        // last username entered by the user
        $lastUsername = $authenticationUtils->getLastUsername();

        return $this->render('security/login.html.twig', ['last_username' => $lastUsername, 'error' => $error]);
    }


    #[Route('/', name: 'accueil')]
    public function accueil(CoordsRepository $repoCoords, Request $request, AnnonceRepository $repoannonce): Response
    {
        // coordonnées
        $coordsArray = $repoCoords->findAll();
        $annonceArray = $repoannonce->findAll();
        // formulaire filtre
        $data=new SearchData(); // je créé un objet et ses propriétés (q et categorie) et je le stocke dans $data
        $data->page = $request->get('page', 1);

/*         dd($data); */
         // je créé mon formulaire qui utilise la classe searchForm que je viens de créé, je précise en second paramètre les données. Comme ça quand je vais faire un handle request ca va modifier cet objet (new search data) qui représente mes données
        $form = $this->createForm(SearchForm::class, $data, [
            'action' => $this->generateUrl('index'),
        ]);
        $form->handleRequest($request);
        [$min, $max] = $repoannonce->findMinMax($data);

        $annonces_search=$repoannonce->findSearch($data);   
        //dump($repoannonce);

        return $this->render('annonce/accueil.html.twig', [
            'controller_name' => 'AnnonceController',
            "coords" => $coordsArray,
            "annonces" => $annonceArray,
            "annonces"=>$annonces_search,
            "form"=>$form->createView(),
            'min' => $min,
            'max' => $max

        ]);
    }

/**
     * @Route("/index_user", name="index_user")
     */
    public function index_user(AnnonceRepository $repoannonce, Request $request, CoordsRepository $repoCoords): Response
    {
        // pour la partie carto du menu gauche

        
        $deja_favoris=$this->getUser()->getFavoris();
    
        $data=new SearchData(); // je créé un objet et ses propriétés (q et categorie) et je le stocke dans $data
        $data->page = $request->get('page', 1);
        // je créé mon formulaire qui utilise la classe searchForm que je viens de créé, je précise en second paramètre les données. Comme ça quand je vais faire un handle request ca va modifier cet objet (new search data) qui représente mes données

        $form = $this->createForm(SearchForm::class, $data);

        $form->handleRequest($request);
        [$min, $max] = $repoannonce->findMinMax($data);

        $annonces=$repoannonce->findSearch($data);
        /* dump(gettype($annonces));
        //dump($annonces); */
        //dd($annonces); renvoit les items qui correspondent à la requête
        $list=$annonces->getItems();
        /* dump($list); */
        
        $coordsi=$repoCoords->findBy(array('annonce' => $list));
        // $filtre = $_GET["categorie"];
        // dump($filtre);
        // $test=$repoannonce->findByCategorie(["categorie"=>$filtre]);
        // if ($test) {
        //     return $this->render('annonce/test.html.twig', ["test"=>$test]);
        // }
        return $this->render('annonce/index_user.html.twig',[
            "annonces_user"=>$annonces,
            "form_user"=>$form->createView(),
            'min' => $min,
            'max' => $max,
            "test" => $coordsi,
            "deja_favoris"=>$deja_favoris
        ]); 
        
    }
    /**
     * @Route("/logout", name="logout")
     */
    public function logout(): void
    {
        throw new \LogicException('This method can be blank - it will be intercepted by the logout key on your firewall.');
    }

    
    #[Route('/mes_annonces_likees', name: 'mes_annonces_likees')]
    public function consulter_annonce(AnnonceRepository $repoannonce)
    {
        $deja_favoris=$this->getUser()->getFavoris();
        

        return $this->render('annonce/mes_annonces_likees.html.twig',[
            "annonces"=>$deja_favoris,
            
            
        ]);
        
    }

    /**
     * @Route("/magic", name="magic")
     * 
     */

    public function magic(UserRepository $userRepository, LoginLinkHandlerInterface $loginLinkHandler, MailerInterface $mailer): Response
    {
        $users=$userRepository->findAll();
        foreach ($users as $user) {
            $loginLinkDetails=$loginLinkHandler->createLoginLink($user);
            // dump($loginLinkDetails);
            $email=(new MimeEmail())
                ->from('bot@test.com')
                ->to($user->getEmail())
                ->text('your magic link is: '. $loginLinkDetails->getUrl());
                ;
            $mailer->send($email);
        }
    
        return new Response('Magic!');
    }


}
