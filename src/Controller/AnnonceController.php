<?php

namespace App\Controller;

use App\Entity\Photo;
use App\Entity\Coords;
use App\Entity\Annonce;
use App\Entity\SearchData;
use App\Form\SearchForm;
use App\Entity\Categorie;
use App\Form\AnnonceType;
use App\Repository\PhotoRepository;
use App\Repository\CoordsRepository;
use App\Repository\AnnonceRepository;
use App\Repository\CategorieRepository;
use Doctrine\ORM\EntityManagerInterface;
use App\Repository\CommentaireRepository;
use Symfony\Contracts\Cache\ItemInterface;
use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;



class AnnonceController extends AbstractController

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

    #[Route('/afficher', name: 'catalogue')]
    public function consulter_annonce(AnnonceRepository $repoannonce, CategorieRepository $repocategorie)
    {
        $annoncesArray = $repoannonce->findAll();
        $categoriesArray = $repocategorie->findAll();
        

        return $this->render('annonce/catalogue.html.twig',[
            "annonces"=>$annoncesArray,
            "categories"=>$categoriesArray,
            
        ]);
        
    }

        /**
     * 
     * @Route("/afficher/fiche_annonce/{id<\d+>}", name="fiche_annonce")
     */
    public function fiche_annonce(Annonce $annonceObject, AnnonceRepository $repoannonce, CommentaireRepository $repocommentaire, )
                // $id, annonceRepository $repoannonce    
        {
            $mesannonces=($annonceObject->getId());
            $comments_tab=sizeof($repocommentaire->findBy(["annonce"=>$mesannonces]));

            $user = $this->getUser()->getId();
            $fav=sizeof($annonceObject->getFavoris());
            

            // $repoannonce->findBy((["id"=>34]));
            // dd($repoannonce);// renvoie un objet
            // $deja_favoris=()->getFavoris();
            // dd(sizeof($deja_favoris));
            return $this->render("annonce/fiche_annonce.html.twig", [
                "annonce"=>$annonceObject,
                "commentaires"=>$repocommentaire->findBy(["annonce"=>$mesannonces]),
                "comments_tab"=>$comments_tab,
                "fav"=>$fav
            ]);
        }

    /**
     * @Route("/ajouter", name="annonce_ajouter")
     * 
     */
    public function annonce_ajouter(Request $request, EntityManagerInterface $manager, SessionInterface $session)
    {
        
        
        
        $test=$request->getSession();
        //dump($test);
        if($this->isGranted('IS_ANONYMOUS')) //si la personne connectée est anonyme
        { 
            $this->addFlash(
                'success',
                'Veuillez vous connecter pour pouvoir déposer une annonce'
            );
            return $this->redirectToRoute("login");
        }
        // ----------Je créé un nouvel objet annonce------------
        $annonce=new Annonce;
        // dd($annonce);
        $form = $this->createForm(AnnonceType::class, $annonce, array("ajouter"=>true));
        $form->handleRequest($request);
        
        
        /* $coord=new Coords;
        
        $annonce->$coord->setLat(2.48);
        $annonce->$coord->setLong(48.84);
        $annonce->addCoord($coord); */
        
        
        if ($form->isSubmitted() && $form->isValid()) {
            
            
            $annonce->setDateenregistrement(new \DateTimeImmutable('now'));
            $annonce->setActive(false);
            

            $user=$this->getUser();
            $annonce->setUser($user);
            
            $coords= new Coords;
            $coords->setLong(2.48);
            $coords->setLat(48.84);
            $annonce->addCoord($coords);


            

            $manager->persist($annonce);
            $manager->flush();
            $photoFile = $form->get('photo')->getData();

            if($photoFile)
            {
                
                //-- le champs photo est un tableau de mon entité annonce--
                for($c = 0; $c < count($photoFile); $c++)
                {
                // --- pour chaque tour de boucle, je génère un nom-----
                $nomImage = md5(uniqid()).'.'.$photoFile[$c]->guessExtension();
                
                // --Je copie le fichier dans le dossier uploads--
                $photoFile[$c]->move(
                    $this->getParameter('images_annonces'),$nomImage);
                // -- je créé un objet et je l'insère dans ma bdd
                $image = new Photo();
                $image->setNom($nomImage);
                $image->setAnnonce($annonce);// dans le champs annonce de mon objet image
                // il sait qu'il doit insérer la clef primaire
                $manager->persist($image); // on persiste l'instance
                $manager->flush(); // on envoie l'instance en BDD
            
                }
            }  
            $this->addFlash("success", "Votre annonce a bien été déposée");
            return $this->redirectToRoute("accueil");
        }
        return $this->render('annonce/annonce_ajouter.html.twig',[
            
            "formAnnonce"=>$form->createView()
        ]);
    }
    /**
     * @Route("/modifier/{id<\d+>}", name="annonce_modifier")
     */
    public function annonce_modifier(Annonce $annonce, Request $request, EntityManagerInterface $manager, PhotoRepository $repophotos) // objet de la class Annonce
    {

        $form = $this->createForm(AnnonceType::class, $annonce, array("modifier"=>true));
        //dump($form->createView());
        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid())
        {
            if($annonce->getPhotos()) // si get photos existe
                {
                    $photos=$repophotos->findBy(["annonce"=>$annonce->getId()]);
                    for($d = 0; $d < count($photos); $d++){
                        ($photos[$d]->getNom());
                        unlink($this->getParameter("images_annonces") . '/' . $photos[$d]->getNom()); 
                        $manager->remove($photos[$d]);
                        $manager->flush ();
                        
                    }
                }
            $photoFile=$form->get('photoFile')->getData();
            
            if($photoFile) // si une photo a été upload
            {
                for($c = 0; $c < count($photoFile); $c++)
                 
                {
                    
                    //dump("val de c:");//dump($c);
                    //dump($photoFile)[$c];
                    

                    $nomImage = md5(uniqid()).'.'.$photoFile[$c]->guessExtension(); // a chaque photo, j'attribue un onm
                    //dump("3");
                    //dump($nomImage);
                    $photoFile[$c]->move($this->getParameter("images_annonces"),$nomImage); // déplace dan upload
                    // -- je créé un objet et je l'insère dans ma bdd
                    $image = new Photo();
                    $image->setNom($nomImage);
                    $image->setAnnonce($annonce);// dans le champs annonce de mon objet image
                    // il sait qu'il doit insérer la clef primaire
                    $manager->persist($image); // on persiste l'instance
                    $manager->flush(); // on envoie l'instance en BDD
                }
            }
            $annonce->setActive(false);
            $manager->persist($annonce); //avec persist on peut ajouter ou modifier un annonce. Si l'id est null, il va créer l'annonce si l'id
            // existe, il va l'update.
            $manager->flush(); 

            $this->addFlash("success", "L'annonce N°" . $annonce->getId() . " a bien été modifiée");

            return $this->redirectToRoute("mes_annonces");
    
        }

        return $this->render('annonce/annonce_modifier.html.twig', [
            "annonce" => $annonce, /* ce 2eme argument est utile si on veut afficher des données de la variable dans le twig */
        "formAnnonce_modif"=>$form->createView()]);
    }
    /**
     * @Route("/supprimer/{id}", name="annonce_supprimer") 
     */
    public function annonce_supprimer(Annonce $annonce, EntityManagerInterface $manager, PhotoRepository $repophotos, CommentaireRepository $repocommentaire, CoordsRepository $repocoords ){
        
        $photos=$repophotos->findBy(["annonce"=>$annonce->getId()]);
        // dump($photos[0]->getNom());
        //dump($annonce);
            if ($photos){
                for ($i=0; $i < count($photos) ; $i++) { 
                    unlink($this->getParameter("images_annonces") . '/' . $photos[$i]->getNom()); 
                    $manager->remove($photos[$i]);        
                    }
                }
        $commentaire=$repocommentaire->findBy(["annonce"=>$annonce->getId()]);        
            if ($commentaire){
                for ($i=0; $i < count($commentaire) ; $i++) { 
                $manager->remove($commentaire[$i]);        
                    }
                }
                $idAnnonce=$annonce->getId();
                
        $coords=$repocoords->findBy(["annonce"=>$annonce->getId()]); 
          
            if ($coords){
                for ($i=0; $i < count($coords) ; $i++) { 
                $manager->remove($coords[$i]);        
                    }
                }
                
            
            
            $manager->remove($annonce);
            $manager->flush ();

            $this->addFlash("success","l'annonce $idAnnonce a bien été supprimée"); 
        

        return $this->redirectToRoute("mes_annonces");


    }
    #[Route('/annonce/mes_annonces', name: 'mes_annonces')]
    public function mesannonces(AnnonceRepository $repoannonce)
    {
        
        
        return $this->render('annonce/mes_annonces.html.twig',[
            "annonces"=>$repoannonce->findBy(['user'=>$this->getUser()->getId()]),
        ]);
        
    }

    /**
     * @Route("/index", name="index")
     */
    public function index(AnnonceRepository $repoannonce, Request $request, CoordsRepository $repoCoords, CacheInterface $cache,  CategorieRepository $catRepo): Response
    {
        // gestion Favoris
        if($this->isGranted('ROLE_USER')){
            $deja_favoris=$this->getUser()->getFavoris();
            
        }
        else{
            $deja_favoris="";
            
            
        }
        
        // pour la partie carto du menu gauche

        $requetes=$request->query->all();
        /* dd($requetes); */// renvoit array:3 ["q" => "" "min" => """max" => ""      ]
        if (isset($requetes)) {
            $requetes['q']="";

        }
                
        //dump($requetes);
        $data=new SearchData(); // je créé un objet et ses propriétés (q et categorie) et je le stocke dans $data
        
        //dump($data);// me renvoit un objet vide avec q:"", min"", max:"", page=1
        $data->page = $request->get('page', 1);
        
        $form = $this->createForm(SearchForm::class, $data);
        //dump($form); 
        
        $form->handleRequest($request);
        // je gère la requête
        [$min, $max] = $repoannonce->findMinMax($data);
        // je cherche en bdd le min max par rapport à la requête effectuée
        $filters = $request->get("categorie");
        //dump($filters);
        // renvoit un tableau avec les catégories cherchées

        $annonces=$repoannonce->findSearch($data);// effectue la requête grâce à getSearchQuery et 
        // découpe ma requête en pages
       
        
        $list=$annonces->getItems();
        //dump($list);
        // renvoie un tableaud des 9 annonces
        $coordsi=$repoCoords->findBy(array('annonce' => $list));

        $total = $repoannonce->getTotalAnnonces($data, $filters);
        //dump($total);
        $limit=9;
        // On récupère le numéro de page
        $page = (int)$request->query->get("page", 1);
        $categories=$catRepo->findAll();

        // On vérifie si on a une requête Ajax
        if($request->get('ajax')){
            
            return new JsonResponse([
                'content' => $this->renderView('annonce/_content.html.twig',[
                    "annonces"=>$annonces,
                    "form"=>$form->createView(),
                    'min' => $min,
                    'max' => $max,
                    "test" => $coordsi,
                    "total" => $total,
                    "page" => $page,
                    "requetes" => $requetes,
                    "deja_favoris"=>$deja_favoris
                    
        
                ])
            ]);
        }
        // On va chercher toutes les catégories
/*         $categories = $cache->get('categories_list', function(ItemInterface $item) use($catRepo){
            $item->expiresAfter(3600);

            return $catRepo->findAll();
        }); */
        
        return $this->render('annonce/index.html.twig',[
            "annonces"=>$annonces,
            "form"=>$form->createView(),
            'min' => $min,
            'max' => $max,
            "test" => $coordsi,
            "categories" => $categories,
            "page" => $page,
            "requetes" => $requetes,
            "total" => $total,
            "deja_favoris"=>$deja_favoris

        ]); 
        
    }

    /**
     * @Route("/activer/{id}", name="activer")
     */
    public function activer(Annonce $annonce)
    {
        $annonce->setActive(($annonce->getActive())?false:true);

        $em = $this->getDoctrine()->getManager();
        $em->persist($annonce);
        $em->flush();

        return new Response("true");
    }

    /**
     * @Route("/session_favori", name="ajout_favoris")
     */
    public function like(AnnonceRepository $repoannonce)
    {

        if($this->isGranted('ROLE_USER')){
            $deja_favoris=$this->getUser()->getFavoris();
            $test = $this->repoannonce->find($this->request->request->get('id')); // find (34)
            
            $existant = $this->request->request->get('state'); // find (34)
    
    
            if ($existant == 0) {
                // 1 -- 1 ere Requête select id where id=10
                $an_id=$this->request->request->get("id"); // 2--  Select objet annonce where id=34
                $test=$this
                ->getUser() // 3-- Requête select id where id=10
                ->addFavori($repoannonce
                ->find($this->request->request
                ->get("id"))); // 4 eme Requête Select moi le User de la table User INNER JOIN annonce_user on
                // t0.id=annonce_user.user_id Where annonce_user.annonce_id=34
                // Ce qui veut dire: sélectionne moi toutes les propriétés de User de la table User, joins moi la table annonce_user
                // ou l'id (ici de User est égal à annonce_user.user_id) et où annonce_user.annonce_id=34.
        
                $this->manager->persist($test); // INSERT INTO annonce_user (annonce_id, user_id) VALUES (34, 10);
                $this->manager->flush();
                $test="l'annonce a bien été ajoutée à vos favoris";
                
            }
            else{
                $test=$this
                ->getUser()
                ->removeFavori($repoannonce
                ->find($this->request->request
                ->get("id"))); 
                $this->manager->persist($test); // INSERT INTO annonce_user (annonce_id, user_id) VALUES (34, 10);
                $this->manager->flush();
                $test="l'annonce a bien été retirée de vos favoris";
                
            }
            
            $deja_favoris=$this->getUser()->getFavoris();
            
            $data = ["ok"=>$test,"class"=>$existant];
                
            
                
            return new JsonResponse($data);
         
        }
            
        
        else{
            return $this->redirectToRoute('login');;
        }    
            
    }
        
    #[Route('/mes_annonces_likees', name: 'mes_annonces_likees')]
    public function consulter_annonce_likees(AnnonceRepository $repoannonce)
    {
        $deja_favoris=$this->getUser()->getFavoris();
        

        return $this->render('annonce/mes_annonces_likees.html.twig',[
            "annonces"=>$deja_favoris,
            
            
        ]);
        
    }
        /**
     * @Route("/image/supprimer/{id}", name="image_annonce_supprimer") 
     * 
     * 
     */


    public function image_annonce_supprimer(Annonce $annonce, EntityManagerInterface $manager, PhotoRepository $repophotos) // objet de la class Annonce )
    {

        $photos=$repophotos->findBy(["annonce"=>$annonce->getId()]);
                    for($d = 0; $d < count($photos); $d++){
                        ($photos[$d]->getNom());
                        unlink($this->getParameter("images_annonces") . '/' . $photos[$d]->getNom()); 
                        $manager->remove($photos[$d]);
                        $manager->flush ();
                        
                    }

    
    

    return $this->redirectToRoute("annonce_modifier", ["id"=>$annonce->getId()]);
    }

}
