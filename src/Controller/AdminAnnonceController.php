<?php

namespace App\Controller;

use App\Entity\Photo;
use DateTimeImmutable;
use App\Entity\Annonce;
use App\Entity\SearchData;
use App\Form\SearchForm;
use App\Form\AnnonceType;
use App\Repository\PhotoRepository;
use App\Repository\CoordsRepository;
use App\Repository\AnnonceRepository;
use Doctrine\ORM\EntityManagerInterface;
use App\Repository\CommentaireRepository;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;


/**
 * @Route("/admin/gestion_annonce")
 */

class AdminAnnonceController extends AbstractController
{
    /**
     * @Route("/afficher", name="gestion_annonce_afficher")
     */
        public function annonce_afficher(AnnonceRepository $repoAnnonce)
        {
            $annoncesArray = $repoAnnonce->findAll();

            
            


            return $this->render('admin_annonce/annonce_afficher.html.twig', [
                "annonces" => $annoncesArray
            ]);
        }


    /**
     * @Route("/ajouter", name="gestion_annonce_ajouter")
     */
    public function annonce_ajouter(Request $request, EntityManagerInterface $manager)
    {

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
        //dd($annonce);
        $form = $this->createForm(AnnonceType::class, $annonce, array("ajouter"=>true));
        $form->handleRequest($request);
        
        if ($form->isSubmitted() && $form->isValid()) {
            
            $annonce->setDateenregistrement(new \DateTimeImmutable('now'));
            
            $user=$this->getUser();
            $annonce->setUser($user);

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
            $this->addFlash("success", "L'annonce N°" . $annonce->getId() . " a bien été déposée");
            return $this->redirectToRoute("accueil");
        }
        return $this->render('admin_annonce/annonce_ajouter.html.twig',[
            
            "formAnnonce"=>$form->createView()
        ]);
    }

    /**
     * @Route("/modifier/{id<\d+>}", name="gestion_annonce_modifier")
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
                    
                    //dump("val de c:");dump($c);
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
           
            $manager->persist($annonce); //avec persist on peut ajouter ou modifier un annonce. Si l'id est null, il va créer l'annonce si l'id
            // existe, il va l'update.
            $manager->flush(); 

            $this->addFlash("success", "L'annonce N°" . $annonce->getId() . " a bien été modifiée");

            return $this->redirectToRoute("gestion_annonce_afficher");
    
        }

        return $this->render('admin_annonce/annonce_modifier.html.twig', [
            "annonce" => $annonce, /* ce 2eme argument est utile si on veut afficher des données de la variable dans le twig */
        "formAnnonce_modif"=>$form->createView()]);
    }



 
    /**
     * @Route("/supprimer/{id}", name="gestion_annonce_supprimer") 
     */
    public function annonce_supprimer(Annonce $annonce, EntityManagerInterface $manager, PhotoRepository $repophotos, CommentaireRepository $repocommentaire, CoordsRepository $repocoords  ){
        
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

            $this->addFlash("success","l'annonce $idAnnonce bien été supprimée"); 
        

        return $this->redirectToRoute("gestion_annonce_afficher");


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

    
    

    return $this->redirectToRoute("gestion_annonce_modifier", ["id"=>$annonce->getId()]);
    }
    
}
