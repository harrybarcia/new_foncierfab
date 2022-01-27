<?php

namespace App\Controller;

use App\Entity\Photo;
use App\Entity\Annonce;
use App\Entity\Commentaire;
use App\Form\CommentaireType;
use Doctrine\ORM\EntityManagerInterface;
use App\Repository\CommentaireRepository;
use App\Repository\PhotoRepository;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;

class CommentaireController extends AbstractController
{
    #[Route('/ajout_commentaire/{id}', name: 'ajout_commentaire')]
    public function deposer__commentaire(Request $request , EntityManagerInterface $manager, Annonce $annonce, PhotoRepository $repophotos)
    {
        //dd(strval($annonce->getId()));
        $comment = new Commentaire;
        $form = $this->createForm(CommentaireType::class, $comment);
        $form->handleRequest($request);
        if ($form->isSubmitted() && $form->isValid()) 
        {    
                $comment->setdateenregistrement(new \DateTimeImmutable('now'));
                $user=$this->getUser();
                //dump($user);
                $comment->setUSer($user);
                ;
                $comment->setAnnonce($annonce);
                $manager->persist($comment);
                $manager->flush();
                $this->addFlash(
                   'success',
                   'Votre commentaire a bien été pris en compte'
                );
                return $this->redirectToRoute('fiche_annonce', ['id'=>$annonce->getId()]);
        }

        if($annonce->getPhotos()) // si get photos existe
        {
            $photos=$repophotos->findBy(["annonce"=>$annonce->getId()]);

        }
        return $this->render('commentaire/commentaire.html.twig',[
            "formComment"=>$form->createView(),
            "photos"=>$photos,
            "annonce"=>$annonce
        ]);
        
    }

        /**
     
     * @Route("commentaire/modifier/{id}", name="commentaire_modifier")
     */
    public function commentaire_modifier(Commentaire $commentaire = null, Request $request, EntityManagerInterface $manager)
    {

     $form = $this->createForm(CommentaireType::class, $commentaire);

        $form->handleRequest($request);

        if($form->isSubmitted() && $form->isValid())
        {
            $modif = $commentaire->getId() !== null;

            $manager->persist($commentaire);
            $manager->flush();

            $this->addFlash("success", "Le commentaire a bien été modifié");
            
            return $this->redirectToRoute('mes_commentaires');
        }

        return $this->render("commentaire/commentaire_modifier.html.twig", [
            "formcommentaire_modif" => $form->createView(),
            "commentaire" => $commentaire,
            "modification" => $commentaire->getId() !== null
        ]);
    }
    #[Route('/commentaire/mes_commentaires', name: 'mes_commentaires')]
    public function mescommentaires(CommentaireRepository $repocommentaire)
    {
        return $this->render('commentaire/mes_commentaires.html.twig',[
            "commentaires"=>$repocommentaire->findBy(['user'=>$this->getUser()->getId()]),
        ]);
        
    }

       /**
     * @Route("/commentaire/supprimer/{id}", name="commentaire_supprimer") 
     */
    public function commentaire_supprimer(Commentaire $commentaire, EntityManagerInterface $manager, CommentaireRepository $repocommentaire ){
        

            $manager->remove($commentaire);
            $manager->flush ();

            $this->addFlash("success","le commentaire a bien été supprimé"); 
        

        return $this->redirectToRoute("mes_commentaires");


    }

}
