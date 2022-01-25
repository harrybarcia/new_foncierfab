<?php

namespace App\Entity;

use App\Repository\CommentaireRepository;
use Doctrine\ORM\Mapping as ORM;
use Symfony\Component\Validator\Constraints as Assert;

/**
 * @ORM\Entity(repositoryClass=CommentaireRepository::class)
 */
class Commentaire
{
    /**
     * @ORM\Id
     * @ORM\GeneratedValue
     * @ORM\Column(type="integer")
     */
    private $id;

    /**
     * @ORM\ManyToOne(targetEntity=User::class, inversedBy="Commentaires")
     */
    private $user;

    /**
     * @ORM\ManyToOne(targetEntity=Annonce::class, inversedBy="Commentaires")
     */
    private $annonce;

    /**
     * @ORM\Column(type="text")
     * @Assert\NotBlank(message="Veuillez saisir un commentaire")
     */
    private $commentaire;

    /**
     * @ORM\Column(type="datetime")
     */
    private $dateenregistrement;

    public function getId(): ?int
    {
        return $this->id;
    }

    public function getUser(): ?User
    {
        return $this->user;
    }

    public function setUser(?User $user): self
    {
        $this->user = $user;

        return $this;
    }

    public function getAnnonce(): ?annonce
    {
        return $this->annonce;
    }

    public function setAnnonce(?annonce $annonce): self
    {
        $this->annonce = $annonce;

        return $this;
    }

    public function getCommentaire(): ?string
    {
        return $this->commentaire;
    }

    public function setCommentaire(string $commentaire): self
    {
        $this->commentaire = $commentaire;

        return $this;
    }

    public function getdateenregistrement(): ?\DateTimeInterface
    {
        return $this->dateenregistrement;
    }

    public function setdateenregistrement(\DateTimeInterface $dateenregistrement): self
    {
        $this->dateenregistrement = $dateenregistrement;

        return $this;
    }
}
