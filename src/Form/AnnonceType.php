<?php

namespace App\Form;

use App\Entity\Annonce;
use App\Entity\Categorie;
use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Bridge\Doctrine\Form\Type\EntityType;
use Symfony\Component\Validator\Constraints\File;
use Symfony\Component\OptionsResolver\OptionsResolver;
use Symfony\Component\Form\Extension\Core\Type\FileType;

class AnnonceType extends AbstractType
{
    public function buildForm(FormBuilderInterface $builder, array $options): void
    {
        $builder
            ->add('titre')
            ->add('description_courte')
            ->add('description_longue')
            ->add('prix')
            ->add('surface')
            ->add('adresse')
            ->add('cp')
            ->add('ville')
            ->add('date_enregistrement')
            ->add('image', FileType::class, [
                "required" => false,
                //"multiple" => true
                "constraints" => [
                    new File([
                        'mimeTypes' => [
                            "image/png", 
                            "image/jpg",
                            "image/jpeg"
                        ],
                        'mimeTypesMessage' => "les extensions des images autorisées sont : PNG - JPG"
                    ])
                ]
            ])
                                            
            ->add('categorie', EntityType::class, [ // cet input a une relation avec une autre entity
                "class" => Categorie::class,        // avec quelle entity
                "choice_label" => "type",          // quelle propriété (quel champ) afficher
                "placeholder" => "Saisir une catégorie"
            ])
            
        ;
    }

    public function configureOptions(OptionsResolver $resolver): void
    {
        $resolver->setDefaults([
            'data_class' => Annonce::class,
        ]);
    }
}
