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
use Symfony\Component\Form\Extension\Core\Type\TextType;
use Symfony\Component\Form\Extension\Core\Type\MoneyType;
use Symfony\Component\Form\Extension\Core\Type\TextareaType;

class AnnonceType extends AbstractType
{
    public function buildForm(FormBuilderInterface $builder, array $options): void
    {
        if($options["ajouter"] == true)
        {
            $builder
            ->add('titre', TextType::class, [
                "label" => "Titre du produit",
                "required" => false,
                "attr" => [
                    "placeholder" => "Saisir le titre du produit",
                    "class" => "bg-warning",
                ]
            ])
                ->add('descriptioncourte', TextType::class, [
                    "label" => "Description du produit",
                    "required" => false,
                    "attr" => [
                        "placeholder" => "",
                        "class" => "bg-warning",
                    ]
                ])
                ->add('descriptionlongue', TextareaType::class, [
                    "label" => "Description longue du produit",
                    "required" => false,
                    "attr" => [
                        "placeholder" => "",
                        "class" => "bg-warning",
                    ]
                ])
                ->add('prix')
                ->add('surface')
                ->add('adresse')
                ->add('cp', TextType::class, [
                    "label" => "Code postal"])
                ->add('ville')
                
                ->add('photo', FileType::class, [
                    "required" => false,
                    "mapped" => false, // imageFile n'est pas une propriété de l'entity
                    //"multiple" => true

                    "multiple"=>true
                ])
                                                
                ->add('categorie', EntityType::class, [ // cet input a une relation avec une autre entity
                    "class" => Categorie::class,        // avec quelle entity
                    "choice_label" => "type",          // quelle propriété (quel champ) afficher
                    "placeholder" => "Saisir une catégorie"
                ])
                
            ;
        }
        elseif($options["modifier"] == true)
        {
            
            $builder
                ->add('titre', TextType::class, [
                    "label" => "Titre du produit",
                    "required" => false,
                    "attr" => [
                        "placeholder" => "Saisir le titre du produit",
                        "class" => "bg-warning",
                    ]
                ])
                ->add('descriptioncourte', TextType::class, [
                    "label" => "Description du produit",
                    "required" => false,
                    "attr" => [
                        "placeholder" => "",
                        "class" => "bg-warning",
                    ]
                ])
                ->add('descriptionlongue', TextType::class, [
                    "label" => "Description longue du produit",
                    "required" => false,
                    "attr" => [
                        "placeholder" => "",
                        "class" => "bg-warning",
                    ]
                ])
                ->add('prix', MoneyType::class, [
                    "currency"=>"EUR",
                    "required" => false,
                    "attr" => [
                        "placeholder" => "Saisir le prix du produit",
                        "class" => "bg-warning",
                    ]
                ])

                ->add('surface')
                ->add('adresse', TextType::class, [
                    "label"=>"adresse",
                    "required" => false,
                    "attr" => [
                        "placeholder" => "Saisissez votre adresse",
                        "class" => "bg-warning",
                    ]
                ])
                ->add('cp', TextType::class, [
                    "label"=>"Code postal",
                    "required" => false,
                    "attr" => [
                        "placeholder" => "Saisir le Code postal",
                        "class" => "bg-warning",
                    ]
                ])
                ->add('ville', TextType::class, [
                    "label" => "Ville",
                    "required" => false,
                    "attr" => [
                        "placeholder" => "Saisir la description du produit",
                        "class" => "bg-warning",
                    ]
                ])

                ->add('categorie', EntityType::class, [ // cet input a une relation avec une autre entity
                    "class" => Categorie::class,        // avec quelle entity
                    "choice_label" => "type",          // quelle propriété (quel champ) afficher
                    "placeholder" => "Saisir une catégorie"
                ])

                ->add('photoFile', FileType::class, [
                    "required" => false,
                    "mapped" => false, // imageFile n'est pas une propriété de l'entity
                    //"multiple" => true

                    "multiple"=>true
                ])
            ;
        }
    }


    public function configureOptions(OptionsResolver $resolver)
    {
        $resolver->setDefaults([
            'data_class' => Annonce::class,
            "ajouter" => false,
            "modifier" => false

        ]);
    }
}
