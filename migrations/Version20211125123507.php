<?php

declare(strict_types=1);

namespace DoctrineMigrations;

use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * Auto-generated Migration: Please modify to your needs!
 */
final class Version20211125123507 extends AbstractMigration
{
    public function getDescription(): string
    {
        return '';
    }

    public function up(Schema $schema): void
    {
        // this up() migration is auto-generated, please modify it to your needs
        $this->addSql('ALTER TABLE annonce CHANGE dateenregistrement date_enregistrement DATETIME NOT NULL');
        $this->addSql('ALTER TABLE commentaire CHANGE dateenregistrement date_enregistrement DATETIME NOT NULL');
    }

    public function down(Schema $schema): void
    {
        // this down() migration is auto-generated, please modify it to your needs
        $this->addSql('ALTER TABLE annonce CHANGE date_enregistrement dateenregistrement DATETIME NOT NULL');
        $this->addSql('ALTER TABLE commentaire CHANGE date_enregistrement dateenregistrement DATETIME NOT NULL');
    }
}
