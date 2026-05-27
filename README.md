# iA.Citizen init. package

## Points d'attention lors d'une instanciation

1. Lancer la commande `python3 /usr/lib/teleservices-iacitizen/install_first.py`
2. Répondre aux différentes questions pour paramétrer les connecteurs passerelles

- Connecteurs passerelle, vérifier les panneaux "Requête".
- Variables combo à créer :
  - `plone_deliberations_url`, Adresse des délibérations communales, valeur : URL à coller
  - `ia_citizen`, Est un iA.Citien, valeur : `Oui`

## Commandes CLI

### `create_plone_restapi`

Installe les connecteurs Passerelle REST API (actualités, annuaire, événements, smartweb) et met à jour la configuration Hobo et les rôles WCS. La configuration est lue depuis les variables d'environnement Keycloak/SSO (issues de `install_first`).

```bash
create_plone_restapi
```

Variable optionnelle : `SMARTWEB_SLUG` — si absente, le slug est dérivé automatiquement depuis le nom d'utilisateur Wallonie Connect (`imio-apps-teleservices_<slug>`).

### `delete_plone_restapi`

Supprime les connecteurs REST API créés par `create_plone_restapi` (`actualites`, `annuaire`, `evenements`, `site-web`, `deliberations`).

```bash
delete_plone_restapi
```
