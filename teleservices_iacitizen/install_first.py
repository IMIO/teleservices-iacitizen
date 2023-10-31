import json
import os
from os.path import join


def update_json(dict_passerelle, dict_queries, path):
    for key, value in dict_passerelle.items():
        dict_passerelle[key] = value.strip()

    for key, value in dict_queries.items():
        dict_queries[key] = value.strip()

    with open(path, "r") as file:
        json_actualites = json.loads(file.read())
        file.close()

    json_actualites["resources"][0].update(dict_passerelle)

    for query in json_actualites["resources"][0]["queries"]:
        query.update(dict_queries)

    with open(path, "w") as file:
        file.write(json.dumps(json_actualites))
        file.close()


# PATH
path_base = "/usr/lib/teleservices_iacitizen"
path_passerelle = join(path_base, "passerelle")

path_actualites = join(path_passerelle, "restapi_actualites.json")
path_annuaire = join(path_passerelle, "restapi_annuaire.json")
path_evenements = join(path_passerelle, "restapi_evenements.json")
path_smartweb = join(path_passerelle, "restapi_smartweb.json")
path_deliberations = join(path_passerelle, "restapi_deliberations.json")

# URL
url_token = "https://agents.wallonie-connect.be/idp/oidc/token/"
url_actualites = "https://actualites.enwallonie.be"
url_annuaire = "https://annuaire.enwallonie.be"
url_evenements = "https://agenda.enwallonie.be"
url_deliberations = "https://www.deliberations.be"

# ACTUALITES
passerelle_actualites = {}
passerelle_actualites_queries = {}
print("Passerelle actualités")
print("=====================\n")
print("Configuration for Passerelle actualités")
passerelle_actualites["basic_auth_username"] = (
    input(
        "Enter the Identifiant d’authentification basique press Enter to leave blank : "
    )
    or ""
)
passerelle_actualites["basic_auth_password"] = (
    input(
        "Enter the Mot de passe pour l’authentification basique press Enter to leave blank : "
    )
    or ""
)
passerelle_actualites["service_url"] = (
    input(f"Enter the URL du site press Enter to {url_actualites} : ") or url_actualites
)
passerelle_actualites["token_ws_url"] = (
    input(
        f"Enter the URL pour récupérer le jeton (token) press Enter to {url_token} : "
    )
    or url_token
)
passerelle_actualites["client_id"] = (
    input("Enter the Identifiant OIDC press Enter to leave blank : ") or ""
)
passerelle_actualites["client_secret"] = (
    input("Enter the Mot de passe OIDC press Enter to leave blank : ") or ""
)
passerelle_actualites["username"] = (
    input("Enter the Identifiant utilisateur press Enter to leave blank : ") or ""
)
passerelle_actualites["password"] = (
    input("Enter the Mot de passe press Enter to leave blank : ") or ""
)
passerelle_actualites_queries["uri"] = (
    input("Enter the URI for queries press Enter to leave blank : ") or ""
)

print("Update JSON actualites")
try:
    update_json(passerelle_actualites, passerelle_actualites_queries, path_actualites)
    print("JSON actualites updated")
except Exception as e:
    print("JSON actualites fatal error")
    print(e)


# ANNUAIRE
passerelle_annuaire = {}
passerelle_annuaire_queries = {}
print("Passerelle annuaire")
print("===================\n")
print("Configuration for Passerelle annuaire")
passerelle_annuaire["basic_auth_username"] = (
    input(
        "Enter the Identifiant d’authentification basique press Enter to leave blank : "
    )
    or ""
)
passerelle_annuaire["basic_auth_password"] = (
    input(
        "Enter the Mot de passe pour l’authentification basique press Enter to leave blank : "
    )
    or ""
)
passerelle_annuaire["service_url"] = (
    input(f"Enter the URL du site press Enter to {url_annuaire} : ") or url_annuaire
)
passerelle_annuaire["token_ws_url"] = (
    input(
        f"Enter the URL pour récupérer le jeton (token) press Enter to {url_token} : "
    )
    or url_token
)
passerelle_annuaire["client_id"] = (
    input("Enter the Identifiant OIDC press Enter to leave blank : ") or ""
)
passerelle_annuaire["client_secret"] = (
    input("Enter the Mot de passe OIDC press Enter to leave blank : ") or ""
)
passerelle_annuaire["username"] = (
    input("Enter the Identifiant utilisateur press Enter to leave blank : ") or ""
)
passerelle_annuaire["password"] = (
    input("Enter the Mot de passe press Enter to leave blank : ") or ""
)
passerelle_annuaire_queries["uri"] = (
    input("Enter the URI for queries press Enter to leave blank : ") or ""
)

print("Update JSON annuaire")
try:
    update_json(passerelle_annuaire, passerelle_annuaire_queries, path_annuaire)
    print("JSON annuaire updated")
except Exception as e:
    print("JSON annuaire fatal error")
    print(e)

# EVENEMENTS
passerelle_evenements = {}
passerelle_evenements_queries = {}
print("Passerelle evenements")
print("=====================\n")
print("Configuration for Passerelle evenements")
passerelle_evenements["basic_auth_username"] = (
    input(
        "Enter the Identifiant d’authentification basique press Enter to leave blank : "
    )
    or ""
)
passerelle_evenements["basic_auth_password"] = (
    input(
        "Enter the Mot de passe pour l’authentification basique press Enter to leave blank : "
    )
    or ""
)
passerelle_evenements["service_url"] = (
    input(f"Enter the URL du site press Enter to {url_evenements} : ") or url_evenements
)
passerelle_evenements["token_ws_url"] = (
    input(
        f"Enter the URL pour récupérer le jeton (token) press Enter to {url_token} : "
    )
    or url_token
)
passerelle_evenements["client_id"] = (
    input("Enter the Identifiant OIDC press Enter to leave blank : ") or ""
)
passerelle_evenements["client_secret"] = (
    input("Enter the Mot de passe OIDC press Enter to leave blank : ") or ""
)
passerelle_evenements["username"] = (
    input("Enter the Identifiant utilisateur press Enter to leave blank : ") or ""
)
passerelle_evenements["password"] = (
    input("Enter the Mot de passe press Enter to leave blank : ") or ""
)
passerelle_evenements_queries["uri"] = (
    input("Enter the URI for queries press Enter to leave blank : ") or ""
)

print("Update JSON evenements")
try:
    update_json(passerelle_evenements, passerelle_evenements_queries, path_evenements)
    print("JSON evenements updated")
except Exception as e:
    print("JSON evenements fatal error")
    print(e)

# SMARTWEB
passerelle_smartweb = {}
passerelle_smartweb_queries = {}
print("Passerelle smartweb")
print("===================\n")
print("Configuration for Passerelle smartweb")
passerelle_smartweb["basic_auth_username"] = (
    input(
        "Enter the Identifiant d’authentification basique press Enter to leave blank : "
    )
    or ""
)
passerelle_smartweb["basic_auth_password"] = (
    input(
        "Enter the Mot de passe pour l’authentification basique press Enter to leave blank : "
    )
    or ""
)
passerelle_smartweb["service_url"] = (
    input(f"Enter the URL du site press Enter to leave blank : ") or ""
)
passerelle_smartweb["token_ws_url"] = (
    input(
        f"Enter the URL pour récupérer le jeton (token) press Enter to {url_token} : "
    )
    or url_token
)
passerelle_smartweb["client_id"] = (
    input("Enter the Identifiant OIDC press Enter to leave blank : ") or ""
)
passerelle_smartweb["client_secret"] = (
    input("Enter the Mot de passe OIDC press Enter to leave blank : ") or ""
)
passerelle_smartweb["username"] = (
    input("Enter the Identifiant utilisateur press Enter to leave blank : ") or ""
)
passerelle_smartweb["password"] = (
    input("Enter the Mot de passe press Enter to leave blank : ") or ""
)

print("Update JSON smartweb")
try:
    update_json(passerelle_smartweb, passerelle_smartweb_queries, path_smartweb)
    print("JSON smartweb updated")
except Exception as e:
    print("JSON smartweb fatal error")
    print(e)

# DELIBERATIONS
passerelle_deliberations = {}
passerelle_deliberations_queries = {}
print("Passerelle deliberations")
print("========================\n")
print("Configuration for Passerelle deliberations")
passerelle_deliberations["basic_auth_username"] = (
    input(
        "Enter the Identifiant d’authentification basique press Enter to leave blank : "
    )
    or ""
)
passerelle_deliberations["basic_auth_password"] = (
    input(
        "Enter the Mot de passe pour l’authentification basique press Enter to leave blank : "
    )
    or ""
)
passerelle_deliberations["service_url"] = (
    input(f"Enter the URL du site press Enter to {url_deliberations} : ")
    or url_deliberations
)
passerelle_deliberations["token_ws_url"] = (
    input(
        f"Enter the URL pour récupérer le jeton (token) press Enter to {url_token} : "
    )
    or url_token
)
passerelle_deliberations["client_id"] = (
    input("Enter the Identifiant OIDC press Enter to leave blank : ") or ""
)
passerelle_deliberations["client_secret"] = (
    input("Enter the Mot de passe OIDC press Enter to leave blank : ") or ""
)
passerelle_deliberations["username"] = (
    input("Enter the Identifiant utilisateur press Enter to leave blank : ") or ""
)
passerelle_deliberations["password"] = (
    input("Enter the Mot de passe press Enter to leave blank : ") or ""
)
passerelle_deliberations_queries["uri"] = (
    input("Enter the URI for queries press Enter to leave blank : ") or ""
)
passerelle_deliberations_queries["name"] = (
    input("Enter the name for queries press Enter to leave blank : ") or ""
)
passerelle_deliberations_queries["slug"] = (
    input("Enter the slug for queries press Enter to leave blank : ") or ""
)

print("Update JSON deliberations")
try:
    update_json(
        passerelle_deliberations, passerelle_deliberations_queries, path_deliberations
    )
    print("JSON deliberations updated")
except Exception as e:
    print("JSON deliberations fatal error")
    print(e)

# COMBO
print("Settings.json for combo")
print("=======================\n")
slug = input("Enter the slug of the instance : ")
path_combo_json = join(
    "/var/lib/combo/tenants", f"{slug}.guichet-citoyen.be/settings.json"
)
combo_json = {"COMBO_DASHBOARD_ENABLED": True}

try:
    with open(path_combo_json, "w") as file:
        file.write(json.dumps(combo_json))
        file.close()
    print("Combo settings updated")
except Exception as e:
    print("Combo settings fatal error")
    print(e)

# SCRIPT BASH
print("Run script bash")
print("===============\n")
os.system(f"{path_base}/install_teleservices_iacitizen.sh")
