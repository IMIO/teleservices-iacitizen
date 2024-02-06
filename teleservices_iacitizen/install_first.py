"""Fetch iA.Smartweb JSON data from Infra API, parse data and use it to install iA.Citizen.


URLs for Plone Rest API passerelle connectors :

- https://[smarweb_url]/@news_request_forwarder
- https://[smarweb_url]/@events_request_forwarder
- https://[smarweb_url]/@directory_request_forwarder

URLs for "Consulter toutes les actualités/événements/annuaire" :

- https://[smarweb_url]/@@news_view
- https://[smarweb_url]/@@events_view
- https://[smarweb_url]/@@directory_view

?language=LA_LANGUE can be added to the URL to filter by language.
"""

import datetime
import json
import logging
import os
import subprocess
import sys

import requests

INFRA_API_URL = "https://infra-api.imio.be"
SMARTWEB_ENDPOINT = INFRA_API_URL + "/application/smartweb"

script_not_working_message = "iA.Citizen install script not working as expected. Exited."


def init_logging():
    """
    Init logging.
    """
    install_script_run_timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    this_log_filename = f"iacitizen_install_first_{install_script_run_timestamp}.log"

    logging.basicConfig(
        filename=this_log_filename,
        filemode="w",
        format="%(asctime)s - %(levelname)s - %(message)s",
        level=logging.DEBUG,
    )

    # also log to stdout
    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setLevel(logging.DEBUG)
    stdout_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    stdout_handler.setFormatter(stdout_formatter)
    logging.getLogger().addHandler(stdout_handler)

    logger = logging.getLogger(__name__)

    return logger


def get_smartweb_data():
    """
    Fetch and return the Smartweb data from Infra API.
    """
    smartweb_data = None
    try:
        smartweb_data = requests.get(SMARTWEB_ENDPOINT).json()
    except Exception as e:
        logging.error("Error while fetching Smartweb data: %s", e)
        return None

    return smartweb_data


def init_smartweb_data(smartweb_data):
    """
    Init variables for Smartweb data.
    """
    preprod_smartweb_data = [app for app in smartweb_data if "prepro" in app["vhost_name"]]
    prod_smartweb_data = [app for app in smartweb_data if "prepro" not in app["vhost_name"]]

    return smartweb_data, preprod_smartweb_data, prod_smartweb_data


def verify_slug_validity(slug, logger):
    """
    Verify that the slug is valid.
    """
    if not slug:
        logger.error("Slug is empty.")
        return False

    if len(slug) < 2:
        logger.error("Slug is not valid. It is too short.")
        return False

    if any(char.isdigit() for char in slug):
        logger.error("Slug is not valid. There are digits in it.")
        return False

    if not slug.islower():
        logger.error("Slug is not valid. There are uppercase letters in it.")
        return False

    return True


def verify_for_slug_in_smartweb_data(slug, preprod_smartweb_data):
    """
    Verify if the slug is present in the preprod Smartweb data.
    """
    found_app = []
    for app in preprod_smartweb_data:
        if slug in app["vhost_name"]:
            found_app.append(app)
    return found_app


def verify_y_n_input(user_input, logger):
    """
    Verify if the user input is 'y' or 'n'.
    """
    if user_input.lower() not in ["y", "n"]:
        logger.error("Input is not valid. Please enter 'y' or 'n'.")
        return False
    return True


def verify_waconnect_username_and_password(wac_username, wac_password, logger):
    """
    Verify if the WaConnect username and password are valid.
    """
    if not wac_username:
        logger.error("WaConnect username is empty.")
        return False

    if len(wac_username) < 2:
        logger.error("WaConnect username is not valid. It is too short.")
        return False

    if len(wac_username) > 125:
        logger.error("WaConnect username is not valid. It is too long.")
        return False

    if not wac_password:
        logger.error("WaConnect password is empty.")
        return False

    if len(wac_password) < 2:
        logger.error("WaConnect password is not valid. It is too short.")
        return False

    if len(wac_password) > 50:
        logger.error("WaConnect password is not valid. It is too long.")
        return False

    return True


def display_found_apps_and_return_chosen_one(found_apps, smartweb_slug, logger):
    """
    Display the found apps in data.

    ChatGPT4 suggestion :
    - This function is well-structured, but consider splitting it into two functions: one for displaying apps and another for getting the user's choice. This adheres to the single responsibility principle.
    """
    logger.info("Found %s apps for %s in preprod Smartweb data.", str(len(found_apps)), smartweb_slug)
    for index, app in enumerate(found_apps, start=1):
        logger.info("App %s: %s", str(index), app)

    # ask user if they want to use one of the found apps
    while True:
        user_input = input(
            "> Do you want to use one of these apps? If not, we will check in prod Smartweb data. (y/n): "
        )
        if verify_y_n_input(user_input, logger):
            break
        else:
            logger.info("Please enter 'y' for yes or 'n' for no.")

    if user_input.lower() == "n":
        return None

    # check if there is only one app found
    if len(found_apps) == 1:
        logger.info("Only one app found, we will use it.")
        return found_apps[0]
    # ask user to select app
    app_index = input("> Select app index to use for this installation (example: 1):")
    # verify that index is positive
    if int(app_index) < 0:
        logger.error("App index is not valid. You must enter a positive number.")
        return
    try:
        app_index = int(app_index)
    except ValueError:
        logger.error("App index is not valid. You must enter a number.")
        return
    if app_index > len(found_apps):
        logger.error("App index is not valid. You must enter a number between 1 and %s.", str(len(found_apps)))
        return

    # logger.info("User wants to use the app: %s", found_apps[app_index - 1])
    return found_apps[app_index - 1]


def display_found_combo_tenant_and_return_chosen_one(logger):
    """Fetch and output combo tenants in /var/lib/combo/tenants (folders contained in that folder) and ask user for wich combo tenant to use"""
    base_dir = "/var/lib/combo/tenants"
    elements_in_base_dir = os.listdir(base_dir)
    try:
        combo_tenants = [tenant for tenant in elements_in_base_dir if os.path.isdir(os.path.join(base_dir, tenant))]
    except Exception as e:
        logger.error("Error while fetching combo tenants: %s", e)
        return

    if not combo_tenants:
        logger.error("No combo tenants found.")
        return

    # Display combo tenants with indexes and ask user to select one
    logger.info("Combo tenants found:")
    for index, tenant in enumerate(combo_tenants, start=1):
        logger.info("Tenant %s: %s", str(index), tenant)

    # check if there is only one combo tenant found
    if len(combo_tenants) == 1:
        logger.info("Only one combo tenant found, we will use it.")
        return combo_tenants[0]
    else:
        # ask user to select combo tenant
        combo_tenant_index = input("> Select combo tenant index to use for this installation (example: 1):")
        # verify that index is positive
        if int(combo_tenant_index) < 0:
            logger.error("Combo tenant index is not valid. You must enter a positive number.")
            return
        try:
            combo_tenant_index = int(combo_tenant_index)
        except ValueError:
            logger.error("Combo tenant index is not valid. You must enter a number.")
            return
        if combo_tenant_index > len(combo_tenants):
            logger.error(
                "Combo tenant index is not valid. You must enter a number between 1 and %s.", str(len(combo_tenants))
            )
            return

        return combo_tenants[combo_tenant_index - 1]


def check_and_update_combo_settings(chosen_combo_tenant, logger):
    settings_path = os.path.join("/var/lib/combo/tenants", chosen_combo_tenant, "path", "settings.json")

    # Check if settings.json exists
    if os.path.isfile(settings_path):
        # Read the existing settings.json
        with open(settings_path, "r") as file:
            try:
                settings = json.load(file)
            except json.JSONDecodeError:
                logger.error(f"Error reading {settings_path}. Invalid JSON format.")
                return

        # Check if COMBO_DASHBOARD_ENABLED key exists
        if "COMBO_DASHBOARD_ENABLED" not in settings:
            settings["COMBO_DASHBOARD_ENABLED"] = True

            # Save the updated settings back to settings.json
            with open(settings_path, "w") as file:
                json.dump(settings, file, indent=4)
            logger.info(f"COMBO_DASHBOARD_ENABLED set to True in {settings_path}.")
        else:
            logger.info("COMBO_DASHBOARD_ENABLED already set.")
    else:
        # Create settings.json with COMBO_DASHBOARD_ENABLED set to True
        with open(settings_path, "w") as file:
            json.dump({"COMBO_DASHBOARD_ENABLED": True}, file, indent=4)
        logger.info(f"Created {settings_path} with COMBO_DASHBOARD_ENABLED set to True.")


def unpack_parsed_data_from_chosen_app(chosen_app, logger):
    """
    Unpack parsed data from chosen app.
    """
    try:
        smartweb_uri = chosen_app["application_name"].split("_")[0]
        smartweb_url = chosen_app["vhost_name"]
    except Exception as e:
        logger.error("Error while unpacking parsed data from chosen app: %s", e)
        return None

    return smartweb_uri, smartweb_url


def strip_values(d):
    """Strip whitespace from all string values in a dictionary."""
    return {k: v.strip() if isinstance(v, str) else v for k, v in d.items()}


def apply_updates_to_json_file(json_file, updates, logger):
    """Apply updates to a given JSON file based on the updates dictionary."""
    try:
        with open(json_file, "r") as file:
            data = json.load(file)

        # Iterate through the resources and apply updates
        for resource in data.get("resources", []):
            if "service_url" in updates:
                resource["service_url"] = updates["service_url"]
            if "token_ws_url" in updates:
                resource["token_ws_url"] = updates["token_ws_url"]
            if "client_id" in updates:
                resource["client_id"] = updates["client_id"]
            if "client_secret" in updates:
                resource["client_secret"] = updates["client_secret"]
            if "username" in updates:
                resource["username"] = updates["username"]
            if "password" in updates:
                resource["password"] = updates["password"]
            for query in resource.get("queries", []):
                if "queries_uri" in updates:
                    query["uri"] = updates["queries_uri"]

        with open(json_file, "w") as file:
            json.dump(data, file, indent=4)

        logger.info(f"Successfully updated {json_file}")

    except Exception as e:
        logger.error(f"Error updating {json_file}: {e}")


def main():
    """
    Main function.
    """

    # Init logging
    logger = init_logging()

    # verify_env_var_presence()

    # Init variables
    chosen_app = None
    passerelle_actualites_url = None
    passerelle_actualites_url_suffix = "/@@news_request_forwarder"
    passerelle_evenements_url = None
    passerelle_evenements_url_suffix = "/@@events_request_forwarder"
    passerelle_annuaire_url = None
    passerelle_annuaire_url_suffix = "/@@directory_request_forwarder"
    hobo_all_actualites_url = None
    hobo_all_actualites_url_suffix = "/@@news_view"
    hobo_all_evenements_url = None
    hobo_all_evenements_url_suffix = "/@@events_view"
    hobo_all_annuaire_url = None
    hobo_all_annuaire_url_suffix = "/@@directory_view"

    smartweb_uri = None
    smartweb_url = None

    # Ask user for slug
    smartweb_slug = input(
        "Insert smatweb slug (/!\ can be different than our Teleservices slug, check up on Infra API)\nFor example TS : sanktvith, Smartweb : saintvith\nEnter smartweb slug:"
    )

    # Verify slug validity
    valid_slug = verify_slug_validity(smartweb_slug, logger)

    if not valid_slug:
        logger.error(script_not_working_message)
        return

    # Fetch Smartweb data
    smartweb_data, preprod_smartweb_data, prod_smartweb_data = init_smartweb_data(get_smartweb_data())

    # Verify Smartweb data
    if not smartweb_data or not preprod_smartweb_data or not prod_smartweb_data:
        logger.error(script_not_working_message)
        logger.error("Smartweb data is not valid.")
        return

    # Look into preprod Smartweb data first and display found apps, ask user if he wants to use one of them
    stuff_found_in_preprod = verify_for_slug_in_smartweb_data(smartweb_slug, preprod_smartweb_data)

    if not stuff_found_in_preprod:
        logger.error("No app found for slug %s in preprod Smartweb data.", smartweb_slug)
    else:
        chosen_app = display_found_apps_and_return_chosen_one(stuff_found_in_preprod, smartweb_slug, logger)

    if not chosen_app:
        logger.info("Checking in prod Smartweb data...")
        stuff_found_in_prod = verify_for_slug_in_smartweb_data(smartweb_slug, prod_smartweb_data)

        if not stuff_found_in_prod:
            logger.error("No app found for slug %s in prod Smartweb data.", smartweb_slug)
            logger.error(script_not_working_message)
            return
        else:
            chosen_app = display_found_apps_and_return_chosen_one(stuff_found_in_prod, smartweb_slug, logger)

    if not chosen_app:
        logger.error(script_not_working_message)
        logger.error("No chosen app, this should not happen unless you selected 'n' to all questions.")
        return

    logger.info("Chosen app: %s", chosen_app)

    # Unpack parsed data from chosen app
    smartweb_uri, smartweb_url = unpack_parsed_data_from_chosen_app(chosen_app, logger)

    # verify if there's a '/' at the end of the string and remove it if there are any
    if smartweb_url[-1] == "/":
        smartweb_url = smartweb_url[:-1]

    logger.info("Smartweb uri: %s", smartweb_uri)
    logger.info("Smartweb url: %s", smartweb_url)

    # Ask user for WaConnect username and password
    wac_username = input("> Enter Wallonie Connect username:").strip()
    wac_password = input("> Enter Wallonie Connect password:").strip()

    # Verify WaConnect username and password
    valid_wac_username_and_password = verify_waconnect_username_and_password(wac_username, wac_password, logger)

    if not valid_wac_username_and_password:
        logger.error(script_not_working_message)
        return

    # Values to update in json files for reference:
    # In restapi_actualites.json
    # "resources":[{"service_url": "SMARTWEB_URL_ACTUALITES",}]
    # "resources":[{"username": "WACONNECT_USERNAME",}]
    # "resources":[{"password": "WACONNECT_PASSWORD",}]
    # "resources": [{"queries": [{"uri":  "ACTUALITES_QUERIES_URI"}]}] (for each query present)
    #
    # In restapi_annuaire.json
    # "resources":[{"service_url": "SMARTWEB_URL_ANNUAIRE",}]
    # "resources":[{"username": "WACONNECT_USERNAME",}]
    # "resources":[{"password": "WACONNECT_PASSWORD",}]
    # "resources": [{"queries": [{"uri":  "ANNUAIRE_QUERIES_URI"}]}] (for each query present)
    #
    # In restapi_smartweb.json
    # "resources":[{"service_url": "SMARTWEB_URL",}]
    # "resources":[{"username": "WACONNECT_USERNAME",}]
    # "resources":[{"password": "WACONNECT_PASSWORD",}]
    #
    # In restapi_evenements.json
    # "resources":[{"service_url": "SMARTWEB_URL_AGENDA",}]
    # "resources":[{"username": "WACONNECT_USERNAME",}]
    # "resources":[{"password": "WACONNECT_PASSWORD",}]
    # "resources": [{"queries": [{"uri":  "AGENDA_QUERIES_URI"}]}] (for each query present)
    #
    # In restapi_deliberations.json
    # "resources":[{"basic_auth_username": "username",}]
    # "resources":[{"basic_auth_password": "password",}]
    # "resources":[{"service_url": "https://www.deliberations.be",}]
    # "resources": [{"queries": [{"uri":  "QUERIES_URI"}]}] (for each query present)

    # Assign URLs
    ## Plone REST API URLs
    restapi_actualites_json_updates = dict()
    restapi_actualites_json_updates["service_url"] = smartweb_url + passerelle_actualites_url_suffix
    restapi_actualites_json_updates["token_ws_url"] = os.environ.get("WACO_TOKEN_WS_URL")
    restapi_actualites_json_updates["client_id"] = os.environ.get("PLONERESTAPI_ACTUALITES_CLIENT_ID")
    restapi_actualites_json_updates["client_secret"] = os.environ.get("PLONERESTAPI_ACTUALITES_CLIENT_SECRET")
    restapi_actualites_json_updates["username"] = wac_username
    restapi_actualites_json_updates["password"] = wac_password
    restapi_actualites_json_updates["queries_uri"] = smartweb_uri

    restapi_annuaire_json_updates = dict()
    restapi_annuaire_json_updates["service_url"] = smartweb_url + passerelle_annuaire_url_suffix
    restapi_annuaire_json_updates["token_ws_url"] = os.environ.get("WACO_TOKEN_WS_URL")
    restapi_annuaire_json_updates["client_id"] = os.environ.get("PLONERESTAPI_ANNUAIRE_CLIENT_ID")
    restapi_annuaire_json_updates["client_secret"] = os.environ.get("PLONERESTAPI_ANNUAIRE_CLIENT_SECRET")
    restapi_annuaire_json_updates["username"] = wac_username
    restapi_annuaire_json_updates["password"] = wac_password
    restapi_annuaire_json_updates["queries_uri"] = smartweb_uri

    restapi_smartweb_json_updates = dict()
    restapi_smartweb_json_updates["service_url"] = smartweb_url
    restapi_smartweb_json_updates["token_ws_url"] = os.environ.get("WACO_TOKEN_WS_URL")
    restapi_smartweb_json_updates["client_id"] = os.environ.get("PLONERESTAPI_SITE_WEB_CLIENT_ID")
    restapi_smartweb_json_updates["client_secret"] = os.environ.get("PLONERESTAPI_SITE_WEB_CLIENT_SECRET")
    restapi_smartweb_json_updates["username"] = wac_username
    restapi_smartweb_json_updates["password"] = wac_password

    restapi_evenements_json_updates = dict()
    restapi_evenements_json_updates["service_url"] = smartweb_url + passerelle_evenements_url_suffix
    restapi_evenements_json_updates["token_ws_url"] = os.environ.get("WACO_TOKEN_WS_URL")
    restapi_evenements_json_updates["client_id"] = os.environ.get("PLONERESTAPI_EVENEMENTS_CLIENT_ID")
    restapi_evenements_json_updates["client_secret"] = os.environ.get("PLONERESTAPI_EVENEMENTS_CLIENT_SECRET")
    restapi_evenements_json_updates["username"] = wac_username
    restapi_evenements_json_updates["password"] = wac_password
    restapi_evenements_json_updates["queries_uri"] = smartweb_uri

    # print all for debugging
    # logger.info("restapi_actualites_json_updates: %s", restapi_actualites_json_updates)
    # logger.info("restapi_annuaire_json_updates: %s", restapi_annuaire_json_updates)
    # logger.info("restapi_smartweb_json_updates: %s", restapi_smartweb_json_updates)
    # logger.info("restapi_evenements_json_updates: %s", restapi_evenements_json_updates)

    # Update json files
    apply_updates_to_json_file("./passerelle/restapi_actualites.json", restapi_actualites_json_updates, logger)
    apply_updates_to_json_file("./passerelle/restapi_annuaire.json", restapi_annuaire_json_updates, logger)
    apply_updates_to_json_file("./passerelle/restapi_smartweb.json", restapi_smartweb_json_updates, logger)
    apply_updates_to_json_file("./passerelle/restapi_evenements.json", restapi_evenements_json_updates, logger)

    # TODO : Implement restapi_deliberations.json setup (deliberations.be)
    # Ask user if he wants to setup restapi_deliberations.json
    # while True:
    #     user_input = input(
    #         "> Do you want to setup restapi_deliberations.json (if they have the deliberations.be product and you got the credentials from the iA.Delib team.) ? (y/n): "
    #     )
    #     if verify_y_n_input(user_input, logger):
    #         break
    #     else:
    #         logger.info("Please enter 'y' for yes or 'n' for no.")

    #

    chosen_combo_tenant = display_found_combo_tenant_and_return_chosen_one(logger)
    if not chosen_combo_tenant:
        logger.error("No combo tenant found.")
        return

    # TODO : Initiate hobo variables
    ## "Consulter toutes les actualités/événements/annuaire" buttons URLs
    hobo_all_actualites_url = smartweb_url + hobo_all_actualites_url_suffix
    hobo_all_evenements_url = smartweb_url + hobo_all_evenements_url_suffix
    hobo_all_annuaire_url = smartweb_url + hobo_all_annuaire_url_suffix

    # {
    # "ia_citizen": {
    #     "label": "Est un iA.Citizen",
    #     "value": "Oui"
    # },
    # "plone_actualites_url": {
    #     "label": "Lien du bouton \"Consulter toutes les actualités\"",
    #     "value": ""
    # },
    # "plone_evenements_url": {
    #     "label": "Lien du bouton \"Consulter tous les événements\"",
    #     "value": ""
    # },
    # "plone_deliberations_url": {
    #     "label": "Lien du bouton \"Consulter toutes les délibérations\"",
    #     "value": ""
    # }
    # }

    # Update hobo_variables.json values
    hobo_variables = {
        "ia_citizen": {"label": "Est un iA.Citizen", "value": "Oui"},
        "plone_actualites_url": {
            "label": 'Lien du bouton "Consulter toutes les actualités"',
            "value": hobo_all_actualites_url,
        },
        "plone_evenements_url": {
            "label": 'Lien du bouton "Consulter tous les événements"',
            "value": hobo_all_evenements_url,
        },
        "plone_annuaire_url": {"label": 'Lien du bouton "Consulter l\'annuaire"', "value": hobo_all_annuaire_url},
    }

    try:
        with open("./hobo_variables.json", "w") as file:
            json.dump(hobo_variables, file, indent=4)
            logger.info("Updated hobo_variables.json.")
    except Exception as e:
        logger.error(f"Error while updating hobo_variables.json: {e}")
        return

    # Run hobo_variables_updater.py using subprocess
    # cmd to run : sudo -u hobo hobo-manage tenant_command runscript -d REPLACE_WITH_TENANT

    try:
        hobo_tenant = (
            subprocess.run("ls /var/lib/hobo/tenants", shell=True, check=True, capture_output=True)
            .stdout.decode("utf-8")
            .strip()
        )
        full_path_for_hobo_runscript = os.path.join(os.getcwd(), "hobo_variables_updater.py")
        # sudo -u hobo hobo-manage tenant_command runscript -d REPLACE_WITH_TENANT full_path_for_hobo_runscript
        subprocess.run(
            [
                "sudo",
                "-u",
                "hobo",
                "hobo-manage",
                "tenant_command",
                "runscript",
                "-d",
                hobo_tenant,
                full_path_for_hobo_runscript,
            ],
            check=True,
        )
        logger.info("hobo_variables_updater.py has been run.")
    except subprocess.CalledProcessError as e:
        logger.error(f"Error while running hobo_variables_updater.py: {e}")
        return

    logger.info("iA.Citizen install_first.py script has run successfully. ✅")


if __name__ == "__main__":
    main()
