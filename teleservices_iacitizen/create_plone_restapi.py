import json
import os
import subprocess

from .install_first import (
    apply_updates_to_json_file,
    check_and_update_combo_settings,
    get_smartweb_data,
    init_logging,
    init_smartweb_data,
    script_not_working_message,
    verify_slug_validity,
    verify_for_slug_in_smartweb_data,
    verify_waconnect_username_and_password,
)

"""Install iA.Citizen connectors, fully driven by environment variables.

Example usage:
    create_plone_restapi

Required environment variables:
    SSO_APPS_URL           Keycloak token endpoint URL
    SSO_APPS_CLIENT_ID     SSO Apps client ID
    SSO_APPS_CLIENT_SECRET SSO Apps client secret
    SSO_APPS_USER_USERNAME Wallonie Connect username (format: imio-apps-teleservices_<slug>[-role])
    SSO_APPS_USER_PASSWORD Wallonie Connect password
    SMARTWEB_URL           Smartweb base URL

Optional environment variables:
    SMARTWEB_URI           Smartweb URI (short identifier used in passerelle queries)
    SMARTWEB_SLUG          Override the Smartweb slug (auto-derived from SSO_APPS_USER_USERNAME)
    COMBO_TENANT           Override the combo tenant (auto-detected from /var/lib/combo/tenants)
    SMARTWEB_APP_INDEX     App index when using Infra API fallback (default: 1)
    SMARTWEB_USE_PROD      Set to "1" to search prod Smartweb data instead of preprod
"""


def _slug_candidates(logger):
    """Return slug candidates from SMARTWEB_SLUG or SSO_APPS_USER_USERNAME.

    Username format: imio-apps-teleservices_<slug>[-role]
    Example: imio-apps-teleservices_belleville-ac → tries ["belleville-ac", "belleville"]
    """
    explicit = os.environ.get("SMARTWEB_SLUG", "").strip()
    if explicit:
        logger.info("Using SMARTWEB_SLUG: %s", explicit)
        return [explicit]

    username = os.environ.get("SSO_APPS_USER_USERNAME", "").strip()
    prefix = "imio-apps-teleservices_"
    if not username.startswith(prefix):
        return []
    candidate = username[len(prefix):]
    if not candidate:
        return []
    candidates = [candidate]
    if "-" in candidate:
        candidates.append(candidate.rsplit("-", 1)[0])
    logger.info("Slug candidates from SSO_APPS_USER_USERNAME: %s", candidates)
    return candidates


def _resolve_tenant(base_dir, service_name, logger, env_override=None, exclude_prefix=None):
    """Generic auto-detection of a single tenant directory."""
    if env_override:
        path = os.path.join(base_dir, env_override)
        if not os.path.isdir(path):
            logger.error("%s tenant '%s' not found in %s.", service_name, env_override, base_dir)
            return None
        return env_override

    try:
        tenants = [t for t in os.listdir(base_dir) if os.path.isdir(os.path.join(base_dir, t))]
    except Exception as e:
        logger.error("Error listing %s tenants: %s", service_name, e)
        return None

    if not tenants:
        logger.error("No %s tenants found in %s.", service_name, base_dir)
        return None

    if len(tenants) == 1:
        logger.info("Auto-selected %s tenant: %s", service_name, tenants[0])
        return tenants[0]

    if exclude_prefix:
        filtered = [t for t in tenants if not t.startswith(exclude_prefix)]
        if len(filtered) == 1:
            logger.info("Auto-selected %s tenant: %s", service_name, filtered[0])
            return filtered[0]

    logger.error(
        "Multiple %s tenants found (%s). Set the appropriate env var to specify one.",
        service_name, ", ".join(tenants),
    )
    return None


def main():
    logger = init_logging()

    script_dir = os.path.dirname(os.path.realpath(__file__))

    # Credentials from environment
    sso_apps_url = os.environ.get("SSO_APPS_URL", "").strip()
    sso_apps_client_id = os.environ.get("SSO_APPS_CLIENT_ID", "").strip()
    sso_apps_client_secret = os.environ.get("SSO_APPS_CLIENT_SECRET", "").strip()
    wac_username = os.environ.get("SSO_APPS_USER_USERNAME", "").strip()
    wac_password = os.environ.get("SSO_APPS_USER_PASSWORD", "").strip()

    if not verify_waconnect_username_and_password(wac_username, wac_password, logger):
        logger.error(script_not_working_message)
        return

    # Slug
    slug_candidates = _slug_candidates(logger)
    if not slug_candidates:
        logger.error("Could not determine slug. Set SMARTWEB_SLUG or SSO_APPS_USER_USERNAME.")
        logger.error(script_not_working_message)
        return

    slug = slug_candidates[0]
    if not verify_slug_validity(slug, logger):
        logger.error(script_not_working_message)
        return

    # Smartweb URL and URI
    smartweb_url = os.environ.get("SMARTWEB_URL", "").strip().rstrip("/")
    env_smartweb_uri = os.environ.get("SMARTWEB_URI", "").strip()

    if smartweb_url:
        logger.info("Using SMARTWEB_URL: %s", smartweb_url)
        smartweb_uri = env_smartweb_uri or slug
    else:
        # Fallback: fetch from Infra API
        raw_data = get_smartweb_data()
        if not raw_data:
            logger.error(script_not_working_message)
            return

        smartweb_data, preprod_smartweb_data, prod_smartweb_data = init_smartweb_data(raw_data)
        if not smartweb_data:
            logger.error("Smartweb data is not valid.")
            logger.error(script_not_working_message)
            return

        use_prod = os.environ.get("SMARTWEB_USE_PROD", "").strip() == "1"
        app_index = int(os.environ.get("SMARTWEB_APP_INDEX", "1"))

        found_apps = []
        for candidate in slug_candidates:
            source = prod_smartweb_data if use_prod else preprod_smartweb_data
            found_apps = verify_for_slug_in_smartweb_data(candidate, source)
            if not found_apps and not use_prod:
                found_apps = verify_for_slug_in_smartweb_data(candidate, prod_smartweb_data)
            if found_apps:
                slug = candidate
                break

        if not found_apps:
            logger.error("No Smartweb app found for slug candidates %s.", slug_candidates)
            logger.error(script_not_working_message)
            return

        if app_index < 1 or app_index > len(found_apps):
            logger.error("SMARTWEB_APP_INDEX %d out of range (1-%d).", app_index, len(found_apps))
            logger.error(script_not_working_message)
            return

        chosen_app = found_apps[app_index - 1]
        logger.info("Selected app: %s", chosen_app)

        try:
            smartweb_url = chosen_app["vhost_name"].rstrip("/")
            smartweb_uri = env_smartweb_uri or chosen_app["application_name"].split("_")[0]
        except KeyError as e:
            logger.error("KeyError unpacking Smartweb app data: %s", e)
            return

    logger.info("Smartweb URL: %s", smartweb_url)
    logger.info("Smartweb URI: %s", smartweb_uri)

    # Build passerelle connector updates
    common = {
        "token_ws_url": sso_apps_url,
        "client_id": sso_apps_client_id,
        "client_secret": sso_apps_client_secret,
        "username": wac_username,
        "password": wac_password,
    }
    passerelle_updates = {
        "restapi_actualites.json": {**common, "service_url": smartweb_url + "/@news_request_forwarder", "queries_uri": smartweb_uri},
        "restapi_annuaire.json":   {**common, "service_url": smartweb_url + "/@directory_request_forwarder", "queries_uri": smartweb_uri},
        "restapi_evenements.json": {**common, "service_url": smartweb_url + "/@events_request_forwarder", "queries_uri": smartweb_uri},
        "restapi_smartweb.json":   {**common, "service_url": smartweb_url},
    }

    # Write to both source dir and install dir
    for passerelle_dir in {os.path.join(script_dir, "passerelle"), "/usr/lib/teleservices_iacitizen/passerelle"}:
        for filename, updates in passerelle_updates.items():
            apply_updates_to_json_file(os.path.join(passerelle_dir, filename), updates, logger)

    # Combo tenant
    chosen_combo_tenant = _resolve_tenant(
        "/var/lib/combo/tenants", "combo", logger,
        env_override=os.environ.get("COMBO_TENANT", "").strip() or None,
        exclude_prefix="agent-",
    )
    if not chosen_combo_tenant:
        logger.error("No combo tenant resolved.")
        return
    check_and_update_combo_settings(chosen_combo_tenant, logger)

    # Hobo variables
    hobo_variables = {
        "ia_citizen": {"label": "Est un iA.Citizen", "value": "Oui"},
        "plone_actualites_url": {"label": 'Lien du bouton "Consulter toutes les actualités"', "value": smartweb_url + "/@@news_view"},
        "plone_evenements_url": {"label": 'Lien du bouton "Consulter tous les événements"', "value": smartweb_url + "/@@events_view"},
        "plone_annuaire_url":   {"label": 'Lien du bouton "Consulter l\'annuaire"', "value": smartweb_url + "/@@directory_view"},
    }
    try:
        with open(os.path.join(script_dir, "hobo_variables.json"), "w") as f:
            json.dump(hobo_variables, f, indent=4)
        logger.info("Updated hobo_variables.json.")
    except Exception as e:
        logger.error("Error updating hobo_variables.json: %s", e)
        return

    hobo_tenant = _resolve_tenant("/var/lib/hobo/tenants", "hobo", logger)
    if not hobo_tenant:
        logger.error("No hobo tenant resolved.")
        return

    try:
        subprocess.run(
            ["sudo", "-u", "hobo", "hobo-manage", "tenant_command", "runscript",
             "-d", hobo_tenant, os.path.join(script_dir, "hobo_variables_updater.py")],
            check=True,
        )
        logger.info("hobo_variables_updater.py has been run.")
    except subprocess.CalledProcessError as e:
        logger.error("Error running hobo_variables_updater.py: %s", e)
        return

    # Ensure required WCS roles exist
    wcs_tenant = _resolve_tenant("/var/lib/wcs/tenants", "WCS", logger)
    roles_file = os.path.join(script_dir, "roles", "roles.json")
    wcs_roles_script = os.path.join(script_dir, "wcs_roles_setup.py")
    if wcs_tenant and os.path.exists(roles_file) and os.path.exists(wcs_roles_script):
        try:
            subprocess.run(
                ["sudo", "-u", "wcs", "python3", wcs_roles_script, wcs_tenant, roles_file],
                check=True,
            )
            logger.info("WCS roles setup completed.")
        except subprocess.CalledProcessError as e:
            logger.error("Error during WCS roles setup: %s", e)
            return

    # Deploy
    try:
        subprocess.run(
            ["sudo", "-u", "hobo", "hobo-manage", "imio_indus_deploy",
             "--directory", "/usr/lib/teleservices_iacitizen", "-d", hobo_tenant],
            check=True,
        )
        logger.info("imio_indus_deploy completed successfully.")
    except subprocess.CalledProcessError as e:
        logger.error("Error running imio_indus_deploy: %s", e)
        return

    logger.info("iA.Citizen create_plone_restapi script has run successfully.")


if __name__ == "__main__":
    main()
