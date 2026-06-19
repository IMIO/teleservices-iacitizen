import os
import subprocess

from .install_first import init_logging

"""Cleanup (delete) Plone REST API passerelle backup connectors.

Removes connectors previously renamed by backup_plone_restapi:
    backup-actualites, backup-annuaire, backup-evenements,
    backup-site-web, backup-deliberations

Example usage:
    cleanup_plone_restapi
"""


def resolve_passerelle_tenant(logger):
    try:
        tenants = (
            subprocess.run(
                "ls /var/lib/passerelle/tenants",
                shell=True,
                check=True,
                capture_output=True,
            )
            .stdout.decode("utf-8")
            .strip()
        )
    except subprocess.CalledProcessError as e:
        logger.error("Error while listing passerelle tenants: %s", e)
        return None

    if not tenants:
        logger.error("No passerelle tenants found.")
        return None

    tenant_list = tenants.splitlines()
    if len(tenant_list) > 1:
        logger.error(
            "Multiple passerelle tenants found (%s). Cannot auto-select.",
            ", ".join(tenant_list),
        )
        return None

    logger.info("Auto-selected passerelle tenant: %s", tenant_list[0])
    return tenant_list[0]


def main():
    logger = init_logging()

    script_dir = os.path.dirname(os.path.realpath(__file__))
    cleaner_script = os.path.join(script_dir, "passerelle_restapi_cleaner.py")

    passerelle_tenant = resolve_passerelle_tenant(logger)
    if not passerelle_tenant:
        logger.error("No passerelle tenant resolved. Aborting.")
        return

    try:
        subprocess.run(
            [
                "sudo", "-u", "passerelle",
                "passerelle-manage",
                "tenant_command", "runscript",
                "-d", passerelle_tenant,
                cleaner_script,
            ],
            check=True,
        )
        logger.info("Plone REST API backup connectors cleaned up successfully.")
    except subprocess.CalledProcessError as e:
        logger.error("Error while cleaning up Plone REST API backup connectors: %s", e)


if __name__ == "__main__":
    main()
