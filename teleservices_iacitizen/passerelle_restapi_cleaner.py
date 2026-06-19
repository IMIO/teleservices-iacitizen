from django.apps import apps

BACKUP_SLUGS_TO_DELETE = [
    "backup-actualites",
    "backup-annuaire",
    "backup-evenements",
    "backup-site-web",
    "backup-deliberations",
]

PloneRestAPI = apps.get_model("plone_restapi", "plonerestapi")
for slug in BACKUP_SLUGS_TO_DELETE:
    deleted, _ = PloneRestAPI.objects.filter(slug=slug).delete()
    if deleted:
        print(f"Deleted backup connector '{slug}'.")
    else:
        print(f"Backup connector '{slug}' not found, skipping.")
