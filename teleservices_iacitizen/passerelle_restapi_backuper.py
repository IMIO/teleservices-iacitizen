from django.apps import apps

SLUGS_TO_BACKUP = ["actualites", "annuaire", "evenements", "site-web", "deliberations"]
BACKUP_PREFIX = "backup-"
TITLE_PREFIX = "[BACKUP] "

PloneRestAPI = apps.get_model("plone_restapi", "plonerestapi")

for slug in SLUGS_TO_BACKUP:
    backup_slug = BACKUP_PREFIX + slug

    connector = PloneRestAPI.objects.filter(slug=slug).first()
    if connector is None:
        print(f"Connector '{slug}' not found, skipping.")
        continue

    existing_backup_deleted, _ = (
        PloneRestAPI.objects.filter(slug=backup_slug).delete()
    )
    if existing_backup_deleted:
        print(f"Previous backup '{backup_slug}' removed to free the slug.")

    new_title = connector.title or slug
    if not new_title.startswith(TITLE_PREFIX):
        new_title = TITLE_PREFIX + new_title

    connector.slug = backup_slug
    connector.title = new_title
    connector.save()
    print(f"Backed up connector '{slug}' as '{backup_slug}'.")
