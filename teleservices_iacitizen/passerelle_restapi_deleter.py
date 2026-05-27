from django.apps import apps

SLUGS_TO_DELETE = ["actualites", "annuaire", "evenements", "site-web", "deliberations"]

PloneRestAPI = apps.get_model("plone_restapi", "plonerestapi")
for slug in SLUGS_TO_DELETE:
    deleted, _ = PloneRestAPI.objects.filter(slug=slug).delete()
    if deleted:
        print(f"Deleted connector '{slug}'.")
    else:
        print(f"Connector '{slug}' not found, skipping.")
