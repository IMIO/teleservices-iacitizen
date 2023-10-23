JSON_CELL_TYPES.update(
    {
        "actualites": {
            "cache_duration": 120,
            "force_async": False,
            "form": [
                {
                    "label": "Identifiant du connecteur Plone REST API",
                    "type": "string",
                    "varname": "connector"
                },
                {
                    "label": "Identifiant de la requête",
                    "type": "string",
                    "varname": "query"
                }
            ],
            "name": "Actualités",
            "log_errors": False,
            "url": "{{ passerelle_url }}plone-restapi/{{ connector }}/q/{{ query }}/"
        },
        "deliberations-communales": {
            "cache_duration": 360,
            "force_async": False,
            "name": "Délibérations communales",
            "log_errors": False,
            "url": "{{ deliberations_communales_json_url|safe }}"
        },
        "evenements": {
            "cache_duration": 120,
            "force_async": False,
            "form": [
                {
                    "label": "Identifiant du connecteur Plone REST API",
                    "type": "string",
                    "varname": "connector"
                },
                {
                    "label": "Identifiant de la requête",
                    "type": "string",
                    "varname": "query"
                }
            ],
            "name": "Événements",
            "log_errors": False,
            "url": "{{ passerelle_url }}plone-restapi/{{ connector }}/q/{{ query }}/"
        }
    }
)
