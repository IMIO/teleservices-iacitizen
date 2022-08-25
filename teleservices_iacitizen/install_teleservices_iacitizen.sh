#!/bin/bash

declare -A passerelle_actualites
declare -A passerelle_site_web
declare -A passerelle_annuaire
declare -A passerelle_deliberations
declare -A passerelle_evenements

passerelle_actualites[BASIC_AUTH_USERNAME]=""
passerelle_actualites[BASIC_AUTH_PW]=""
passerelle_actualites[SERVICE_URL]="https://actualites.enwallonie.be"
passerelle_actualites[TOKEN_WS_URL]="https://agents.wallonie-connect.be/idp/oidc/token/"
passerelle_actualites[CLIENT_ID]=""
passerelle_actualites[CLIENT_SECRET]=""
passerelle_actualites[USRNAME]=""
passerelle_actualites[PASSWORD]=""
passerelle_actualites[QUERIES_URI]=""

passerelle_annuaire[BASIC_AUTH_USERNAME]=""
passerelle_annuaire[BASIC_AUTH_PW]=""
passerelle_annuaire[SERVICE_URL]="https://annuaire.enwallonie.be"
passerelle_annuaire[TOKEN_URL]="https://agents.wallonie-connect.be/idp/oidc/token/"
passerelle_annuaire[CLIENT_ID]=""
passerelle_annuaire[CLIENT_SECRET]=""
passerelle_annuaire[USRNAME]=""
passerelle_annuaire[PASSWORD]=""
passerelle_annuaire[QUERIES_URI]=""

passerelle_deliberations[BASIC_AUTH_USERNAME]=""
passerelle_deliberations[BASIC_AUTH_PW]=""
passerelle_deliberations[SERVICE_URL]="https://www.deliberations.be"
passerelle_deliberations[TOKEN_URL]=""
passerelle_deliberations[CLIENT_ID]=""
passerelle_deliberations[CLIENT_SECRET]=""
passerelle_deliberations[USRNAME]=""
passerelle_deliberations[PASSWORD]=""
passerelle_deliberations[QUERY_NAME]=""
passerelle_deliberations[QUERY_SLUG]=""
passerelle_deliberations[QUERIES_URI]=""

passerelle_evenements[BASIC_AUTH_USERNAME]=""
passerelle_evenements[BASIC_AUTH_PW]=""
passerelle_evenements[SERVICE_URL]="https://agenda.enwallonie.be"
passerelle_evenements[TOKEN_URL]="https://agents.wallonie-connect.be/idp/oidc/token/"
passerelle_evenements[CLIENT_ID]=""
passerelle_evenements[CLIENT_SECRET]=""
passerelle_evenements[USRNAME]=""
passerelle_evenements[PASSWORD]=""
passerelle_evenements[QUERIES_URI]=""

passerelle_site_web[BASIC_AUTH_USERNAME]=""
passerelle_site_web[BASIC_AUTH_PW]=""
passerelle_site_web[SERVICE_URL]=""
passerelle_site_web[TOKEN_URL]=""
passerelle_site_web[CLIENT_ID]=""
passerelle_site_web[CLIENT_SECRET]=""
passerelle_site_web[USRNAME]=""
passerelle_site_web[PASSWORD]=""
passerelle_site_web[QUERIES_URI]=""

#Data that will populate ./forms/*.wcs ( not actually all *.wcs but only where is it needed)
FORM_PLONE_FOLDER=""
FORM_URI_PLONE=""

sed -i "s|FORM_PLONE_FOLDER|$FORM_PLONE_FOLDER|g" ./forms/form-actualite.wcs
sed -i "s|FORM_URI_PLONE|$FORM_URI_PLONE|g" ./forms/form-actualite.wcs

sed -i "s|FORM_PLONE_FOLDER|$FORM_PLONE_FOLDER|g" ./forms/form-annuaire.wcs
sed -i "s|FORM_URI_PLONE|$FORM_URI_PLONE|g" ./forms/form-annuaire.wcs

sed -i "s|FORM_PLONE_FOLDER|$FORM_PLONE_FOLDER|g" ./forms/form-evenement.wcs
sed -i "s|FORM_URI_PLONE|$FORM_URI_PLONE|g" ./forms/form-evenement.wcs


for key in "${!passerelle_actualites[@]}"
do
    sed -i "s|$key|${passerelle_actualites[$key]}|g" ./passerelle/export_plone-restapi_actualites.json
done

for key in "${!passerelle_annuaire[@]}"
do
    sed -i "s|$key|${passerelle_annuaire[$key]}|g" ./passerelle/export_plone-restapi_annuaire.json
done

for key in "${!passerelle_deliberations[@]}"
do
    sed -i "s|$key|${passerelle_deliberations[$key]}|g" ./passerelle/export_plone-restapi_delibertions.json
done

for key in "${!passerelle_evenements[@]}"
do
    sed -i "s|$key|${passerelle_evenements[$key]}|g" test-actu.json
done

for key in "${!passerelle_site_web[@]}"
do
    sed -i "s|$key|${passerelle_site_web[$key]}|g" test-actu.json
done


set -e # Exit immediately if a command exits with a non-zero status.

# installation path
install_path="/usr/lib/teleservices_iacitizen"

sudo -u hobo hobo-manage imio_indus_deploy --directory $install_path
