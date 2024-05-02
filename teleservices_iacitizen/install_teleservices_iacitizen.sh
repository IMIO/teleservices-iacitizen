#!/bin/bash

set -e # Exit immediately if a command exits with a non-zero status.

# Ask for the commune slug
echo "Veuillez entrer le slug de la commune :"
read commune_slug

# List of selected files
selected_files=("restapi_actualites.json" "restapi_annuaire.json" "restapi_evenements.json.json")

# Use a loop to apply the change to all selected files
for file in "${selected_files[@]}"; do
    # Use sed to replace "uri": "saintvith" with "uri": "value_of_COMMUNE_SLUG" in the file
    sed -i "s/\"uri\": \"saintvith\"/\"uri\": \"$commune_slug\"/g" "$file"
done

# installation path
install_path="/usr/lib/teleservices_iacitizen"

sudo -u hobo hobo-manage imio_indus_deploy --directory $install_path
