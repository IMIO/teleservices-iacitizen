import os
import sys

import requests

# TODO add raise

if len(sys.argv) != 3:
    print("Wrong number of arguments")
    exit()

path_base = "/usr/lib/teleservices_iacitizen"

url = "https://api.imio.be/imio/authentic/v1/services/agents"

print("Getting services/agents")
response = requests.get(url, auth=(os.environ['WEBSERVICE_AGENT_USER'], os.environ['WEBSERVICE_AGENT_PASSWORD']))

data = response.json()['data']

print("Parsing data")
for i in data:
    if sys.argv[1] in i['locality']['name'].lower():
        services_member = i['services']
    if "imio" in i['locality']['name'].lower():
        services_imio = i['services']

users_passwords = {
    "smartweb": {},
    "actualites": {},
    "annuaire": {},
    "evenements": {},
    "gen": {},
    "basic": {}
}

print("Setting user, password for oidc and other")
for service in services_member:
    if service['app'] == "iasmartweb-restapi":
        users_passwords['smartweb']['oidc_user'] = service['client_id']
        users_passwords['smartweb']['oidc_password'] = service['client_secret']
    if service['app'] == 'iateleservice':
        users_passwords['gen']['user'] = service['slug']

for service in services_imio:
    if service['app'] == "news-restapi":
        users_passwords['actualites']['oidc_user'] = service['client_id']
        users_passwords['actualites']['oidc_password'] = service['client_secret']
    if service['app'] == "directory-restapi":
        users_passwords['annuaire']['oidc_user'] = service['client_id']
        users_passwords['annuaire']['oidc_password'] = service['client_secret']
    if service['app'] == "events-restapi":
        users_passwords['evenements']['oidc_user'] = service['client_id']
        users_passwords['evenements']['oidc_password'] = service['client_secret']

for i in users_passwords.keys():
    if 'oidc_user' in users_passwords[i] and 'oidc_password' in users_passwords[i]:
        print(f"Sed {i}")
        print(" - Sed for oidc user")
        cmd = f's/"client_id": "",/"client_id": "{users_passwords[i]["oidc_user"]}",/g'
        try:
            os.system(f"sed -i '{cmd}' {path_base}/passerelle/restapi_{i}.json")
        except Exception as e:
            print(e)
        print(" - Sed for oidc password")
        cmd = f's/"client_secret": "",/"client_secret": "{users_passwords[i]["oidc_password"]}",/g'
        try:
            os.system(f"sed -i '{cmd}' {path_base}/passerelle/restapi_{i}.json")
        except Exception as e:
            print(e)

print("Sed gen user for all passerelle")
cmd_user = f's/"username": "",/"username": "{users_passwords["gen"]["user"]}",/g'
files = os.listdir(f"{path_base}/passerelle")
for file in files:
    if "deliberations" not in file:
        try:
            os.system(f"sed -i '{cmd_user}' {path_base}/passerelle/{file}")
        except Exception as e:
            print(e)

print("Sed uri for all passerelle")
cmd_uri = f's/"uri": "",/"uri": "{sys.argv[2]}",/g'
try:
    os.system(f"sed -i '{cmd_uri}' {path_base}/passerelle/*")
except Exception as e:
    print(e)

os.system(f'{path_base}/install_teleservices_iacitizen.sh')
