#/usr/bin/env python3

import sys
import json
import pytz
from datetime import datetime

import requests
from requests.auth import HTTPBasicAuth

class colors:
   RED = "15548997"
   GREEN = "5763719"
   YELLOW = "16705372"

rome_tz = pytz.timezone("Europe/Rome")

"""
ossec.conf configuration structure
 <integration>
     <name>custom-discord</name>
     <hook_url>https://discord.com/api/webhooks/XXXXXXXXXXX</hook_url>
     <alert_format>json</alert_format>
 </integration>
"""

# PER VEDERE LE PRINT DI DEBUG INSIEME AI LOG DEL CONTAINER IN STDOUT SI DEVE ESEGUIRE IL SEGUENTE COMANDO:
#    - /var/ossec/bin/wazuh-integratord -dd   ## DEBUG vero e proprio
# Altrimenti tutte le print di debug saranno disponibili in '/var/ossec/logs/integrations.log'

# Invio alert a DISCORD x DEBUG o errori
def send_alert(hook_url, content, title, color, description, fields):
    payload = json.dumps({
        "content": content,
        "embeds": [
            {
                "title": title,
                "color": color,
                "description": description,
                "fields": fields
            }
        ]
    })

    requests.post(hook_url, data=payload, headers={"content-type": "application/json"})

def debug(msg):
    log_time = get_time()
    msg = f"{log_time}: {msg}\n"
    print(msg)
    with open("/var/ossec/logs/integrations.log", "a") as log_file:
        log_file.write(msg)

def get_time():
    date = datetime.now()
    return date.astimezone(rome_tz).strftime("%Y-%m-%d %H:%M:%S")



debug(f"\n\n\n{'#'*200}\n")

# DEBUG: Look at input argument
for i, arg in enumerate(sys.argv):
    debug(f"sys.argv[{i}]: {arg}")

# read configuration
alert_file = sys.argv[1]
hook_url = sys.argv[3]

# read alert file
with open(alert_file) as f:
    alert_json = json.loads(f.read())
    debug(f"alert_json: {alert_json}\n")

# extract rule id
rule_id = int(alert_json["rule"]["id"])
debug(f"\n\n{'#'*30}\nrule_id: {rule_id}\n{'#'*30}\n")

if (rule_id == 100015 or rule_id == 100011 or rule_id == 100008):
    debug("Trovate regole scraping social con DANGER_LEVEL='INFO'. Skip invio notifica Discord...")
    sys.exit(0)

# extract alert level
alert_level = int(alert_json["rule"]["level"])

# extract rule description
rule_description = alert_json["rule"]["description"]

# extract agent details
if "agentless" in alert_json:
    agent_ = "agentless"
else:
    agent_ = alert_json["agent"]["name"]

# extract location details
if "location" in alert_json:
    location = alert_json['location']
else:
    location = ""

# extract hostname details
if "predecoder" in alert_json:
    if "hostname" in alert_json["predecoder"]:
        hostname = alert_json['predecoder']['hostname']
else:
    hostname = ""

if hostname:
    if location:
        received_from = f"{hostname} -> {location}"
    else:
        received_from = hostname
elif location:
    received_from = location
else:
    received_from = "N/A"

# Set message color (based on alert level)
## colors from https://gist.github.com/thomasbnt/b6f455e2c7d743b796917fa3c205f812
if(alert_level < 5):
    color = colors.GREEN
elif(alert_level >= 5 and alert_level <= 7):
    color = colors.YELLOW
else:
    color = colors.RED

# set color for specific alert (regole con DANGER_LEVEL='DANGER')
if (rule_id == 100013 or rule_id == 100009 or rule_id == 100006):
    color = colors.RED

# combine message details
## max description lenght: 4096 char - Source: https://discord.com/developers/docs/resources/message
if (len(str(alert_json)) > 4096):
    debug("L'alert che si voleva inviare è più lunga di 4096 char quindi verranno inviate solo le parti principali\n")
    tmp_alert_json = {}
    tmp_alert_json['too_long_alert'] = "Nella seguente alert vengono mostrate solo le parti salienti in quanto il messaggio eccedeva la dimensione massima consentita da Discord (4096 char)"
    tmp_alert_json['timestamp'] = alert_json['timestamp']

    if (len(alert_json['full_log']) > 3886): # 4096 - 210 char (len fissa struttura)
        debug("Anche la sola field alert_json['full_log'] è più lunga di 4096 char quindi non verrà inviata\n")
        tmp_alert_json['decoder'] = alert_json['decoder']
        tmp_alert_json['id'] = alert_json['id']
    else:
        tmp_alert_json['full_log'] = alert_json['full_log']

    debug(f"tmp_alert_json: {tmp_alert_json}\n")
    alert_json = tmp_alert_json
    debug(f"NUOVA alert_json: {alert_json}\n")

debug(f"Description alert (alert_json): {str(alert_json)}\n\nlen(str(alert_json)): {len(str(alert_json))}")

try:
    payload = json.dumps({
    "content": "",
    "embeds": [
        {
            "title": f"Wazuh Alert - Rule {rule_id}",
            "color": color,
            "description": str(alert_json),
            "fields": [{
                "name": "Agent",
                "value": agent_,
                "inline": True
            },
            { 
                "name": "Alert level",
                "value": alert_level,
                "inline": True
            },
            { 
                "name": "Received from",
                "value": received_from,
                "inline": True
            },
            {
                "name": "Description",
                "value": rule_description,
                "inline": False
            }]
        }
    ]
    })
except Exception as e:
    if rule_id:
        error = f"{get_time()} ERRORE: Non si è riusciti a inviare l'alert a Discord per la rule {rule_id}.\nErrore durante la costruzione del payload: {e}"
    else:
        error = f"{get_time()} ERRORE: Non si è riusciti a inviare l'alert a Discord.\nErrore durante la costruzione del payload: {e}"

    debug(error)
    send_alert(hook_url, "", "Errore invio alert!", colors.RED, error, [{"name": "Full error","value": str(e),"inline": False},{"name": "Hint","value": "Guarda il log in `/var/ossec/logs/integrations.log`","inline": False}])

debug(f"payload: {payload}\n")

# send message to Discord
try:
    r = requests.post(hook_url, data=payload, headers={"content-type": "application/json"})
    debug(f"r.status_code: {r.status_code}, r.text: {r.text}")
    r.raise_for_status()
except requests.RequestException as e:
    if rule_id:
        error = f"{get_time()} ERRORE: Non si è riusciti a inviare l'alert a Discord per la rule {rule_id}."
    else:
        error = f"{get_time()} ERRORE: Non si è riusciti a inviare l'alert a Discord."

    debug(f"{error}\nFull error: {str(e)}\n")
    send_alert(hook_url, "", "Errore invio alert!", colors.RED, error, [{"name": "Full error","value": str(e),"inline": False},{"name": "Hint","value": "Guarda il log in `/var/ossec/logs/integrations.log`","inline": False}])

sys.exit(0)
