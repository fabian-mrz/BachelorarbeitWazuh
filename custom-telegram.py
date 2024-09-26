#file lies in /var/ossec/integrations/custom-telegram.py
#!/usr/bin/env python

import sys
import json
import requests
import configparser
from requests.auth import HTTPBasicAuth

# Read configuration from config.ini
config = configparser.ConfigParser()
config.read('/var/ossec/integrations/config.ini')

CHAT_ID = config['telegram']['CHAT_ID']
HOOK_URL = config['telegram']['HOOK_URL']

# Read the alert file
alert_file = open(sys.argv[1])
alert_json = json.loads(alert_file.read())
alert_file.close()

# Extract common data fields
alert_level = alert_json['rule']['level'] if 'level' in alert_json['rule'] else "N/A"
description = alert_json['rule']['description'] if 'description' in alert_json['rule'] else "N/A"
agent = alert_json['agent']['name'] if 'name' in alert_json['agent'] else "N/A"
rule_id = alert_json['rule']['id'] if 'id' in alert_json['rule'] else "N/A"

def load_and_fill_template(template_path, data):
    with open(template_path, 'r') as template_file:
        template_json = json.load(template_file)
    template = template_json['template']
    fields = template_json['fields']
    
    # Populate data dynamically
    populated_data = {key: eval(value) for key, value in fields.items()}
    
    return template.format(**populated_data)

# Define a function to get message data based on rule_id
def get_message_data(rule_id, alert_json):
    template_path = f'/var/ossec/integrations/templates/{rule_id}.json'
    try:
        message = load_and_fill_template(template_path, alert_json)
    except FileNotFoundError:
        # Fallback to default template
        message = load_and_fill_template('/var/ossec/integrations/templates/default.json', alert_json)
    return {
        'chat_id': CHAT_ID,
        'text': message
    }


# Get message data based on rule_id
msg_data = get_message_data(rule_id, alert_json)

headers = {'content-type': 'application/json', 'Accept-Charset': 'UTF-8'}

# Send the request
response = requests.post(HOOK_URL, headers=headers, data=json.dumps(msg_data))

# Print response for debugging
print(response.json())

sys.exit(0)