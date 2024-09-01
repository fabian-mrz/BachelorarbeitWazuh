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

# Function to load and fill template
def load_and_fill_template(template_path, data):
    with open(template_path, 'r') as template_file:
        template = template_file.read()
    return template.format(**data)

# Define a function to get message data based on rule_id
def get_message_data(rule_id, alert_json):
    if rule_id == "60122":
        data = {
            'description': alert_json['rule']['description'],
            'alert_level': alert_json['rule']['level'],
            'agent': alert_json['agent']['name'],
            'timestamp': alert_json['timestamp'],
            'event_id': alert_json['data']['win']['system']['eventID'],
            'provider_name': alert_json['data']['win']['system']['providerName'],
            'logon_type': alert_json['data']['win']['eventdata']['logonType'],
            'ip_address': alert_json['data']['win']['eventdata']['ipAddress'],
            'failure_reason': alert_json['data']['win']['eventdata']['failureReason'],
            'mitre_tactics': ', '.join(alert_json['rule']['mitre']['tactic']),
            'mitre_techniques': ', '.join(alert_json['rule']['mitre']['technique']),
            'location': alert_json['location']
        }
        template_path = '/var/ossec/integrations/templates/60122.txt'
        message = load_and_fill_template(template_path, data)
        return {
            'chat_id': CHAT_ID,
            'text': message
        }
    # Add more rule_id cases here
    else:
        return {
            'chat_id': CHAT_ID,
            'text': f"Description: {description}\nAlert Level: {alert_level}\nAgent: {agent}"
        }

# Get message data based on rule_id
msg_data = get_message_data(rule_id, alert_json)

headers = {'content-type': 'application/json', 'Accept-Charset': 'UTF-8'}

# Send the request
response = requests.post(HOOK_URL, headers=headers, data=json.dumps(msg_data))

# Print response for debugging
print(response.json())

sys.exit(0)