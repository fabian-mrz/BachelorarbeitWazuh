#!/usr/bin/env python

import sys
import json
import configparser
import os
from threading import Lock

# Read configuration from config.ini
config = configparser.ConfigParser()
config.read('/var/ossec/integrations/config.ini')

# Read the alert file
alert_file = open(sys.argv[1])
alert_json = json.loads(alert_file.read())
alert_file.close()

# Extract rule_id
rule_id = alert_json['rule']['id'] if 'id' in alert_json['rule'] else "N/A"

# Define a lock for thread-safe file operations
lock = Lock()

def save_event(rule_id, alert_json):
    # Create the events directory if it doesn't exist
    events_dir = '/var/ossec/integrations/events'
    if not os.path.exists(events_dir):
        os.makedirs(events_dir)
    
    file_path = os.path.join(events_dir, f'events_{rule_id}.json')
    with lock:
        if os.path.exists(file_path):
            with open(file_path, 'r+') as file:
                data = json.load(file)
                data.append(alert_json)
                file.seek(0)
                json.dump(data, file)
        else:
            with open(file_path, 'w') as file:
                json.dump([alert_json], file)

# Save the event
save_event(rule_id, alert_json)