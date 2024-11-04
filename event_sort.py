import os
import json
import sys
from datetime import datetime
from threading import Lock

lock = Lock()

def parse_date(date_str):
    return datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%S.%f%z")

def evaluate_expression(expression, alert_json):
    return eval(expression)


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

# Read the alert file
alert_file = open(sys.argv[1])
alert_json = json.loads(alert_file.read())
alert_file.close()

# Save the event
save_event(alert_json["rule"]["id"], alert_json)