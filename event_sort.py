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

def is_suppressed(alert_json, suppression_criteria):
    for criteria in suppression_criteria:
        match = True
        suppression_fields = criteria["fields"]
        for key, value in criteria.items():
            if key == "timeframe":
                start_time, end_time = value.split('/')
                event_time = parse_date(evaluate_expression(suppression_fields["timestamp"], alert_json))
                if not (parse_date(start_time) <= event_time <= parse_date(end_time)):
                    match = False
                    break
            elif key != "fields":
                field_value = evaluate_expression(suppression_fields[key], alert_json)
                if field_value != value:
                    match = False
                    break
        if match:
            return True
    return False

def save_event(rule_id, alert_json):
    if is_suppressed(alert_json, suppression_criteria):
        print(f"Event with rule_id {rule_id} is suppressed.")
        return

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

# Load suppression criteria from suppression.json
with open('/var/ossec/integrations/suppression.json') as suppression_file:
    suppression_data = json.load(suppression_file)
    suppression_criteria = suppression_data['criteria']

# Read the alert file
alert_file = open(sys.argv[1])
alert_json = json.loads(alert_file.read())
alert_file.close()

# Save the event
save_event(alert_json["rule"]["id"], alert_json)