import os
import json
import sys
from datetime import datetime
from threading import Lock

lock = Lock()

def parse_date(date_str):
    return datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%S.%f%z")

def read_suppressions():
    try:
        with open('/home/wazuhserver/integrations/suppressions.json', 'r') as f:
            return json.load(f)
    except Exception as e:
        log_debug(f"Error reading suppressions.json: {str(e)}")
        return {}

def log_debug(message):
    log_dir = '/var/ossec/integrations/events'
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    with open(os.path.join(log_dir, 'log.txt'), 'a') as f:
        timestamp = datetime.now().isoformat()
        f.write(f"{timestamp}: {message}\n")

def get_field_value(alert_json, field):
    parts = field.split('.')
    value = alert_json
    for part in parts:
        if isinstance(value, dict):
            value = value.get(part, {})
        else:
            return None
    return value

def is_suppressed(alert_json, suppressions):
    for suppression_id, suppression in suppressions.items():
        matches_all_criteria = True
        
        # Check time range
        if not suppression['timeRange']['permanent']:
            current_time = datetime.now()
            start_time = datetime.fromisoformat(suppression['timeRange']['start'])
            end_time = datetime.fromisoformat(suppression['timeRange']['end'])
            if not (start_time <= current_time <= end_time):
                continue

        # Check all criteria
        for criterion in suppression['criteria']:
            field_value = get_field_value(alert_json, criterion['field'])
            if field_value is None:
                matches_all_criteria = False
                break

            if criterion['operator'] == 'equals':
                if str(field_value) != str(criterion['value']):
                    matches_all_criteria = False
                    break
            elif criterion['operator'] == 'contains':
                if str(criterion['value']) not in str(field_value):
                    matches_all_criteria = False
                    break

        if matches_all_criteria:
            log_debug(f"Alert suppressed by suppression ID: {suppression_id}")
            return True
            
    return False

def save_event(rule_id, alert_json):
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

# Main execution
try:
    alert_file = open(sys.argv[1])
    alert_json = json.loads(alert_file.read())
    alert_file.close()

    suppressions = read_suppressions()
    log_debug(f"Processing alert for rule ID: {alert_json['rule']['id']}")

    if not is_suppressed(alert_json, suppressions):
        save_event(alert_json["rule"]["id"], alert_json)
        log_debug(f"Event saved for rule ID: {alert_json['rule']['id']}")
    else:
        log_debug(f"Event suppressed for rule ID: {alert_json['rule']['id']}")

except Exception as e:
    log_debug(f"Error processing alert: {str(e)}")
    sys.exit(1)