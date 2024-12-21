import os
import json
import sys
from datetime import datetime
from threading import Lock

lock = Lock()

def parse_date(date_str):
    try:
        if not date_str:
            log_debug(f"Empty timestamp received")
            return None
        
        # Handle various timestamp formats
        if '+' in date_str:
            # Format: 2024-12-19T03:22:38.652+0000
            return datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%S.%f%z")
        else:
            # Format without timezone
            return datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%S.%f")
            
    except ValueError as e:
        log_debug(f"Timestamp parsing error: {str(e)} for value: {date_str}")
        return None

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
    # Validate timestamp before saving
    if 'timestamp' in alert_json:
        parsed_time = parse_date(alert_json['timestamp'])
        if not parsed_time:
            log_debug(f"Invalid timestamp in alert: {alert_json['timestamp']}")
            alert_json['timestamp'] = datetime.now().isoformat()
            
    events_dir = '/var/ossec/integrations/events'
    if not os.path.exists(events_dir):
        os.makedirs(events_dir)
        log_debug(f"Created events directory: {events_dir}")
    
    file_path = os.path.join(events_dir, f'events_{rule_id}.json')
    with lock:
        try:
            if os.path.exists(file_path):
                log_debug(f"Updating existing file: {file_path}")
                with open(file_path, 'r+') as file:
                    log_debug(f"Current file content: {file.read()}")
                    file.seek(0)
                    data = json.load(file)
                    data.append(alert_json)
                    file.seek(0)
                    json.dump(data, file)
                    log_debug(f"Updated file with new alert")
            else:
                log_debug(f"Creating new file: {file_path}")
                with open(file_path, 'w') as file:
                    json.dump([alert_json], file)
                    log_debug(f"Created new file with alert")
        except json.JSONDecodeError as e:
            log_debug(f"JSON error in file {file_path}: {str(e)}")
            raise
        except Exception as e:
            log_debug(f"File operation error: {str(e)}")
            raise

# Main execution
try:
    alert_file = open(sys.argv[1])
    log_debug(f"Reading alert file: {sys.argv[1]}")
    alert_content = alert_file.read()
    log_debug(f"Alert content: {alert_content}")
    alert_json = json.loads(alert_content)
    alert_file.close()

    # Validate timestamp immediately after parsing
    if 'timestamp' in alert_json:
        log_debug(f"Validating timestamp: {alert_json['timestamp']}")
        if not parse_date(alert_json['timestamp']):
            log_debug(f"Using current timestamp instead")
            alert_json['timestamp'] = datetime.now().isoformat()

    suppressions = read_suppressions()
    log_debug(f"Loaded suppressions: {json.dumps(suppressions, indent=2)}")
    log_debug(f"Processing alert for rule ID: {alert_json['rule']['id']}")
    log_debug(f"Alert data: {json.dumps(alert_json, indent=2)}")

    if not is_suppressed(alert_json, suppressions):
        save_event(alert_json["rule"]["id"], alert_json)
        log_debug(f"Event saved for rule ID: {alert_json['rule']['id']}")
    else:
        log_debug(f"Event suppressed for rule ID: {alert_json['rule']['id']}")

except json.JSONDecodeError as e:
    log_debug(f"JSON parsing error: {str(e)}")
    sys.exit(1)
except Exception as e:
    log_debug(f"Error processing alert: {str(e)}")
    sys.exit(1)