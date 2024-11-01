import os
import json
import csv
import time
from datetime import datetime
import requests
import asyncio
from pathlib import Path

# Constants
EVENTS_DIR = './events'
TEMPLATES_DIR = './templates'
CSV_STORAGE_DIR = './static/incidents'
INCIDENT_SERVER_URL = "http://localhost:8000/incidents/"
DEFAULT_TEMPLATE_PATH = os.path.join(TEMPLATES_DIR, 'default.json')

# Create required directories
os.makedirs(CSV_STORAGE_DIR, exist_ok=True)
os.makedirs(TEMPLATES_DIR, exist_ok=True)

def load_template(rule_id):
    """Load template for specific rule_id or fall back to default"""
    template_path = os.path.join(TEMPLATES_DIR, f'{rule_id}.json')
    try:
        if os.path.exists(template_path):
            with open(template_path, 'r') as f:
                return json.load(f)
        with open(DEFAULT_TEMPLATE_PATH, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading template: {e}")
        return None

def get_field_values(template_fields, event):
    """Extract field values based on template"""
    values = {}
    for field_name, field_expr in template_fields.items():
        try:
            values[field_name] = eval(field_expr, {'alert_json': event})
        except Exception as e:
            #print(f"Error evaluating field {field_name}: {e}") # Commented out to avoid spamming logs
            values[field_name] = 'N/A'
    return values

def format_description(template, field_values):
    """Format description using template"""
    try:
        return template.format(**field_values)
    except Exception as e:
        print(f"Error formatting description: {e}")
        return "Error formatting description"

def parse_events():
    """Parse and aggregate events from JSON files"""
    aggregated_events = []
    for filename in os.listdir(EVENTS_DIR):
        if filename.startswith('events_') and filename.endswith('.json'):
            try:
                file_path = os.path.join(EVENTS_DIR, filename)
                with open(file_path, 'r') as file:
                    events = json.load(file)
                    aggregated_events.extend(events)
                os.remove(file_path)
            except Exception as e:
                print(f"Error processing {filename}: {e}")
    return aggregated_events

def save_to_csv(events, incident_id, template):
    """Save events to CSV using template fields"""
    if not events or not template:
        return None
    
    incident_dir = os.path.join(CSV_STORAGE_DIR, incident_id)
    os.makedirs(incident_dir, exist_ok=True)
    csv_path = os.path.join(incident_dir, "events.csv")
    
    try:
        with open(csv_path, 'w', newline='') as csvfile:
            fieldnames = list(template['fields'].keys())
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for event in events:
                row = get_field_values(template['fields'], event)
                writer.writerow(row)
        return f"/incidents/{incident_id}/events.csv"
    except Exception as e:
        print(f"Error writing CSV: {e}")
        return None

async def send_to_incident_server(events):
    """Send events to incident server with template-based CSV"""
    if not events:
        return
    
    events_by_rule_id = {}
    for event in events:
        rule_id = event['rule']['id']
        if rule_id not in events_by_rule_id:
            events_by_rule_id[rule_id] = []
        events_by_rule_id[rule_id].append(event)
    
    for rule_id, rule_events in events_by_rule_id.items():
        template = load_template(rule_id)
        if not template:
            continue
            
        incident_id = f"{rule_id}_{int(time.time())}"
        first_event = rule_events[0]
        
        # Save CSV and get path
        csv_path = save_to_csv(rule_events, incident_id, template)
        
        incident = {
            "id": incident_id,
            "timestamp": datetime.now().isoformat(),
            "description": json.dumps({
                "rule_id": rule_id,
                "rule_description": first_event['rule']['description'],
                "rule_level": first_event['rule']['level'],
                "total_events": len(rule_events),
                "agent_names": list(set(e['agent']['name'] for e in rule_events)),
                "first_event_timestamp": rule_events[0]['timestamp'],
                "last_event_timestamp": rule_events[-1]['timestamp'],
                "sample_event": rule_events[0],
                "csv_path": csv_path
            }),
            "acknowledged": False,
            "escalated": False
        }
        
        try:
            response = requests.post(
                INCIDENT_SERVER_URL,
                json=incident,
                headers={"Content-Type": "application/json"}
            )
            response.raise_for_status()
            print(f"Successfully sent incident {incident_id}")
        except requests.exceptions.RequestException as e:
            print(f"Failed to send incident: {e}")


async def main():
    """Main event processing loop"""
    while True:
        try:
            events = parse_events()
            if events:
                await send_to_incident_server(events)
        except Exception as e:
            print(f"Error in main loop: {e}")
        await asyncio.sleep(60)

if __name__ == '__main__':
    asyncio.run(main())