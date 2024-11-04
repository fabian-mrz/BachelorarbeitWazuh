import os
import json
import time
import requests
from datetime import datetime
import pandas as pd
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Constants
EVENTS_DIR = './events'
CSV_STORAGE_DIR = './static/incidents'
INCIDENT_SERVER_URL = "http://localhost:8000/incidents/"
# Add at top with other constants
RULE_DELAY = 5  # 5 seconds delay between same rule events
last_rule_events = {}  # Track last event time per rule ID

# Create required directories
os.makedirs(CSV_STORAGE_DIR, exist_ok=True)

def save_events_to_csv(events, incident_id):
    """Save events to CSV file"""
    directory = os.path.join(CSV_STORAGE_DIR, incident_id)
    os.makedirs(directory, exist_ok=True)
    
    csv_path = os.path.join(directory, 'events.csv')
    df = pd.DataFrame(events)
    df.to_csv(csv_path, index=False)
    
    return f'/incidents/{incident_id}/events.csv'

def process_rule_events(rule_events):
    """Process aggregated events and send incidents"""
    if not rule_events:
        return
        
    first_event = rule_events[0]
    rule_id = first_event['rule']['id']
    current_time = time.time()
    
    # Check if we need to wait for this rule
    if rule_id in last_rule_events:
        time_since_last = current_time - last_rule_events[rule_id]
        if time_since_last < RULE_DELAY:
            print(f"⏳ Waiting {RULE_DELAY - time_since_last:.1f}s for rule {rule_id}")
            time.sleep(RULE_DELAY - time_since_last)
    
    # Update last event time and process
    last_rule_events[rule_id] = current_time
    incident_id = f"{rule_id}_{int(current_time)}"
    csv_path = save_events_to_csv(rule_events, incident_id)
    
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
        print(f"✅ Events sent for rule {rule_id}")
    except Exception as e:
        print(f"❌ Error sending events: {e}")

class EventHandler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory:
            return
        if event.src_path.endswith('.json'):
            try:
                with open(event.src_path, 'r') as f:
                    rule_events = json.load(f)
                process_rule_events(rule_events)
                os.remove(event.src_path)  # Clean up processed file
            except Exception as e:
                print(f"Error processing file {event.src_path}: {e}")

def main():
    event_handler = EventHandler()
    observer = Observer()
    observer.schedule(event_handler, EVENTS_DIR, recursive=False)
    observer.start()
    print(f"🔍 Monitoring {EVENTS_DIR} for new events...")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("\n⚡ Stopping event monitoring...")
    
    observer.join()

if __name__ == "__main__":
    main()