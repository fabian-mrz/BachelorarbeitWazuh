import os
import json
import time
import requests
import pandas as pd
from datetime import datetime
from typing import List, Dict
import logging

# Constants
EVENTS_DIR = './events'
CSV_STORAGE_DIR = './static/incidents'
INCIDENT_SERVER_URL = "http://localhost:8000/incidents/"
RULE_DELAY = 5  # seconds between same rule events
BATCH_SIZE = 100  # events to process at once
FILE_CHECK_INTERVAL = 0.1  # seconds between file checks

# Setup
os.makedirs(CSV_STORAGE_DIR, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class EventProcessor:
    def __init__(self):
        self.last_rule_events = {}
        self.events_buffer = {}

    def get_rule_id_from_filename(self, filename: str) -> str:
        """Extract rule ID from filename"""
        return filename.split('_')[1].split('.')[0]

    def save_events_to_csv(self, events: List[Dict], rule_id: str) -> str:
        """Save events to CSV file"""
        incident_id = f"RULE_{rule_id}_{int(time.time())}"
        directory = os.path.join(CSV_STORAGE_DIR, incident_id)
        os.makedirs(directory, exist_ok=True)
        csv_path = os.path.join(directory, 'events.csv')
        
        df = pd.DataFrame(events)
        df.to_csv(csv_path, index=False)
        return f'/incidents/{incident_id}/events.csv'

    def create_incident(self, events: List[Dict], rule_id: str, csv_path: str):
        """Create incident from events"""
        first_event = events[0]
        incident = {
            "id": f"RULE_{rule_id}_{int(time.time())}",
            "timestamp": datetime.now().isoformat(),
            "description": json.dumps({
                "rule_id": rule_id,
                "rule_description": first_event['rule']['description'],
                "rule_level": first_event['rule']['level'],
                "total_events": len(events),
                "agent_names": list(set(e['agent']['name'] for e in events)),
                "first_event_timestamp": events[0]['timestamp'],
                "last_event_timestamp": events[-1]['timestamp'],
                "sample_event": first_event,
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
            logger.info(f"✅ Created incident for rule {rule_id}")
        except Exception as e:
            logger.error(f"Failed to create incident: {e}")

    def process_file(self, filepath: str, rule_id: str):
        """Process single rule file"""
        try:
            with open(filepath, 'r') as f:
                events = json.load(f)
                
                # Initialize buffer for rule if needed
                if rule_id not in self.events_buffer:
                    self.events_buffer[rule_id] = []
                
                self.events_buffer[rule_id].extend(events)
                
                # Process when batch size reached
                if len(self.events_buffer[rule_id]) >= BATCH_SIZE:
                    current_time = time.time()
                    
                    # Apply rate limiting
                    if rule_id in self.last_rule_events:
                        time_since_last = current_time - self.last_rule_events[rule_id]
                        if time_since_last < RULE_DELAY:
                            return
                    
                    self.last_rule_events[rule_id] = current_time
                    batch = self.events_buffer[rule_id][:BATCH_SIZE]
                    csv_path = self.save_events_to_csv(batch, rule_id)
                    self.create_incident(batch, rule_id, csv_path)
                    
                    # Remove processed events
                    self.events_buffer[rule_id] = self.events_buffer[rule_id][BATCH_SIZE:]
                    
                    # Clean up file if all events processed
                    if not self.events_buffer[rule_id]:
                        os.remove(filepath)
                        logger.info(f"Removed processed file: {filepath}")
                    
        except json.JSONDecodeError:
            logger.warning(f"Incomplete JSON in {filepath}, waiting...")
        except Exception as e:
            logger.error(f"Error processing {filepath}: {e}")

    def monitor_directory(self):
        """Monitor directory for new event files"""
        logger.info(f"🔍 Monitoring {EVENTS_DIR} for rule events...")
        
        while True:
            try:
                for filename in os.listdir(EVENTS_DIR):
                    if not filename.endswith('.json'):
                        continue
                        
                    filepath = os.path.join(EVENTS_DIR, filename)
                    rule_id = self.get_rule_id_from_filename(filename)
                    self.process_file(filepath, rule_id)
                    
            except Exception as e:
                logger.error(f"Directory monitoring error: {e}")
                
            time.sleep(FILE_CHECK_INTERVAL)

def main():
    processor = EventProcessor()
    try:
        processor.monitor_directory()
    except KeyboardInterrupt:
        logger.info("⚡ Stopping event monitoring...")

if __name__ == "__main__":
    main()