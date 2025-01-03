import os
import json
import time
import requests
import pandas as pd
from datetime import datetime
from typing import List, Dict, Generator
import logging
import gc
import ijson  # For streaming JSON parsing


# Constants
EVENTS_DIR = './events'
CSV_STORAGE_DIR = './static/incidents'
INCIDENT_SERVER_URL = "https://192.168.178.40:8334/incidents/"
RULE_DELAY = 5
BATCH_SIZE = 50  # Reduced batch size
MAX_BUFFER_SIZE = 100  # Limit buffer size
CLEANUP_INTERVAL = 60  # Cleanup every minute
FILE_CHECK_INTERVAL = 5  # Check every 5 seconds
token = "1234"

# Setup
os.makedirs(CSV_STORAGE_DIR, exist_ok=True)

class EventProcessor:
    def __init__(self):
        self.last_rule_events = {}
        self.events_buffer = {}
        self.last_cleanup = time.time()

    def get_rule_id_from_filename(self, filename: str) -> str:
        """Extract rule ID from filename"""
        return filename.split('_')[1].split('.')[0]
    
    def stream_json_events(self, filepath: str) -> Generator[Dict, None, None]:
        """Stream JSON events instead of loading entire file"""
        try:
            with open(filepath, 'rb') as f:
                parser = ijson.items(f, 'item')
                for event in parser:
                    yield event
        except (OSError, ijson.JSONError) as e:
            logger.error(f"Error streaming JSON events from {filepath}: {e}")
            raise

    def save_events_to_csv(self, events: List[Dict], rule_id: str) -> str:
        """Save events to CSV file with chunking"""
        incident_id = f"RULE_{rule_id}_{int(time.time())}"
        directory = os.path.join(CSV_STORAGE_DIR, incident_id)
        os.makedirs(directory, exist_ok=True)
        csv_path = os.path.join(directory, 'events.csv')
        
        try:
            # Write CSV in chunks
            for i in range(0, len(events), 1000):
                chunk = events[i:i + 1000]
                mode = 'w' if i == 0 else 'a'
                pd.DataFrame(chunk).to_csv(csv_path, index=False, mode=mode, header=(i == 0))
        except (OSError, pd.errors.EmptyDataError) as e:
            logger.error(f"Error saving events to CSV for rule {rule_id}: {e}")
            raise
        
        return f'/incidents/{incident_id}/events.csv'
    
    def cleanup_buffers(self):
        """Perform periodic cleanup"""
        current_time = time.time()
        if current_time - self.last_cleanup > CLEANUP_INTERVAL:
            for rule_id in list(self.events_buffer.keys()):
                if len(self.events_buffer[rule_id]) > MAX_BUFFER_SIZE:
                    self.events_buffer[rule_id] = self.events_buffer[rule_id][-MAX_BUFFER_SIZE:]
            self.last_cleanup = current_time
            gc.collect()  # Force garbage collection

    def create_incident(self, events: List[Dict], rule_id: str, csv_path: str):
        """Create incident from events"""
        now = datetime.now()
        first_event = events[0]
        
        # Determine severity based on rule level
        severity = "high" if int(first_event['rule']['level']) >= 10 else "medium"
        
        incident = {
            "id": f"RULE_{rule_id}_{int(now.timestamp())}",
            "title": first_event['rule']['description'],
            "severity": severity,
            "source": "wazuh",
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
            "escalated": False,
            "created_at": now.isoformat()
        }

        try:
            response = requests.post(
                INCIDENT_SERVER_URL,
                json=incident,
                headers={
                    "Content-Type": "application/json",
                    "X-API-Key": token
                },
                verify=False  # Disable SSL verification
            )
            response.raise_for_status()
            logger.info(f"✅ Created incident for rule {rule_id}")
        except requests.RequestException as e:
            logger.error(f"Failed to create incident for rule {rule_id}: {e}")
            if hasattr(e, 'response') and e.response is not None:
                logger.error(f"Response body: {e.response.text}")

    def process_file(self, filepath: str, rule_id: str):
        """Process file in streaming mode"""
        try:
            self.cleanup_buffers()
            current_batch = []
            
            for event in self.stream_json_events(filepath):
                current_batch.append(event)
                
                if len(current_batch) >= BATCH_SIZE:
                    csv_path = self.save_events_to_csv(current_batch, rule_id)
                    self.create_incident(current_batch, rule_id, csv_path)
                    current_batch = []
                    gc.collect()
            
            if current_batch:  # Process remaining events
                csv_path = self.save_events_to_csv(current_batch, rule_id)
                self.create_incident(current_batch, rule_id, csv_path)
            
            if os.path.exists(filepath):
                os.remove(filepath)
                
        except Exception as e:
            logger.error(f"Error processing {filepath}: {e}")
        finally:
            gc.collect()

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