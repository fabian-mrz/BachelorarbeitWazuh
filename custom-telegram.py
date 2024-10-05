#!/usr/bin/env python

import os
import json
import csv
import time
import requests
import configparser

# Read configuration from config.ini
config = configparser.ConfigParser()
config.read('/var/ossec/integrations/config.ini')

CHAT_ID = config['telegram']['CHAT_ID']
BOT_TOKEN = config['telegram']['BOT_TOKEN']
HOOK_URL = f"https://api.telegram.org/bot{BOT_TOKEN}/sendDocument"

EVENTS_DIR = '/var/ossec/integrations/events'
DEFAULT_TEMPLATE_PATH = '/var/ossec/integrations/templates/default.json'
CSV_FILE_PATH_TEMPLATE = '/var/ossec/integrations/{rule_id}_aggregated_events.csv'

def parse_events():
    aggregated_events = []
    for filename in os.listdir(EVENTS_DIR):
        if filename.startswith('events_') and filename.endswith('.json'):
            with open(os.path.join(EVENTS_DIR, filename), 'r') as file:
                events = json.load(file)
                for event in events:
                    aggregated_events.append(event)
            os.remove(os.path.join(EVENTS_DIR, filename))
    return aggregated_events

def load_and_fill_template(template_path, alert_json):
    with open(template_path, 'r') as template_file:
        template_json = json.load(template_file)
    template = template_json['template']
    fields = template_json['fields']
    
    # Populate data
    populated_data = {key: eval(value, {'alert_json': alert_json}) for key, value in fields.items()}
    
    return template.format(**populated_data), fields

def get_template_fields(rule_id, alert_json):
    template_path = f'/var/ossec/integrations/templates/{rule_id}.json'
    if not os.path.exists(template_path):
        template_path = DEFAULT_TEMPLATE_PATH
    _, fields = load_and_fill_template(template_path, alert_json)
    return fields

def save_to_csv(events):
    if not events:
        return
    
    # Group events by rule_id
    events_by_rule_id = {}
    for event in events:
        rule_id = event['rule']['id']
        if rule_id not in events_by_rule_id:
            events_by_rule_id[rule_id] = []
        events_by_rule_id[rule_id].append(event)
    
    # Save each group of events to a separate CSV file
    for rule_id, events in events_by_rule_id.items():
        fields = get_template_fields(rule_id, events[0])
        fieldnames = list(fields.keys())
        csv_file_path = CSV_FILE_PATH_TEMPLATE.format(rule_id=rule_id)
        
        with open(csv_file_path, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for event in events:
                row = {key: eval(value, {'alert_json': event}) for key, value in fields.items()}
                writer.writerow(row)
        # logging.info(f"CSV file created: {csv_file_path}")

def send_aggregated_events(events):
    if not events:
        return
    
    # Group events by rule_id
    events_by_rule_id = {}
    for event in events:
        rule_id = event['rule']['id']
        if rule_id not in events_by_rule_id:
            events_by_rule_id[rule_id] = []
        events_by_rule_id[rule_id].append(event)
    
    # Send an alert for each group of events
    for rule_id, events in events_by_rule_id.items():
        # Use the first event to generate the message
        first_event = events[0]
        template_path = f'/var/ossec/integrations/templates/{rule_id}.json'
        if not os.path.exists(template_path):
            template_path = DEFAULT_TEMPLATE_PATH
        message, _ = load_and_fill_template(template_path, first_event)
        
        # Append the number of events to the message
        event_count = len(events)
        message += f"\n\nNumber of events in CSV: {event_count}"
        
        # Log the generated message
        # logging.info(f"Generated message: {message}")
        
        # Determine the CSV file path
        csv_file_path = CSV_FILE_PATH_TEMPLATE.format(rule_id=rule_id)
        
        # Send the message with the CSV file as an attachment
        payload = {
            'chat_id': CHAT_ID,
            'caption': message
        }
        try:
            with open(csv_file_path, 'rb') as csvfile:
                files = {'document': csvfile}
                response = requests.post(HOOK_URL, data=payload, files=files)
                # logging.info(f"Message sent with status code: {response.status_code}")
                if response.status_code != 200:
                    # logging.error(f"Error sending message: {response.text}")
                    pass
        except Exception as e:
            # logging.error(f"Error opening or sending CSV file: {e}")
            pass

while True:
    events = parse_events()
    if events:
        save_to_csv(events)
        send_aggregated_events(events)
    time.sleep(60)