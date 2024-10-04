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
HOOK_URL = config['telegram']['HOOK_URL']

EVENTS_DIR = '/var/ossec/integrations/events'
DEFAULT_TEMPLATE_PATH = '/var/ossec/integrations/templates/default.json'
CSV_FILE_PATH = '/var/ossec/integrations/aggregated_events.csv'

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
    
    # Determine fields dynamically based on the first event's rule_id
    first_event = events[0]
    rule_id = first_event['rule']['id']
    fields = get_template_fields(rule_id, first_event)
    fieldnames = list(fields.keys())
    
    with open(CSV_FILE_PATH, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for event in events:
            rule_id = event['rule']['id']
            fields = get_template_fields(rule_id, event)
            row = {key: eval(value, {'alert_json': event}) for key, value in fields.items()}
            writer.writerow(row)

def send_aggregated_events(events):
    if not events:
        return
    
    # Use the first event to generate the message
    first_event = events[0]
    rule_id = first_event['rule']['id']
    template_path = f'/var/ossec/integrations/templates/{rule_id}.json'
    if not os.path.exists(template_path):
        template_path = DEFAULT_TEMPLATE_PATH
    message, _ = load_and_fill_template(template_path, first_event)
    
    # Read the CSV content
    with open(CSV_FILE_PATH, 'r') as file:
        csv_content = file.read()
    
    full_message = f"{message}\n\nCSV Data:\n{csv_content}"
    payload = {
        'chat_id': CHAT_ID,
        'text': full_message
    }
    headers = {'content-type': 'application/json', 'Accept-Charset': 'UTF-8'}
    response = requests.post(HOOK_URL, json=payload, headers=headers)
    return response.status_code

while True:
    events = parse_events()
    if events:
        save_to_csv(events)
        send_aggregated_events(events)
    time.sleep(30)