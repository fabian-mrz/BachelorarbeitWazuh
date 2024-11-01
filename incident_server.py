# incident_server.py
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from datetime import datetime
import asyncio
from typing import Dict
import telegram
import json
import configparser
from telegram.constants import ParseMode
import os
from pathlib import Path

app = FastAPI()

# Add constants
TEMPLATES_DIR = './templates'
DEFAULT_TEMPLATE_PATH = os.path.join(TEMPLATES_DIR, 'default.json')

# Add configuration loading
config = configparser.ConfigParser()
config.read('config.ini')

CHAT_ID = config['telegram']['CHAT_ID']
BOT_TOKEN = config['telegram']['BOT_TOKEN']

# In-memory storage (replace with database in production)
incidents = {}

class Incident(BaseModel):
    id: str
    timestamp: str
    description: str
    acknowledged: bool = False
    escalated: bool = False

async def handle_incident_timer(incident_id: str):
    await asyncio.sleep(60)
    if not incidents[incident_id].acknowledged:
        incidents[incident_id].escalated = True
        print(f"⚠️ Incident {incident_id} not acknowledged within 60 seconds - escalating!")
        
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

async def send_telegram_notification(incident_data):
    """Send incident notification via Telegram using templates"""
    try:
        bot = telegram.Bot(BOT_TOKEN)
        details = json.loads(incident_data['description'])
        
        # Load appropriate template
        template = load_template(details['rule_id'])
        if not template:
            print("Failed to load template, skipping notification")
            return
        
        # Get field values using template
        field_values = {}
        for field_name, field_expr in template['fields'].items():
            try:
                # Use sample_event for field evaluation
                field_values[field_name] = eval(field_expr, {
                    'alert_json': details['sample_event'],
                    'json': json  # Make json available for sample_event formatting
                })
            except Exception as e:
                print(f"Error evaluating field {field_name}: {e}")
                field_values[field_name] = 'N/A'
        
        # Format message using template
        message = template['template'].format(**field_values)
        
        await bot.send_message(
            chat_id=CHAT_ID,
            text=message,
            parse_mode=ParseMode.MARKDOWN
        )
        print(f"Telegram notification sent for incident {incident_data['id']}")
    except Exception as e:
        print(f"Error sending Telegram notification: {e}")

# Modify the create_incident endpoint
@app.post("/incidents/")
async def create_incident(incident: Incident):
    incidents[incident.id] = incident
    asyncio.create_task(handle_incident_timer(incident.id))
    
    # Send Telegram notification
    await send_telegram_notification(incident.dict())
    
    return {"message": "Incident created", "id": incident.id}

@app.post("/incidents/{incident_id}/acknowledge")
async def acknowledge_incident(incident_id: str):
    if incident_id not in incidents:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    incident = incidents[incident_id]
    if not incident.escalated:
        incident.acknowledged = True
        print(f"✅ Incident {incident_id} acknowledged successfully")
        return {"message": "Incident acknowledged"}
    else:
        return {"message": "Incident already escalated"}

@app.get("/incidents/")
async def list_incidents():
    return incidents

app.mount("/", StaticFiles(directory="static", html=True), name="static")