# incident_server.py
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from datetime import datetime
import asyncio
from typing import Dict
import json
import configparser
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import smtplib
import aiohttp
from email.mime.application import MIMEApplication
from telegram import Bot
from telegram.constants import ParseMode


app = FastAPI()

# Add constants
BASE_DIR = './'
# Update constants at top of file
STATIC_DIR = './static/incidents'
TEMPLATES_DIR = './templates'
DEFAULT_TEMPLATE_PATH = os.path.join(TEMPLATES_DIR, 'default.json')

#telegram
config = configparser.ConfigParser()
config.read('config.ini')

CHAT_ID = config['telegram']['CHAT_ID']
BOT_TOKEN = config['telegram']['BOT_TOKEN']

#email
SMTP_SERVER = config['SMTP']['server']
SMTP_PORT = 587  # Office365 uses port 587 for STARTTLS
SMTP_USER = config['SMTP']['username']
SMTP_PASS = config['SMTP']['password']
SMTP_FROM = config['SMTP']['from']

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

async def load_escalation_config(rule_id: str = None):
    """Load escalation config for specific rule or default"""
    with open('escalations.json') as f:
        escalations = json.load(f)
    
    if rule_id and rule_id in escalations['rules']:
        return escalations['rules'][rule_id]
    return escalations['default']

def load_contacts():
    """Load contacts from contacts.json"""
    with open('contacts.json') as f:
        return json.load(f)['contacts']
    
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



def process_template_fields(template_data: dict, incident_data: dict) -> dict:
    """Process template fields using incident data"""
    processed_fields = {}
    alert_json = incident_data['sample_event']  # Get sample event from incident
    
    for field_name, field_expr in template_data['fields'].items():
        try:
            eval_globals = {
                'alert_json': alert_json,
                'json': json,
                'len': len
            }
            processed_fields[field_name] = eval(field_expr, eval_globals, {})
        except Exception as e:
            print(f"Error processing field {field_name}: {e}")
            processed_fields[field_name] = 'N/A'
    
    return processed_fields


async def send_notifications(incident_id: str):
    """Send notifications with attachments using template and escalation config"""
    try:
        incident = incidents[incident_id]
        incident_data = json.loads(incident.description)
        rule_id = incident_data['rule_id']
        csv_filename = incident_data.get('csv_path')  # Directory name like "531_1730653308"
        csv_path = "./static" + csv_filename
        
        
        # Load configurations
        template_data = load_template(rule_id)
        escalation = await load_escalation_config(rule_id)
        contacts = load_contacts()
        
        # Process template once
        processed_fields = process_template_fields(template_data, incident_data)
        message = template_data['template'].format(**processed_fields)
        
        # Immediate notifications first (email and telegram)
        for contact_id in escalation['phases'][0]['contacts']:
            contact = contacts[contact_id]
            
            # Send email with attachment
            try:
                msg = MIMEMultipart()
                msg['From'] = SMTP_FROM
                msg['To'] = contact['email']
                msg['Subject'] = f"Security Alert - Rule {rule_id}"
                msg.attach(MIMEText(message, 'plain'))
                
                # Attach CSV if available
                if csv_path and os.path.exists(csv_path):
                    with open(csv_path, 'rb') as f:
                        part = MIMEApplication(f.read(), Name=os.path.basename(csv_path))
                        part['Content-Disposition'] = f'attachment; filename="{os.path.basename(csv_path)}"'
                        msg.attach(part)
                
                server = smtplib.SMTP("smtp.office365.com", 587)
                server.starttls()
                server.login(SMTP_USER, SMTP_PASS)
                server.send_message(msg)
                server.quit()
                print(f"✉️ Email sent to {contact['name']} ({contact['email']}) with attachment")
            except Exception as e:
                print(f"Error sending email to {contact['email']}: {e}")
            
            # Update the telegram part in send_notifications
            try:
                # Send telegram message and document
                await send_telegram_notification(
                    message=message,
                    csv_path=csv_path
                )
            except Exception as e:
                print(f"Error in telegram notification: {e}")
        
        # Handle phone calls with delay
        for phase in escalation['phases']:
            if incidents[incident_id].acknowledged:
                return
                
            if phase['type'] == 'phone':
                # Wait for configured delay
                if phase['delay'] > 0:
                    await asyncio.sleep(phase['delay'] * 60)
                
                if incidents[incident_id].acknowledged:
                    return
                
                # Simulate phone calls
                for contact_id in phase['contacts']:
                    contact = contacts[contact_id]
                    print(f"☎️ Calling {contact['name']} at {contact['phone']}")
                    # In real implementation, integrate with phone calling service here
                    
    except Exception as e:
        print(f"Error in notification process: {e}")


# Update telegram sending code
async def send_telegram_notification(message: str, csv_path: str = None):
    """Send telegram notification using python-telegram-bot"""
    try:
        bot = Bot(token=BOT_TOKEN)
        
        # Send message first
        await bot.send_message(
            chat_id=CHAT_ID,
            text=message,
            parse_mode=ParseMode.MARKDOWN
        )
        print(f"📱 Telegram message sent to CHATID")
        
        # Send document if available
        if csv_path and os.path.exists(csv_path):
            print(f"📎 Sending CSV via Telegram: {csv_path}")
            with open(csv_path, 'rb') as doc:
                await bot.send_document(
                    chat_id=CHAT_ID,
                    document=doc,
                    filename='events.csv'
                )
            print(f"📎 CSV file sent via Telegram")
            
    except Exception as e:
        print(f"Error sending telegram notification: {e}")


# Update incident creation to use new notification function
@app.post("/incidents/")
async def create_incident(incident: Incident):
    incidents[incident.id] = incident
    print(f"📝 New incident created: {incident.id}")
    
    # Start notification handling in background
    asyncio.create_task(send_notifications(incident.id))
    
    return {"message": "Incident created", "id": incident.id}








### routes

# Update incident creation to use new phase handling
@app.post("/incidents/")
async def create_incident(incident: Incident):
    incidents[incident.id] = incident
    print(f"📝 New incident created: {incident.id}")
    
    # Start phase handling in background
    asyncio.create_task(handle_incident_phases(incident.id))
    
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

@app.get("/api/escalations")
async def get_escalations():
    with open('escalations.json') as f:
        return json.load(f)

@app.post("/api/escalations")
async def save_escalations(escalations: dict):
    with open('escalations.json', 'w') as f:
        json.dump(escalations, f, indent=4)
    return {"message": "Escalations saved successfully"}

@app.get("/api/contacts")
async def get_contacts():
    with open('contacts.json') as f:
        return json.load(f)
    
@app.post("/api/contacts")
async def create_contact(contact: dict):
    with open('contacts.json', 'r+') as f:
        data = json.load(f)
        contact_id = f"contact_{len(data['contacts']) + 1}"
        data['contacts'][contact_id] = contact
        f.seek(0)
        json.dump(data, f, indent=4)
        f.truncate()
    return {"id": contact_id}

@app.delete("/api/contacts/{contact_id}")
async def delete_contact(contact_id: str):
    with open('contacts.json', 'r+') as f:
        data = json.load(f)
        if contact_id in data['contacts']:
            del data['contacts'][contact_id]
            f.seek(0)
            json.dump(data, f, indent=4)
            f.truncate()
            return {"message": "Contact deleted"}
        raise HTTPException(status_code=404, detail="Contact not found")
    
@app.put("/api/contacts/{contact_id}")
async def update_contact(contact_id: str, contact: dict):
    with open('contacts.json', 'r+') as f:
        data = json.load(f)
        if contact_id in data['contacts']:
            data['contacts'][contact_id] = contact
            f.seek(0)
            json.dump(data, f, indent=4)
            f.truncate()
            return {"message": "Contact updated"}
        raise HTTPException(status_code=404, detail="Contact not found")

app.mount("/", StaticFiles(directory="static", html=True), name="static")
app.mount("/", StaticFiles(directory=".", html=True), name="static")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)