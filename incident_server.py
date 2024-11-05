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
import subprocess
import time
import os
from pathlib import Path
import time
import wave



app = FastAPI()

# Add constants
BASE_DIR = './'
# Update constants at top of file
STATIC_DIR = './static/incidents'
TEMPLATES_DIR = './templates'
DEFAULT_TEMPLATE_PATH = os.path.join(TEMPLATES_DIR, 'default.json')
# Set output directory
OUTPUT_DIR = Path('/var/ossec/integrations')

#telegram
config = configparser.ConfigParser()
config.read('config.ini')

CHAT_ID = config['telegram']['CHAT_ID']
BOT_TOKEN = config['telegram']['BOT_TOKEN']
SIP_USERNAME = config['SIP']['username']
SIP_PASSWORD = config['SIP']['password']
SIP_HOST = config['SIP']['host']

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
    update_count: int = 0  # Add counter for updates

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
                
                # Make phone calls with await
                for contact_id in phase['contacts']:
                    contact = contacts[contact_id]
                    print(f"☎️ Calling {contact['name']} at {contact['phone']}")
                    await make_call(contact['phone'], message)
                    
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



##update
async def find_active_incident(rule_id: str) -> str:
    """Find existing unacknowledged incident for rule_id"""
    for inc_id, inc in incidents.items():
        if not inc.acknowledged:
            try:
                details = json.loads(inc.description)
                if details['rule_id'] == rule_id:
                    return inc_id
            except:
                continue
    return None

async def update_incident(incident_id: str, new_data: dict):
    """Update existing incident with new event data"""
    try:
        incident = incidents[incident_id]
        old_data = json.loads(incident.description)
        
        # Extract relevant data from new incident
        old_data['total_events'] = old_data.get('total_events', 0) + 1
        old_data['last_event_timestamp'] = new_data.get('last_event_timestamp', 
                                                       new_data.get('timestamp', 'N/A'))
        
        # Update agent names if present - handle lists properly
        if 'agent_names' in old_data and 'agent_names' in new_data:
            # Convert lists to sets, merge, then back to list
            old_agents = set(old_data['agent_names'])
            new_agents = set(new_data['agent_names'])
            old_data['agent_names'] = list(old_agents.union(new_agents))
            
        # Update sample event if present
        if 'sample_event' in new_data:
            old_data['sample_event'] = new_data['sample_event']
            
        # Update CSV path if present
        if 'csv_path' in new_data:
            old_data['csv_path'] = new_data['csv_path']
        
        # Update incident
        incident.description = json.dumps(old_data)
        incident.update_count += 1
        print(f"📝 Updated incident {incident_id} (Update #{incident.update_count})")
        
    except Exception as e:
        print(f"Error in update_incident: {e}")
        print(f"Old data: {old_data}")
        print(f"New data: {new_data}")
        raise


#call
def text_to_speech(text: str, output_file: Path) -> bool:
    """Convert text to speech using espeak"""
    try:
        # Convert Path to string for file operations
        output_path = str(output_file)
        with open(output_path, 'wb') as f:
            subprocess.run(
                ['espeak', '-v', 'en', '-s', '120', text, '--stdout'],
                stdout=f,
                check=True
            )
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error generating speech: {e}")
        return False

def get_wav_duration(filename: str) -> float:
    """Get duration of WAV file in seconds"""
    try:
        # Ensure we're working with string path
        filepath = str(filename) if isinstance(filename, Path) else filename
        with wave.open(filepath, 'rb') as wav_file:
            frames = wav_file.getnframes()
            rate = wav_file.getframerate()
            return frames / float(rate)
    except Exception as e:
        print(f"Error getting WAV duration: {e}")
        return 0.0
    
async def make_call(sip_address: str, message: str) -> None:
    """Make an async SIP call using linphonec"""
    
    # Start linphonec process
    process = await asyncio.create_subprocess_exec(
        'linphonec', '-d', '0',
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )

    async def write_cmd(cmd: str):
        """Helper to write commands to linphonec"""
        process.stdin.write(f"{cmd}\n".encode())
        await process.stdin.drain()

    try:
                # Generate speech file
        output_path = Path('output.wav')
        text_to_speech(message, output_path)
        duration = get_wav_duration(output_path)
        print(f"Output duration: {duration} seconds")
        # Register SIP account
        await write_cmd(f'register sip:{SIP_USERNAME}@{SIP_HOST} {SIP_PASSWORD}')
        await asyncio.sleep(3)

        # Configure for WAV files
        await write_cmd('soundcard use files')
        await asyncio.sleep(3)

        # Make the call
        await write_cmd(f'call {sip_address}')

        # Wait for connection
        while True:
            if process.stdout:
                line = await process.stdout.readline()
                if b"connected" in line:
                    print("Call connected.")
                    break

        # Play and monitor
        while True:
            print("Playing message...")
            await write_cmd('play output.wav')

            start_time = time.time()
            while time.time() - start_time < duration:
                if process.stdout:
                    line = await process.stdout.readline()
                    line_str = line.decode().strip()
                    print("Output:", line_str)

                    if "Receiving tone 4" in line_str:
                        print("ack")
                        await write_cmd('play ack.wav')
                        await asyncio.sleep(5)
                        await write_cmd('terminate')
                        await write_cmd('quit')
                        return

                    elif "Receiving tone 5" in line_str:
                        print("skipped") 
                        await write_cmd('play skip.wav')
                        await asyncio.sleep(5)
                        await write_cmd('terminate')
                        await write_cmd('quit')
                        return

                    elif "Receiving tone 6" in line_str:
                        print("replay")
                        break

                    elif "ended (Unknown error)" in line_str:
                        print("Call ended with unknown error.")
                        await write_cmd('terminate')
                        await write_cmd('quit')
                        return

                await asyncio.sleep(0.1)

    finally:
        # Cleanup
        if process.returncode is None:
            process.terminate()
            await process.wait()



### routes

@app.post("/incidents/")
async def create_incident(incident: Incident):
    try:
        incident_data = json.loads(incident.description)
        rule_id = incident_data['rule_id']
        
        # Check for existing active incident
        existing_id = await find_active_incident(rule_id)
        if existing_id:
            await update_incident(existing_id, incident_data)
            return {"message": "Incident updated", "id": existing_id}
            
        # Create new incident if none exists
        incidents[incident.id] = incident
        print(f"📝 New incident created: {incident.id}")
        
        # Start notification handling in background
        asyncio.create_task(send_notifications(incident.id))
        
        return {"message": "Incident created", "id": incident.id}
        
    except Exception as e:
        print(f"Error creating/updating incident: {e}")
        raise HTTPException(status_code=500, detail=str(e))

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