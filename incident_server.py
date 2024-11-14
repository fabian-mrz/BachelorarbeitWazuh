# incident_server.py
from fastapi import FastAPI, HTTPException, Depends, Security, status
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from datetime import datetime
import asyncio
from typing import Dict, Optional, List
import json
import configparser
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import smtplib
from email.mime.application import MIMEApplication
from telegram import Bot
from telegram.constants import ParseMode
import subprocess
import time
from pathlib import Path
import wave
import threading
import re
from auth import verify_auth, create_access_token, get_db, verify_token
from sqlalchemy.orm import Session
import uvicorn



app = FastAPI()


##
class LinphoneController:
    def reset(self):
        """Reset controller state between calls"""
        self.dtmf_digits = []
        self.call_active = False
        self.call_result = None
        self.stop_audio = False
        self.call_error = None
        if self.process:
            try:
                self.process.terminate()
                self.process = None
            except:
                pass

    def text_to_speech(self, text: str, filename: str = "output.wav") -> None:
            """Convert text to speech and save as wav file"""
            try:
                subprocess.run(['espeak', text, '--stdout', '-s', '120'], stdout=open(filename, 'wb'))
            except Exception as e:
                print(f"Error generating speech: {e}")

    def __init__(self, sip_server: str, username: str, password: str):
        self.sip_server = sip_server
        self.username = username
        self.password = password
        self.process: Optional[subprocess.Popen] = None
        self.dtmf_digits: List[str] = []
        self.call_active = False
        self.call_result = None
        self.stop_audio = False  # New flag for audio control
        self.call_error = None  # Track error state

    def _handle_dtmf(self, digit: str) -> Optional[bool]:
        """Handle DTMF input and return True/False/None based on digit"""
        if digit == '4':
            print("Acknowledged")
            self.stop_audio = True  # Stop audio loop
            time.sleep(0.5)  # Small delay to ensure audio stops
            self._write_command("play ack.wav")
            time.sleep(4)
            self.call_active = False
            return True
        elif digit == '5':
            print("Skipped")
            self.stop_audio = True  # Stop audio loop
            time.sleep(0.5)  # Small delay to ensure audio stops
            self._write_command("play skip.wav")
            time.sleep(4)
            self.call_active = False
            return False
        return None
        
    def _write_command(self, command: str) -> None:
        """Write command to linphonec"""
        print(f"Writing command: {command}")
        self.process.stdin.write(f"{command}\n".encode())
        self.process.stdin.flush()

    def _play_audio_loop(self) -> None:
        print("audio loop")
        """Play audio file in loop while call is active"""
        wav_file = "output.wav"
        duration = self._get_wav_duration(wav_file)
        
        while self.call_active and not self.stop_audio:
            print("Playing audio")
            self._write_command(f"play {wav_file}")
            time.sleep(duration + 0.5)

    def _get_wav_duration(self, filename: str) -> float:
        """Get duration of wav file in seconds using ffprobe"""
        try:
            cmd = [
                'ffprobe', 
                '-v', 'quiet',
                '-show_entries', 'format=duration',
                '-of', 'json',
                filename
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)
            import json
            duration = float(json.loads(result.stdout)['format']['duration'])
            print(f"Duration of {filename}: {duration:.2f} seconds")
            return duration
        except Exception as e:
            print(f"Error getting audio duration: {e}")
            return 3.0  # Reasonable fallback for espeak output
        

    def _read_output(self) -> None:
        """Read and process linphonec output"""
        while self.call_active:
            line = self.process.stdout.readline().decode().strip()
            print(f"Linphone output: {line}")
            if "Call" in line and "connected" in line:
                audio_thread = threading.Thread(target=self._play_audio_loop)
                audio_thread.daemon = True
                audio_thread.start()
            elif "Receiving tone" in line:
                digit = re.search(r"tone (\d)", line)
                if digit:
                    digit_value = digit.group(1)
                    self.dtmf_digits.append(digit_value)
                    result = self._handle_dtmf(digit_value)
                    if result is not None:
                        self.call_result = result
            elif "Call" in line and "error" in line:
                self.call_error = "error"
                self.call_active = False
                self.call_result = False
            elif "Call" in line and "declined" in line:
                self.call_error = "declined"
                self.call_active = False
                self.call_result = False
            elif "Call" in line and "ended" in line:
                self.call_active = False
                
    def make_call(self, number: str, message: str, timeout: int = 60) -> List[str]:
        """Make a call and collect DTMF tones"""
        try:
            print("Making call")
            self.reset()

            # Generate speech file first
            self.text_to_speech(message)
            
            # Start linphonec process
            print("Starting linphonec process")
            self.process = subprocess.Popen(
                ["linphonec"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Register SIP account
            print("Registering SIP account")
            self._write_command(f"register sip:{self.username}@{self.sip_server} {self.password}")
            time.sleep(1)  # Wait for registration
            
            # Configure audio
            print("Configuring audio")
            self._write_command("soundcard use files")
            time.sleep(1)
            
            # Start call
            print(f"Making call to {number}")
            self._write_command(f"call {number}")
            self.call_active = True
            
            # Start output reading thread
            print("Starting output thread")
            output_thread = threading.Thread(target=self._read_output)
            output_thread.start()
            
            # Wait for timeout or call end
            print(f"Waiting for call to complete (timeout: {timeout} seconds)")
            timeout_time = time.time() + timeout
            while self.call_active and time.time() < timeout_time:
                time.sleep(0.1)
                
            # Cleanup
            print("Call completed - cleaning up")
            self.call_active = False
            self._write_command("terminate")
            self._write_command("quit")
            output_thread.join()
            self.process.terminate()
            
            return self.dtmf_digits, self.call_result, self.call_error
            
        except Exception as e:
            print(f"Error: {e}")
            if self.process:
                self.process.terminate()
            return [], None, "error"

# Add constants
BASE_DIR = './'
# Update constants at top of file
STATIC_DIR = './static/incidents'
TEMPLATES_DIR = './templates'
DEFAULT_TEMPLATE_PATH = os.path.join(TEMPLATES_DIR, 'default.json')
# Set output directory
OUTPUT_DIR = Path('/var/ossec/integrations')
SUPPRESSIONS_FILE = Path("suppressions.json")

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

#phone controller
# Global LinphoneController instance
phone_controller = LinphoneController(
    sip_server=SIP_HOST,
    username=SIP_USERNAME, 
    password=SIP_PASSWORD
)


# In-memory storage (replace with database in production)
incidents = {}

class Incident(BaseModel):
    id: str
    timestamp: str
    description: str
    acknowledged: bool = False
    acknowledged_by: str = None
    escalated: bool = False
    update_count: int = 0  # Add counter for updates


# Update models in incident_server.py
class TimeRange(BaseModel):
    permanent: bool = False
    start: Optional[str] = None
    end: Optional[str] = None

class SuppressionCriterion(BaseModel):
    field: str
    operator: str
    value: str
    booleanOperator: Optional[str] = None

class SuppressionRule(BaseModel):
    id: str
    created: str
    criteria: List[SuppressionCriterion]
    timeRange: TimeRange

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
            # try:
            #     msg = MIMEMultipart()
            #     msg['From'] = SMTP_FROM
            #     msg['To'] = contact['email']
            #     msg['Subject'] = f"Security Alert - Rule {rule_id}"
            #     msg.attach(MIMEText(message, 'plain'))
                
            #     # Attach CSV if available
            #     if csv_path and os.path.exists(csv_path):
            #         with open(csv_path, 'rb') as f:
            #             part = MIMEApplication(f.read(), Name=os.path.basename(csv_path))
            #             part['Content-Disposition'] = f'attachment; filename="{os.path.basename(csv_path)}"'
            #             msg.attach(part)
                
            #     server = smtplib.SMTP("smtp.office365.com", 587)
            #     server.starttls()
            #     server.login(SMTP_USER, SMTP_PASS)
            #     server.send_message(msg)
            #     server.quit()
            #     print(f"✉️ Email sent to {contact['name']} ({contact['email']}) with attachment")
            # except Exception as e:
            #     print(f"Error sending email to {contact['email']}: {e}")
            
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
                    print(f"📞 Calling {contacts[contact_id]['name']} ({contacts[contact_id]['phone']})")
                    contact = contacts[contact_id]
                    ack = await make_phone_call(contact, f"Security Alert. Please press 4 to acknoledge and 5 to skip. {message}")
                    if ack:
                        incidents[incident_id].acknowledged = True
                        incidents[incident_id].acknowledged_by = contact['name']
                        print(f"✅ Incident {incident_id} acknowledged by {contact['name']}")
                        return
                    
                                  


                    
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
async def make_phone_call(contact: dict, message: str) -> bool:
    """Make phone call and return if acknowledged"""
    try:
        print(f"📞 Starting call to {contact['name']}")
        print(f"   Phone: {contact['phone']}")
        print(f"   Message length: {len(message)} chars")
        
        # Validate contact data
        if not contact.get('phone'):
            print("❌ Invalid phone number in contact")
            return False
            
        # Debug LinphoneController state
        print(f"   SIP Server: {phone_controller.sip_server}")
        print(f"   SIP Username: {phone_controller.username}")
        print(f"   Process active: {phone_controller.process is not None}")
        
        # Make the call with detailed error handling
        dtmf, success, error = phone_controller.make_call(
            number=contact['phone'],
            message=message,
            timeout=60
        )
        
        print(f"   Call completed:")
        print(f"   - DTMF received: {dtmf}")
        print(f"   - Success: {success}")
        print(f"   - Error: {error}")
        
        if error:
            print(f"❌ Call failed for {contact['name']}: {error}")
            return False
            
        return bool(success)
        
    except Exception as e:
        import traceback
        print(f"❌ Exception in make_phone_call:")
        print(f"   {str(e)}")
        print("   Traceback:")
        print(traceback.format_exc())
        return False



### routes

# incidents

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
async def acknowledge_incident(incident_id: str, token = Depends(verify_token)):
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
async def list_incidents(token = Depends(verify_token)):
    return incidents

@app.get("/incidents/{incident_id}")
async def get_incident(incident_id: str, token = Depends(verify_token)):
    if incident_id not in incidents:
        raise HTTPException(
            status_code=404, 
            detail=f"Incident {incident_id} not found"
        )
    return incidents[incident_id]

# escalations

@app.get("/api/escalations")
async def get_escalations(token = Depends(verify_token)):
    with open('escalations.json') as f:
        return json.load(f)

@app.post("/api/escalations")
async def save_escalations(escalations: dict, token = Depends(verify_token)):
    with open('escalations.json', 'w') as f:
        json.dump(escalations, f, indent=4)
    return {"message": "Escalations saved successfully"}

# contacts

@app.get("/api/contacts")
async def get_contacts(token = Depends(verify_token)):
    with open('contacts.json') as f:
        return json.load(f)
    
@app.post("/api/contacts")
async def create_contact(contact: dict, token = Depends(verify_token)):
    with open('contacts.json', 'r+') as f:
        data = json.load(f)
        contact_id = f"contact_{len(data['contacts']) + 1}"
        data['contacts'][contact_id] = contact
        f.seek(0)
        json.dump(data, f, indent=4)
        f.truncate()
    return {"id": contact_id}

@app.delete("/api/contacts/{contact_id}")
async def delete_contact(contact_id: str, token = Depends(verify_token)):
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
async def update_contact(contact_id: str, contact: dict, token = Depends(verify_token)):
    with open('contacts.json', 'r+') as f:
        data = json.load(f)
        if contact_id in data['contacts']:
            data['contacts'][contact_id] = contact
            f.seek(0)
            json.dump(data, f, indent=4)
            f.truncate()
            return {"message": "Contact updated"}
        raise HTTPException(status_code=404, detail="Contact not found")
    
# suppression
# Add helper functions
def load_suppressions() -> dict:
    """Load suppressions from file"""
    if not SUPPRESSIONS_FILE.exists():
        return {}
    with open(SUPPRESSIONS_FILE) as f:
        return json.load(f)

def save_suppressions(suppressions: dict):
    """Save suppressions to file"""
    with open(SUPPRESSIONS_FILE, 'w') as f:
        json.dump(suppressions, f, indent=2)

@app.get("/api/suppressions")
async def get_suppressions(token = Depends(verify_token)):
    """Get all suppression rules"""
    return load_suppressions()

@app.post("/api/suppressions")
async def create_suppression(rule: SuppressionRule, token = Depends(verify_token)):
    """Create new suppression rule"""
    suppressions = load_suppressions()
    
    # Convert to dict and ensure proper structure
    rule_dict = {
        "id": rule.id,
        "created": rule.created,
        "timeRange": {
            "permanent": rule.timeRange.permanent,
            "start": rule.timeRange.start if not rule.timeRange.permanent else None,
            "end": rule.timeRange.end if not rule.timeRange.permanent else None
        },
        "criteria": [
            {
                "field": c.field,
                "operator": c.operator,
                "value": c.value,
                "booleanOperator": c.booleanOperator
            } for c in rule.criteria
        ]
    }
    
    suppressions[rule.id] = rule_dict
    save_suppressions(suppressions)
    return {"message": "Suppression rule created", "id": rule.id}

@app.delete("/api/suppressions/{rule_id}")
async def delete_suppression(rule_id: str, token = Depends(verify_token)):
    """Delete suppression rule"""
    suppressions = load_suppressions()
    if rule_id in suppressions:
        del suppressions[rule_id]
        save_suppressions(suppressions)
        return {"message": "Suppression rule deleted"}
    raise HTTPException(status_code=404, detail="Rule not found")

@app.get("/api/suppressions/{rule_id}")
async def get_suppression(rule_id: str, token = Depends(verify_token)):
    """Get single suppression rule"""
    suppressions = load_suppressions()
    if rule_id in suppressions:
        return suppressions[rule_id]
    raise HTTPException(status_code=404, detail="Suppression rule not found")

@app.put("/api/suppressions/{rule_id}")
async def update_suppression(rule_id: str, rule: SuppressionRule, token = Depends(verify_token)):
    """Update suppression rule"""
    suppressions = load_suppressions()
    if rule_id in suppressions:
        rule_dict = {
            "id": rule.id,
            "created": rule.created,
            "timeRange": {
                "permanent": rule.timeRange.permanent,
                "start": rule.timeRange.start if not rule.timeRange.permanent else None,
                "end": rule.timeRange.end if not rule.timeRange.permanent else None
            },
            "criteria": [
                {
                    "field": c.field,
                    "operator": c.operator,
                    "value": c.value,
                    "booleanOperator": c.booleanOperator
                } for c in rule.criteria
            ]
        }
        suppressions[rule_id] = rule_dict
        save_suppressions(suppressions)
        return {"message": "Suppression rule updated"}
    raise HTTPException(status_code=404, detail="Rule not found")

# Login endpoint with database dependency
@app.post("/api/login")
async def login(credentials: dict, db: Session = Depends(get_db)):
    username = credentials.get("username")
    password = credentials.get("password")
    
    if verify_auth(username, password):
        token = create_access_token({"sub": username})
        return {"token": token}
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

# Mount static files - simplified to avoid conflicts
app.mount("/", StaticFiles(directory="static", html=True), name="static")
app.mount("/", StaticFiles(directory=".", html=True), name="static")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)