# incident_server.py
from fastapi import FastAPI, HTTPException, Depends, Security, status
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
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
import telegram
import subprocess
import time
from pathlib import Path
import threading
import re
from auth import verify_auth, create_access_token, verify_token, is_admin
from database import SessionLocal, Base, engine, get_db
from models import User
import bcrypt
import logging
from sqlalchemy.orm import Session
import uvicorn
from concurrent.futures import ThreadPoolExecutor
from functools import partial
import secrets




# Add to global variables
LOGS_DIR = "audit_logs"
CURRENT_LOG_FILE = os.path.join(LOGS_DIR, "current_audit.log")

# Create logs directory if it doesn't exist
os.makedirs(LOGS_DIR, exist_ok=True)

def add_audit_log(action: str, user: str = None, details: str = None):
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "user": user,
        "action": action,
        "details": details
    }
    
    with open(CURRENT_LOG_FILE, 'a') as f:
        f.write(json.dumps(log_entry) + '\n')



def init_db():
    Base.metadata.create_all(bind=engine)
    
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


app = FastAPI()

#Phone controller
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
            time.sleep(3)  # Wait for setup
            
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

# constants
BASE_DIR = './'
# Update constants at top of file
STATIC_DIR = './static/incidents'
TEMPLATES_DIR = './templates'
DEFAULT_TEMPLATE_PATH = os.path.join(TEMPLATES_DIR, 'default.json')
# Set output directory
OUTPUT_DIR = Path('/var/ossec/integrations')
SUPPRESSIONS_FILE = Path("suppressions.json")

archived_incidents = {}


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
    title: Optional[str] = None
    description: str
    severity: Optional[int] = None
    source: Optional[str] = None
    acknowledged: bool = False
    acknowledged_by: Optional[str] = None
    escalated: bool = False
    created_at: datetime = Field(default_factory=datetime.now)
    archived: bool = False
    archived_at: Optional[datetime] = None
    archived_by: Optional[str] = None
    update_count: int = 0  # Add update counter

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


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


# Remove, esalation is already handling this
async def handle_incident_timer(incident_id: str):
    await asyncio.sleep(60)
    if not incidents[incident_id].acknowledged:
        incidents[incident_id].escalated = True
        add_audit_log(f"⚠️ Incident {incident_id} not acknowledged within 60 seconds - escalating!")

async def load_escalation_config(rule_id: str = None):
    """Load escalation config for specific rule or default"""
    with open('escalations.json') as f:
        escalations = json.load(f)
    
    if rule_id and rule_id in escalations['rules']:
        return escalations['rules'][rule_id]
    return escalations['default']


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


#proccess template fields
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

#notification
async def send_notifications(incident_id: str):
    """Send notifications with attachments using template and escalation config"""
    try:
        incident = incidents[incident_id]
        incident_data = json.loads(incident.description)
        rule_id = incident_data['rule_id']
        csv_filename = incident_data.get('csv_path')
        csv_path = "./static" + csv_filename
        
        # Load configurations
        template_data = load_template(rule_id)
        escalation = await load_escalation_config(rule_id)
        contacts = load_contacts()
        
        # Process template
        processed_fields = process_template_fields(template_data, incident_data)
        message = template_data['template'].format(**processed_fields)

        # Immediate notifications (email and telegram)
        for contact_id in escalation['phases'][0]['contacts']:
            contact = contacts[contact_id]
            
            # Send email if enabled
            if contact['email'] and config['SMTP'].get('enabled', 'False').lower() == 'true':
                try:
                    await send_email_notification(contact, message, csv_path)
                except Exception as e:
                    print(f"Error sending email to {contact['email']}: {e}")

            # Send telegram if enabled    
            if config['telegram'].get('enabled', 'False').lower() == 'true':
                try:
                    await send_telegram_notification(
                        message=message,
                        csv_path=csv_path
                    )
                except Exception as e:
                    print(f"Error in telegram notification: {e}")

        # Handle phone calls
        for phase in escalation['phases']:
            if incidents[incident_id].acknowledged:
                return
                
            if phase['type'] == 'phone' and config['SIP'].get('enabled', 'False').lower() == 'true':
                if phase['delay'] > 0:
                    await asyncio.sleep(phase['delay'] * 60)
                
                if incidents[incident_id].acknowledged:
                    return
                
                for contact_id in phase['contacts']:
                    try:
                        contact = contacts[contact_id]
                        print(f"📞 Calling {contact['name']} ({contact['phone']})")
                        ack = await make_phone_call(contact, f"Security Alert. Please press 4 to acknoledge and 5 to skip. {message}")
                        if ack:
                            incidents[incident_id].acknowledged = True
                            incidents[incident_id].acknowledged_by = contact['name']
                            add_audit_log("Incident Acknowledged by Phone Call", contact['name'])
                        else:
                            add_audit_log("Escalating furhter. Incident Not Acknowledged by Phone Call", contact['name'])
                            return
                    except Exception as e:
                        print(f"Error making phone call: {e}")
                        continue

    except Exception as e:
        print(f"Error in notification process: {e}")

#email notification
async def send_email_notification(contact: dict, message: str, csv_path: str = None):
                    """Send email notification with optional CSV attachment"""
                    try:
                        msg = MIMEMultipart()
                        msg['From'] = SMTP_FROM
                        msg['To'] = contact['email']
                        msg['Subject'] = "Security Alert"
                        msg.attach(MIMEText(message, 'plain'))
                        
                        # Attach CSV if available
                        if csv_path and os.path.exists(csv_path):
                            with open(csv_path, 'rb') as f:
                                part = MIMEApplication(f.read(), Name=os.path.basename(csv_path))
                                part['Content-Disposition'] = f'attachment; filename="{os.path.basename(csv_path)}"'
                                msg.attach(part)
                        
                        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
                        server.starttls()
                        server.login(SMTP_USER, SMTP_PASS)
                        server.send_message(msg)
                        server.quit()
                        print(f"✉️ Email sent to {contact['name']} ({contact['email']}) with attachment")
                    except Exception as e:
                        print(f"Error sending email to {contact['email']}: {e}")

# telegram notification
async def send_telegram_notification(message: str, csv_path: str = None):
    """Send notification via Telegram with markdown formatting"""
    try:
        bot = telegram.Bot(token=config['telegram']['BOT_TOKEN'])
        chat_id = config['telegram']['CHAT_ID']
        
        # Send message with markdown parsing
        await bot.send_message(
            chat_id=chat_id,
            text=message,
            parse_mode='MarkdownV2'
        )
        
        # Send CSV if exists
        if csv_path and os.path.exists(csv_path):
            async with aiofiles.open(csv_path, 'rb') as doc:
                await bot.send_document(chat_id=chat_id, document=doc)
                
    except Exception as e:
        print(f"Telegram notification error: {e}")
        raise


##update incidents
async def find_active_incident(rule_id: str) -> Optional[str]:
    for id, incident in incidents.items():
        incident_data = json.loads(incident.description)
        if (incident_data.get('rule_id') == rule_id and 
            not incident.archived):  # Only check non-archived incidents
            return id
    return None

async def update_incident(incident_id: str, new_data: dict) -> None:
    try:
        incident = incidents[incident_id]
        old_data = json.loads(incident.description)
        
        print(f"Old data: {old_data}")
        print(f"New data: {new_data}")
        
        # Update event counts and timestamps
        new_data['total_events'] = old_data.get('total_events', 0) + new_data.get('total_events', 0)
        
        # Keep earliest first_event_timestamp
        if 'first_event_timestamp' in old_data:
            old_first = datetime.fromisoformat(old_data['first_event_timestamp'])
            new_first = datetime.fromisoformat(new_data['first_event_timestamp'])
            new_data['first_event_timestamp'] = min(old_first, new_first).isoformat()
            
        incident.description = json.dumps(new_data)
        incident.update_count += 1
        
        print(f"✏️ Incident {incident_id} updated (update #{incident.update_count})")
        return incident_id
        
    except Exception as e:
        print(f"Error in update_incident: {e}")
        raise

# Create thread pool executor for phone call
thread_pool = ThreadPoolExecutor(max_workers=4)

async def make_phone_call(contact: dict, message: str) -> bool:
    """Make phone call and return if acknowledged"""
    try:
        print(f"📞 Starting call to {contact['name']}")
        print(f"   Phone: {contact['phone']}")
        print(f"   Message length: {len(message)} chars")
        
        if not contact.get('phone'):
            print("❌ Invalid phone number in contact")
            return False
            
        print(f"   SIP Server: {phone_controller.sip_server}")
        print(f"   SIP Username: {phone_controller.username}")
        print(f"   Process active: {phone_controller.process is not None}")
        
        # Run blocking call in thread pool
        loop = asyncio.get_running_loop()
        make_call_func = partial(
            phone_controller.make_call,
            number=contact['phone'],
            message=message,
            timeout=60
        )
        
        # Execute call with timeout
        try:
            dtmf, success, error = await asyncio.wait_for(
                loop.run_in_executor(thread_pool, make_call_func),
                timeout=70  # Slightly longer than call timeout
            )
        except asyncio.TimeoutError:
            print(f"❌ Call timed out for {contact['name']}")
            add_audit_log("Contact did not pick up Phone Call", contact['name'])
            return False
            
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
        # Extract username from token and store it
        incident.acknowledged_by = token["sub"]  # token contains username in "sub" field
        add_audit_log("Acknowledge Incident", token["sub"], f"Incident ID: {incident_id}")
        print(f"✅ Incident {incident_id} acknowledged by {incident.acknowledged_by}")
        return {"message": f"Incident acknowledged by {incident.acknowledged_by}"}
    else:
        return {"message": "Incident already escalated"}

@app.get("/incidents/")
async def list_incidents(token = Depends(verify_token)):
    return {id: incident for id, incident in incidents.items() 
            if not incident.archived}

@app.get("/incidents/{incident_id}")
async def get_incident(incident_id: str, token = Depends(verify_token)):
    # Check active incidents first
    if incident_id in incidents:
        add_audit_log("Get Incident", token["sub"], f"Incident ID: {incident_id}")
        return incidents[incident_id]
    
    # Then check archived incidents
    if incident_id in archived_incidents:
        add_audit_log("Get Archived Incident", token["sub"], f"Incident ID: {incident_id}")
        return archived_incidents[incident_id]
        
    raise HTTPException(
        status_code=404, 
        detail=f"Incident {incident_id} not found"
    )


#audit log
@app.get("/api/audit-logs")
async def get_audit_logs(token = Depends(verify_token)):
    logs = []
    if os.path.exists(CURRENT_LOG_FILE):
        with open(CURRENT_LOG_FILE, 'r') as f:
            logs = [json.loads(line) for line in f.readlines()]
    return logs[-100:]  # Return last 100 logs

@app.get("/api/audit-logs/download")
async def download_audit_logs(token = Depends(verify_token)):
    add_audit_log("Download Audit Logs", token["sub"])
    if not os.path.exists(CURRENT_LOG_FILE):
        raise HTTPException(status_code=404, detail="No audit logs found")
    return FileResponse(
        CURRENT_LOG_FILE,
        filename=f"audit_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    )

@app.post("/api/audit-logs/clear")
async def clear_audit_logs(token = Depends(verify_token)):
    if not is_admin(token):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    if os.path.exists(CURRENT_LOG_FILE):
        # Archive current log
        archive_name = f"audit_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        os.rename(CURRENT_LOG_FILE, os.path.join(LOGS_DIR, archive_name))
        
        # Create new empty log file
        open(CURRENT_LOG_FILE, 'w').close()
        
        add_audit_log("Clear Audit Logs", token["sub"], f"Archived as {archive_name}")
        return {"message": "Audit logs cleared and archived"}
    
    return {"message": "No logs to clear"}

#archive 
@app.get("/incidents/archived/")
async def list_archived_incidents(token = Depends(verify_token)):
    return archived_incidents

@app.post("/incidents/{incident_id}/archive")
async def archive_incident(incident_id: str, token = Depends(verify_token)):
    if incident_id not in incidents:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    incident = incidents[incident_id]
    incident.archived = True
    incident.archived_at = datetime.now()
    incident.archived_by = token["sub"]
    
    # Move to archive dictionary
    archived_incidents[incident_id] = incidents.pop(incident_id)
    
    print(f"📦 Incident {incident_id} archived by {incident.archived_by}")
    add_audit_log("Archive Incident", token["sub"], f"Incident ID: {incident_id}")
    return {"message": f"Incident archived by {incident.archived_by}"}



# escalations

@app.get("/api/escalations")
async def get_escalations(token = Depends(verify_token)):
    with open('escalations.json') as f:
        return json.load(f)

@app.post("/api/escalations")
async def save_escalations(escalations: dict, token = Depends(verify_token)):
    add_audit_log("Save Escalations", token["sub"])
    with open('escalations.json', 'w') as f:
        json.dump(escalations, f, indent=4)
    return {"message": "Escalations saved successfully"}

# contacts

def generate_password():
    return secrets.token_urlsafe(12)

# Updated endpoints
@app.get("/api/contacts")
async def get_contacts(db: Session = Depends(get_db), token = Depends(verify_token)):
    try:
        users = db.query(User).all()
        return {
            "contacts": {
                f"contact_{user.id}": {
                    "name": user.name,
                    "email": user.email,
                    "phone": user.phone,
                    "department": user.department,
                    "role": user.role
                } for user in users
            }
        }
    except Exception as e:
        print(f"Error getting contacts: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/contacts")
async def create_contact(contact: dict, db: Session = Depends(get_db), token = Depends(verify_token)):
    try:
        # Debug logging
        add_audit_log("Create Contact by", token["sub"], f"Creating contact: {contact}")
        
        # Generate initial password
        temp_password = generate_password()
        
        # Create user object
        user = User(
            username=contact["email"],
            name=contact["name"],
            email=contact["email"],
            phone=contact.get("phone"),
            department=contact.get("department"),
            role=contact.get("role"),
            password_hash=hash_password(temp_password),
            reset_token=None,
            token_expiry=None
        )
        
        # Database operations
        try:
            db.add(user)
            db.commit()
            db.refresh(user)
        except Exception as db_error:
            db.rollback()
            raise HTTPException(status_code=500, detail=f"Database error: {str(db_error)}")
        
        # Send email
        try:
            msg = MIMEMultipart()
            msg['From'] = SMTP_FROM
            msg['To'] = user.email
            msg['Subject'] = "Your temporary password"
            msg.attach(MIMEText(f"Your temporary password is: {temp_password}", 'plain'))
            
            server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
            server.quit()
            add_audit_log("Email Sent", token["sub"], f"Sent password email to {user.email}")
        except Exception as email_error:
            add_audit_log("Email Error", token["sub"], f"Email error: {str(email_error)}")
            # Don't rollback DB - user is created but email failed
            
        return {"id": f"contact_{user.id}"}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    

# Add password change request model
class PasswordChangeRequest(BaseModel):
    old_password: str
    new_password: str

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(
        plain_password.encode(), 
        hashed_password.encode()
    )

@app.post("/api/change-password")
async def change_password(
    request: PasswordChangeRequest,
    db: Session = Depends(get_db),
    token = Depends(verify_token)
):
    try:
        # Get user from token
        user = db.query(User).filter(User.username == token["sub"]).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
            
        # Verify old password
        if not verify_password(request.old_password, user.password_hash):
            raise HTTPException(status_code=400, detail="Invalid old password")
            
        # Update password
        user.password_hash = hash_password(request.new_password)
        db.commit()
        
        return {"message": "Password updated successfully"}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/contacts/{contact_id}")
async def delete_contact(contact_id: str, db: Session = Depends(get_db), token = Depends(verify_token)):
    try:
        user_id = int(contact_id.replace("contact_", ""))
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="Contact not found")
        db.delete(user)
        db.commit()
        add_audit_log("Delete Contact", token["sub"], f"Deleted contact: {contact_id}")
        return {"message": "Contact deleted"}
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid contact ID")
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/api/contacts/{contact_id}")
async def update_contact(contact_id: str, contact: dict, db: Session = Depends(get_db), token = Depends(verify_token)):
    try:
        user_id = int(contact_id.replace("contact_", ""))
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="Contact not found")
            
        user.username = contact["email"]
        user.name = contact["name"]
        user.email = contact["email"]
        user.phone = contact.get("phone")
        user.department = contact.get("department")
        user.role = contact.get("role")
        user.updated_at = datetime.utcnow()
        
        db.commit()
        add_audit_log("Update Contact", token["sub"], f"Updated contact: {contact_id}")
        return {"message": "Contact updated"}
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid contact ID")
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    
class PasswordResetRequest(BaseModel):
    new_password: str

@app.put("/api/admin/reset-password/{user_id}")
async def admin_reset_password(
    user_id: int,
    request: PasswordResetRequest,
    db: Session = Depends(get_db),
    admin_user: User = Depends(is_admin)
):
    try:
        # Find target user
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
            
        # Update password
        user.password_hash = hash_password(request.new_password)
        db.commit()
        add_audit_log("Admin Password Reset", admin_user.username, f"Reset password for user {user.username}")
        return {"message": f"Password reset successful for user {user.username}"}
        
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

class UserResponse(BaseModel):
    id: int
    username: str
    role: str 

@app.get("/api/users", response_model=List[UserResponse])
async def get_users(admin_user: User = Depends(is_admin)):
    try:
        db = next(get_db())
        users = db.query(User).all()
        return [
            UserResponse(
                id=user.id,
                username=user.username,
                role=user.role
            ) for user in users
        ]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
# suppression
# Add helper functions
def load_suppressions() -> dict:
    """Load suppressions from file"""
    if not SUPPRESSIONS_FILE.exists():
        return {}
    with open(SUPPRESSIONS_FILE) as f:
        return json.load(f)
    

#load contacts from users.db
def load_contacts() -> dict:
    """Load contacts from users.db"""
    db = next(get_db())
    users = db.query(User).all()
    return {
        f"contact_{user.id}": {
            "name": user.name,
            "email": user.email,
            "phone": user.phone,
            "department": user.department,
            "role": user.role
        } for user in users
    }

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
    add_audit_log("Create Suppression Rule", token["sub"], f"Created suppression rule: {rule.id}")
    
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
        add_audit_log("Delete Suppression Rule", token["sub"], f"Deleted suppression rule: {rule_id}")
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
        add_audit_log("Update Suppression Rule", token["sub"], f"Updated suppression rule: {rule_id}")
        return {"message": "Suppression rule updated"}
    raise HTTPException(status_code=404, detail="Rule not found")

# Login endpoint with database dependency
@app.post("/api/login")
async def login(credentials: dict, db: Session = Depends(get_db)):
    username = credentials.get("username")
    password = credentials.get("password")
    
    if verify_auth(username, password):
        token = create_access_token({"sub": username})
        add_audit_log("User logged in", username)
        return {"token": token}
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

### settings.html
# Config handling functions
def read_config() -> Dict:
    try:
        config.read('config.ini')
        return {
            "telegram": {
                "CHAT_ID": str(config['telegram']['CHAT_ID']),
                "BOT_TOKEN": config['telegram']['BOT_TOKEN'],
                "enabled": config['telegram']['enabled']
            },
            "smtp": dict(config['SMTP']),
            "sip": dict(config['SIP'])
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error reading config: {str(e)}")

def save_config(settings: Dict):
    config['telegram'] = {
        'CHAT_ID': settings['telegram']['CHAT_ID'],
        'BOT_TOKEN': settings['telegram']['BOT_TOKEN'],
        'enabled': settings['telegram']['enabled']
    }
    
    config['SMTP'] = {
        'server': settings['smtp']['server'],
        'port': str(settings['smtp']['port']),
        'username': settings['smtp']['username'],
        'password': settings['smtp']['password'],
        'from': settings['smtp']['from'],
        'enabled': settings['smtp']['enabled']
    }
    
    config['SIP'] = {
        'username': settings['sip']['username'],
        'password': settings['sip']['password'],
        'host': settings['sip']['host'],
        'enabled': settings['sip']['enabled']
    }
    
    try:
        with open('config.ini', 'w') as f:
            config.write(f)
            add_audit_log("Config Updated by", token["sub"])
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error saving config: {str(e)}")

#settings
@app.get("/settings")
async def get_settings(admin_user = Depends(is_admin)):
    """Get all settings from config.ini"""
    return read_config()

@app.post("/settings")
async def update_settings(settings: Dict, admin_user = Depends(is_admin)):
    """Update settings in config.ini"""
    try:
        save_config(settings)
        return {"message": "Settings updated successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
#Templates
@app.get('/list_templates')
async def list_templates():
    """List all available notification templates"""
    try:
        templates = []
        for file in os.listdir(TEMPLATES_DIR):
            if file.endswith('.json'):
                templates.append(file)
        return templates
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error listing templates: {str(e)}"
        )

@app.get("/templates/{template_name}")
async def get_template(template_name: str):
    try:
        with open(f"{TEMPLATES_DIR}/{template_name}") as f:
            return json.load(f)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Template not found")

@app.post("/templates/{template_name}")
async def save_template(template_name: str, template: dict):
    add_audit_log("Save Template", token["sub"], f"Saved template: {template_name}")
    with open(f"{TEMPLATES_DIR}/{template_name}", 'w') as f:
        json.dump(template, f, indent=2)
    return {"message": "Template saved"}

@app.delete("/templates/{template_name}")
async def delete_template(template_name: str):
    try:
        os.remove(f"{TEMPLATES_DIR}/{template_name}")
        add_audit_log("Delete Template", token["sub"], f"Deleted template: {template_name}")
        return {"message": "Template deleted"}
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Template not found")
    
@app.get("/isadmin")
async def check_admin(admin_user = Depends(is_admin)):
    return {"is_admin": True}


# Mount static files - simplified to avoid conflicts
app.mount("/", StaticFiles(directory="static", html=True), name="static")
app.mount("/", StaticFiles(directory=".", html=True), name="static")

if __name__ == "__main__":
    init_db()
    uvicorn.run(app, host="localhost", port=8000)