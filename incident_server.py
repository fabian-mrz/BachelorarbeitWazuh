# incident_server.py
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, EmailStr, constr, validator, conint, Field
from datetime import datetime, timedelta
import asyncio
from typing import List, Tuple, Union, Dict, Optional, Literal
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
from database import Base, get_incidents_db, get_users_db, users_engine, incidents_engine
from models import User, IncidentModel
import bcrypt
from logger import logger
from sqlalchemy.orm import Session
from concurrent.futures import ThreadPoolExecutor
from functools import partial
import secrets
import uvicorn
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
import shutil
from utils import add_audit_log, init_db, hash_password, load_escalation_config, load_template, process_template_fields, clean_message_for_phone, load_contacts, save_config, read_config, load_suppressions, save_suppressions, verify_api_key, generate_password, generate_openssl_config
from LinphoneController import LinphoneController
import secrets




app = FastAPI()



# constants
BASE_DIR = './'
# Update constants at top of file
STATIC_DIR = './static/incidents'
TEMPLATES_DIR = './templates'
DEFAULT_TEMPLATE_PATH = os.path.join(TEMPLATES_DIR, 'default.json')
LOGS_DIR = "audit_logs"
CURRENT_LOG_FILE = os.path.join(LOGS_DIR, "current_audit.log")

# Set output directory
OUTPUT_DIR = Path('/var/ossec/integrations')


archived_incidents = {}


#telegram
config = configparser.ConfigParser()
config.read('config.ini')

CHAT_ID = config.get('telegram', 'CHAT_ID', fallback='123456789')
BOT_TOKEN = config.get('telegram', 'BOT_TOKEN', fallback='fake_bot_token')
SIP_USERNAME = config.get('SIP', 'username', fallback='fake_username')
SIP_PASSWORD = config.get('SIP', 'password', fallback='fake_password')
SIP_HOST = config.get('SIP', 'host', fallback='sip.example.com')

#email
SMTP_SERVER = config.get('SMTP', 'server', fallback='smtp.example.com')
SMTP_PORT = int(config.get('SMTP', 'port', fallback=587))  
SMTP_USER = config.get('SMTP', 'username', fallback='user@example.com')
SMTP_PASS = config.get('SMTP', 'password', fallback='fake_password')
SMTP_FROM = config.get('SMTP', 'from', fallback='noreply@example.com')

#tls
SERVER_HOST = config.get('Server', 'host', fallback='0.0.0.0')
SERVER_PORT = int(config.get('Server', 'port', fallback=8334))

SSL_KEYFILE = config.get('SSL', 'keyfile', fallback='key.pem')
SSL_CERTFILE = config.get('SSL', 'certfile', fallback='cert.pem')


#phone controller
phone_controller = LinphoneController(
    sip_server=SIP_HOST,
    username=SIP_USERNAME, 
    password=SIP_PASSWORD
)


class Incident(BaseModel):
    id: str
    title: str
    description: Union[str, Dict]
    severity: str = "medium"
    source: str = "wazuh"
    acknowledged: bool = False
    acknowledged_by: Optional[str] = None
    escalated: bool = False
    created_at: datetime = Field(default_factory=datetime.now)
    archived: bool = False
    archived_at: Optional[datetime] = None
    archived_by: Optional[str] = None
    update_count: int = 0

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

class ContactCreate(BaseModel):
    name: str
    email: str
    phone: str | None = None
    department: str | None = None
    role: str = "analyst"

class PasswordChangeRequest(BaseModel):
    old_password: str
    new_password: str

class UserResponse(BaseModel):
    id: int
    username: str
    role: str 

class PasswordResetRequest(BaseModel):
    new_password: str

class Phase(BaseModel):
    type: Literal["email", "phone"]
    contacts: List[EmailStr]
    delay: conint(ge=0)  # Ensure non-negative delay

class EscalationRule(BaseModel):
    phases: List[Phase]

    @validator('phases')
    def validate_phases(cls, phases):
        if not phases:
            raise ValueError("At least one phase required")
        return phases

class EscalationConfig(BaseModel):
    default: EscalationRule
    rules: Dict[str, EscalationRule]

    @validator('rules')
    def validate_rule_ids(cls, rules):
        for rule_id in rules.keys():
            if not rule_id.isdigit():
                raise ValueError(f"Rule ID must be numeric: {rule_id}")
        return rules


#notification
async def send_notifications(incident_id: str, db: Session):
    try:
        incident = db.query(IncidentModel).filter(
            IncidentModel.id == incident_id
        ).first()
        
        if not incident:
            raise ValueError(f"Incident {incident_id} not found")
            
        # Ensure proper JSON handling
        if isinstance(incident.description, str):
            incident_data = json.loads(incident.description)
        elif isinstance(incident.description, dict):
            incident_data = incident.description
        else:
            raise ValueError(f"Invalid description type: {type(incident.description)}")
            
        rule_id = incident_data['rule_id']
        csv_filename = incident_data.get('csv_path')
        csv_path = "./static" + csv_filename if csv_filename else None
        
        # Load configurations
        template_data = load_template(rule_id)
        escalation = await load_escalation_config(rule_id)
        contacts = load_contacts()
        
        # Process template with validated data
        processed_fields = process_template_fields(template_data, incident_data)
        message = template_data['template'].format(**processed_fields)

        # Do the same for phone message, which should replace newlines with dots and remove special characters
        phone_message = clean_message_for_phone(message)

        #Telegram
        if config['telegram'].get('enabled', 'False').lower() == 'true':
            try:
                await send_telegram_notification(message, csv_path)
            except Exception as e:
                logger.error(f"Error sending Telegram notification: {e}")

        # Immediate notifications email
        for email in escalation['phases'][0]['contacts']:
            contact = next((c for c in contacts.values() if c['email'] == email), None)
            print(contact)
            if not contact:
                logger.error(f"Contact not found for email: {email}")
                continue
            
            # Send email if enabled
            if config['SMTP'].get('enabled', 'False').lower() == 'true':
                try:
                    await send_email_notification(contact, message, csv_path)
                except Exception as e:
                    logger.error(f"Error sending email to {email}: {e}")

        # Handle phone calls
        for phase in escalation['phases']:
            if incident.acknowledged:
                return
                
            if phase['type'] == 'phone' and config['SIP'].get('enabled', 'False').lower() == 'true':
                if phase['delay'] > 0:
                    await asyncio.sleep(phase['delay'] * 60)
                
                if incident.acknowledged:
                    return
                
                for email in phase['contacts']:
                    contact = next((c for c in contacts.values() if c['email'] == email), None)
                    if not contact or not contact.get('phone'):
                        logger.error(f"No valid phone number for contact: {email}")
                        continue
                        

                    try:
                        logger.info(f"📞 Calling {contact['name']} ({contact['phone']})")
                        ack = await make_phone_call(contact, f"Security Alert. Please press 4 to acknowledge or 5 to skip. {phone_message}")
                        if ack:
                            # Refresh incident from DB
                            incident = db.query(IncidentModel).filter(IncidentModel.id == incident.id).first()
                            if incident:
                                logger.info(f"Updating incident {incident.id} - Acknowledged by {contact['name']}")
                                incident.acknowledged = True
                                incident.acknowledged_by = contact['email']
                                db.commit()
                                logger.info(f"✅ Incident {incident.id} successfully acknowledged")
                                add_audit_log("Incident Acknowledged by Phone Call", contact['name'])
                                return
                            else:
                                logger.error(f"❌ Incident not found in DB for update")
                                raise Exception("Incident not found")
                        else:
                            add_audit_log("Escalating further. Incident Not Acknowledged by Phone Call", contact['name'])
                            continue
                    except Exception as e:
                        logger.error(f"Error making phone call to {contact['name']}: {e}")
                        db.rollback()  # Rollback on error
                        continue

    except Exception as e:
        logger.error(f"Error in notification process: {e}")
        db.rollback()

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
        logger.info(f"✉️ Email sent to {contact['name']} ({contact['email']}) with attachment")
    except Exception as e:
        logger.error(f"Error sending email to {contact['email']}: {e}")

# telegram notification
async def send_telegram_notification(message: str, csv_path: str = None):
    """Send notification via Telegram"""
    try:
        bot = telegram.Bot(token=config['telegram']['BOT_TOKEN'])
        chat_id = config['telegram']['CHAT_ID']
        
        # Send message
        await bot.send_message(
            chat_id=chat_id,
            text=message,
            parse_mode='Markdown'
        )
        
        # Send CSV if exists
        if csv_path and os.path.exists(csv_path):
            with open(csv_path, 'rb') as doc:
                await bot.send_document(
                    chat_id=chat_id,
                    document=doc
                )
                
    except Exception as e:
        logger.error(f"Telegram notification error: {e}")
        raise

async def update_incident(incident_id: str, new_data: dict) -> None:
    try:
        incident = incidents[incident_id]
        old_data = json.loads(incident.description)
        
        logger.info(f"Old data: {old_data}")
        logger.info(f"New data: {new_data}")
        
        # Update event counts and timestamps
        new_data['total_events'] = old_data.get('total_events', 0) + new_data.get('total_events', 0)
        
        # Keep earliest first_event_timestamp
        if 'first_event_timestamp' in old_data:
            old_first = datetime.fromisoformat(old_data['first_event_timestamp'])
            new_first = datetime.fromisoformat(new_data['first_event_timestamp'])
            new_data['first_event_timestamp'] = min(old_first, new_first).isoformat()
            
        incident.description = json.dumps(new_data)
        incident.update_count += 1
        
        logger.info(f"✏️ Incident {incident_id} updated (update #{incident.update_count})")
        return incident_id
        
    except Exception as e:
        logger.error(f"Error in update_incident: {e}")
        raise

# Create thread pool executor for phone call
thread_pool = ThreadPoolExecutor(max_workers=4)

async def make_phone_call(contact: dict, message: str) -> bool:
    """Make phone call and return if acknowledged"""
    try:
        logger.info(f"📞 Starting call to {contact['name']}")
        logger.info(f"   Phone: {contact['phone']}")
        logger.info(f"   Message length: {len(message)} chars")
        
        if not contact.get('phone'):
            logger.error("❌ Invalid phone number in contact")
            return False
            
        logger.info(f"   SIP Server: {phone_controller.sip_server}")
        logger.info(f"   SIP Username: {phone_controller.username}")
        logger.info(f"   Process active: {phone_controller.process is not None}")
        
        # Run blocking call in thread pool
        loop = asyncio.get_running_loop()
        make_call_func = partial(
            phone_controller.make_call,
            number=contact['phone'],
            message=message,
            timeout=90
        )
        
        # Execute call with timeout
        try:
            dtmf, success, error = await asyncio.wait_for(
                loop.run_in_executor(thread_pool, make_call_func),
                timeout=LinphoneController._get_wav_duration("output.wav") * 2 + 20
            )
        except asyncio.TimeoutError:
            logger.error(f"❌ Call timed out for {contact['name']}")
            add_audit_log("Contact did not pick up Phone Call", contact['name'])
            return False
            
        logger.info(f"   Call completed:")
        logger.info(f"   - DTMF received: {dtmf}")
        logger.info(f"   - Success: {success}")
        logger.info(f"   - Error: {error}")
        
        if error:
            logger.error(f"❌ Call failed for {contact['name']}: {error}")
            return False
            
        return bool(success)
        
    except Exception as e:
        logger.error(f"❌ Exception in make_phone_call: {e}")
        return False


### routes



@app.post("/incidents/")
async def create_incident(
    incident: Incident,
    db: Session = Depends(get_incidents_db),
    api_key: str = Depends(verify_api_key)
):
    try:
        # Parse description
        if isinstance(incident.description, str):
            incident_data = json.loads(incident.description)
        else:
            incident_data = incident.description
            
        rule_id = incident_data['rule_id']
        
        # Check for any existing incidents with this rule_id
        existing = db.query(IncidentModel).filter(
            IncidentModel.description.like(f'%"rule_id": "{rule_id}"%')
        ).all()
        
        active_incident = next((inc for inc in existing if not inc.archived), None)
        
        if active_incident:
            # Update existing active incident
            active_incident.update_count += 1
            active_incident.description = incident_data
            
            if not active_incident.acknowledged:
                active_incident.acknowledged = incident.acknowledged
                active_incident.acknowledged_by = incident.acknowledged_by
            if not active_incident.escalated:
                active_incident.escalated = incident.escalated
            
            db.commit()
            return {"message": "Incident updated", "id": active_incident.id}
        
        # Create new incident with generated ID if only archived exists
        new_id = incident.id
        if any(inc.id == incident.id for inc in existing):
            timestamp = int(time.time())
            new_id = f"{incident.id}_{timestamp}"
            
        db_incident = IncidentModel(
            id=new_id,
            title=incident.title,
            description=incident_data,
            severity=incident.severity,
            source=incident.source,
            acknowledged=incident.acknowledged,
            acknowledged_by=incident.acknowledged_by,
            escalated=incident.escalated,
            created_at=incident.created_at,
            archived=False,
            archived_at=None,
            archived_by=None,
            update_count=0
        )
        
        db.add(db_incident)
        db.commit()
        
        asyncio.create_task(send_notifications(new_id, db))
        return {"message": "Incident created", "id": new_id}
        
    except Exception as e:
        db.rollback()
        logger.error(f"Error creating incident: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    

@app.post("/incidents/{incident_id}/acknowledge")
async def acknowledge_incident(
    incident_id: str, 
    token = Depends(verify_token),
    db: Session = Depends(get_incidents_db)
):
    try:
        incident = db.query(IncidentModel).filter(
            IncidentModel.id == incident_id
        ).first()
        
        if not incident:
            raise HTTPException(
                status_code=404, 
                detail=f"Incident {incident_id} not found"
            )
        
        if incident.escalated:
            return {"message": "Incident already escalated"}
            
        # Update incident
        incident.acknowledged = True
        incident.acknowledged_by = token["sub"]
        
        db.commit()
        
        # Audit log
        add_audit_log(
            "Acknowledge Incident", 
            token["sub"], 
            f"Incident ID: {incident_id}"
        )
        
        print(f"✅ Incident {incident_id} acknowledged by {incident.acknowledged_by}")
        
        return {
            "message": f"Incident acknowledged by {incident.acknowledged_by}"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        print(f"Error acknowledging incident: {e}")
        raise HTTPException(
            status_code=500, 
            detail="Error acknowledging incident"
        )

@app.get("/incidents/")
async def list_incidents(
    db: Session = Depends(get_incidents_db),
    token = Depends(verify_token)
):
    try:
        incidents = db.query(IncidentModel).filter(
            IncidentModel.archived == False
        ).all()
        
        # Convert SQLAlchemy objects to dict for JSON serialization
        return [
            {
                "id": incident.id,
                "title": incident.title,
                "description": incident.description,
                "severity": incident.severity,
                "source": incident.source,
                "acknowledged": incident.acknowledged,
                "acknowledged_by": incident.acknowledged_by,
                "escalated": incident.escalated,
                "created_at": incident.created_at,
                "archived": incident.archived,
                "archived_at": incident.archived_at,
                "archived_by": incident.archived_by,
                "update_count": incident.update_count
            }
            for incident in incidents
        ]
    except Exception as e:
        print(f"Error fetching incidents: {e}")
        raise HTTPException(status_code=500, detail="Error fetching incidents")

@app.get("/incidents/{incident_id}")
async def get_incident(
    incident_id: str, 
    token = Depends(verify_token),
    db: Session = Depends(get_incidents_db)
):
    try:
        incident = db.query(IncidentModel).filter(
            IncidentModel.id == incident_id
        ).first()
        
        if not incident:
            raise HTTPException(
                status_code=404,
                detail=f"Incident {incident_id} not found"
            )
            
        add_audit_log("Get Incident", token["sub"], f"Incident ID: {incident_id}")
        
        return {
            "id": incident.id,
            "title": incident.title,
            "description": incident.description,
            "severity": incident.severity,
            "source": incident.source,
            "acknowledged": incident.acknowledged,
            "acknowledged_by": incident.acknowledged_by,
            "escalated": incident.escalated,
            "created_at": incident.created_at,
            "archived": incident.archived,
            "archived_at": incident.archived_at,
            "archived_by": incident.archived_by,
            "update_count": incident.update_count
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error fetching incident: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


#audit log
#audit log
@app.get("/api/audit-logs")
async def get_audit_logs(token = Depends(is_admin)):
    try:
        # Debug token
        logger.debug(f"Received token: {token}")
        
        # Check if user is properly authenticated
        if not token:
            logger.error("No token provided or invalid token")
            raise HTTPException(status_code=401, detail="Authentication required")

        logs = []
        # Verify file path
        logger.debug(f"Checking log file at: {CURRENT_LOG_FILE}")
        if not os.path.exists(CURRENT_LOG_FILE):
            logger.error(f"Log file not found at {CURRENT_LOG_FILE}")
            return []
            
        try:
            with open(CURRENT_LOG_FILE, 'r') as f:
                for line_number, line in enumerate(f, 1):
                    try:
                        log_entry = json.loads(line)
                        logs.append(log_entry)
                    except json.JSONDecodeError as je:
                        logger.error(f"Invalid JSON at line {line_number}: {line.strip()}")
                        continue
                        
        except PermissionError:
            logger.error(f"Permission denied reading {CURRENT_LOG_FILE}")
            raise HTTPException(status_code=500, detail="Permission error reading logs")
            
        return logs[-100:]  # Return last 100 logs
        
    except HTTPException as he:
        logger.error(f"HTTP Exception in audit logs: {str(he)}")
        raise he
    except Exception as e:
        logger.error(f"Error fetching audit logs: {str(e)}")
        logger.exception("Full traceback:")
        raise HTTPException(status_code=500, detail=f"Error fetching audit logs: {str(e)}")

@app.get("/api/audit-logs/download")
async def download_audit_logs(token = Depends(verify_token)):
    try:
        file_path = Path(CURRENT_LOG_FILE)
        
        if not file_path.exists():
            raise HTTPException(status_code=404, detail="No audit logs found")
            
        filename = f"audit_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        username = token["sub"].split('@')[0] if '@' in token["sub"] else token["sub"]
        
        add_audit_log("Download Audit Logs", username, f"Downloaded {filename}")
        
        return FileResponse(
            path=file_path,
            filename=filename,
            media_type='text/plain'
        )
        
    except Exception as e:
        logger.error(f"Audit log download error: {str(e)}")
        raise HTTPException(status_code=500, detail="Error downloading audit logs")

@app.post("/api/audit-logs/clear")
async def clear_audit_logs(token = Depends(verify_token)):
    try:
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
    except Exception as e:
        logger.error(f"Error clearing audit logs: {str(e)}")
        raise HTTPException(status_code=500, detail="Error clearing audit logs")

#archive 
@app.get("/incidents/archived/")
async def list_archived_incidents(
    token = Depends(verify_token),
    db: Session = Depends(get_incidents_db)
):
    try:
        archived = db.query(IncidentModel).filter(
            IncidentModel.archived == True
        ).all()
        
        add_audit_log("List Archived Incidents", token["sub"])
        
        return [
            {
                "id": incident.id,
                "title": incident.title,
                "description": incident.description,
                "severity": incident.severity,
                "source": incident.source,
                "acknowledged": incident.acknowledged,
                "acknowledged_by": incident.acknowledged_by,
                "escalated": incident.escalated,
                "created_at": incident.created_at,
                "archived": incident.archived,
                "archived_at": incident.archived_at,
                "archived_by": incident.archived_by,
                "update_count": incident.update_count
            }
            for incident in archived
        ]
    except Exception as e:
        print(f"Error listing archived incidents: {e}")
        raise HTTPException(status_code=500, detail="Error listing archived incidents")

@app.post("/incidents/{incident_id}/archive")
async def archive_incident(
    incident_id: str, 
    token = Depends(verify_token),
    db: Session = Depends(get_incidents_db)
):
    try:
        incident = db.query(IncidentModel).filter(
            IncidentModel.id == incident_id
        ).first()
        
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")
        
        incident.archived = True
        incident.archived_at = datetime.now()
        incident.archived_by = token["sub"]
        
        db.commit()
        
        print(f"📦 Incident {incident_id} archived by {incident.archived_by}")
        add_audit_log("Archive Incident", token["sub"], f"Incident ID: {incident_id}")
        
        return {"message": f"Incident archived by {incident.archived_by}"}
        
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        print(f"Error archiving incident: {e}")
        raise HTTPException(status_code=500, detail="Error archiving incident")

@app.delete("/incidents/archived/{incident_id}")
async def delete_archived_incident(
    incident_id: str,
    token = Depends(verify_token),
    db: Session = Depends(get_incidents_db)
):
    try:
        incident = db.query(IncidentModel).filter(
            IncidentModel.id == incident_id,
            IncidentModel.archived == True
        ).first()
        
        if not incident:
            raise HTTPException(status_code=404, detail="Archived incident not found")
            
        db.delete(incident)
        db.commit()
        
        print(f"🗑️ Archived incident {incident_id} deleted by {token['sub']}")
        add_audit_log("Delete Archived Incident", token["sub"], f"Incident ID: {incident_id}")
        
        return {"message": f"Archived incident {incident_id} deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        print(f"Error deleting archived incident: {e}")
        raise HTTPException(status_code=500, detail="Error deleting archived incident")

@app.delete("/incidents/archived/")
async def delete_all_archived_incidents(
    token = Depends(verify_token),
    db: Session = Depends(get_incidents_db)
):
    try:
        deleted_count = db.query(IncidentModel).filter(
            IncidentModel.archived == True
        ).delete()
        
        if deleted_count == 0:
            return {"message": "No archived incidents to delete"}
            
        db.commit()
        
        print(f"🗑️ All archived incidents deleted by {token['sub']}")
        add_audit_log("Delete All Archived Incidents", token["sub"], f"Deleted {deleted_count} incidents")
        
        return {"message": f"Successfully deleted {deleted_count} archived incidents"}
        
    except Exception as e:
        db.rollback()
        print(f"Error deleting all archived incidents: {e}")
        raise HTTPException(status_code=500, detail="Error deleting all archived incidents")


# escalations
@app.get("/api/escalations")
async def get_escalations(token = Depends(verify_token)):
    try:
        with open('escalations.json') as f:
            return json.load(f)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Escalations file not found")
    except json.JSONDecodeError:
        raise HTTPException(status_code=500, detail="Error decoding escalations file")
    except Exception as e:
        logger.error(f"Error fetching escalations: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/api/escalations")
async def save_escalations(escalations: dict, token = Depends(verify_token)):
    try:
        add_audit_log("Save Escalations", token["sub"])
        with open('escalations.json', 'w') as f:
            json.dump(escalations, f, indent=4)
        return {"message": "Escalations saved successfully"}
    except Exception as e:
        logger.error(f"Error saving escalations: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")

# contacts
@app.get("/api/contacts")
async def get_contacts(db: Session = Depends(get_users_db), token = Depends(verify_token)):
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
async def create_contact(
    contact: ContactCreate,
    db: Session = Depends(get_users_db),
    token = Depends(is_admin)
):
    try:
        logger.info(f"Attempting to create contact: {contact.model_dump()}")
        
        existing_query = db.query(User).filter(
            (User.email == contact.email) | 
            (User.username == contact.email)
        )
        existing = existing_query.first()
        if existing:
            raise HTTPException(
                status_code=409,
                detail=f"User with email {contact.email} already exists"
            )
    
        temp_password = secrets.token_urlsafe(12)
        if not temp_password:
            raise ValueError("Failed to generate password")
            
        hashed = bcrypt.hashpw(temp_password.encode(), bcrypt.gensalt()).decode()
        
        user = User(
            username=contact.email,
            name=contact.name,
            email=contact.email,
            phone=contact.phone,
            department=contact.department,
            role=contact.role,
            password_hash=hashed
        )
        
        db.add(user)
        db.commit()
        db.refresh(user)
        
        logger.info(f"Created new user: {user.email}")
        
        await send_email_notification(
            contact={"email": user.email, "name": user.name},
            message=f"Your temporary password is: {temp_password}"
        )
        
        # Fix: Access token subject properly
        username = token.username if hasattr(token, 'username') else str(token)
        add_audit_log("Create Contact", username, f"Created contact: {user.email}")
        
        return {"id": user.id, "message": "Contact created successfully"}
            
    except Exception as e:
        db.rollback()
        logger.error(f"Error creating contact: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))




@app.delete("/api/contacts/{contact_id}")
async def delete_contact(contact_id: str, db: Session = Depends(get_users_db), token = Depends(is_admin)):
    try:
        user_id = int(contact_id.replace("contact_", ""))
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="Contact not found")
        db.delete(user)
        db.commit()
        add_audit_log("Delete Contact", token.username, f"Deleted contact: {user.email}")
        return {"message": "Contact deleted"}
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid contact ID")
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/api/contacts/{contact_id}")
async def update_contact(contact_id: str, contact: dict, db: Session = Depends(get_users_db), token = Depends(is_admin)):
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
        add_audit_log("Update Contact", token.username, f"Updated contact: {user.email}")
        return {"message": "Contact updated"}
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid contact ID")
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/users", response_model=List[UserResponse])
async def get_users(admin_user: User = Depends(is_admin)):
    try:
        db = next(get_users_db())
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
    


# Change pw
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(
        plain_password.encode(), 
        hashed_password.encode()
    )

@app.post("/api/change-password")
async def change_password(
    request: PasswordChangeRequest,
    db: Session = Depends(get_users_db),
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
        add_audit_log("Change Password by", user.username)
        return {"message": "Password updated successfully"}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

#admin reset
@app.put("/api/admin/reset-password/{user_id}")
async def admin_reset_password(
    user_id: int,
    request: PasswordResetRequest,
    db: Session = Depends(get_users_db),
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
    
# suppression
# Add helper functions

@app.get("/api/suppressions")
async def get_suppressions(token = Depends(verify_token)):
    """Get all suppression rules"""
    try:
        return load_suppressions()
    except Exception as e:
        logger.error(f"Error loading suppressions: {str(e)}")
        raise HTTPException(status_code=500, detail="Error loading suppressions")

@app.post("/api/suppressions")
async def create_suppression(rule: SuppressionRule, token = Depends(verify_token)):
    """Create new suppression rule"""
    try:
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
    except Exception as e:
        logger.error(f"Error creating suppression rule: {str(e)}")
        raise HTTPException(status_code=500, detail="Error creating suppression rule")

@app.delete("/api/suppressions/{rule_id}")
async def delete_suppression(rule_id: str, token = Depends(verify_token)):
    """Delete suppression rule"""
    try:
        suppressions = load_suppressions()
        if rule_id in suppressions:
            del suppressions[rule_id]
            save_suppressions(suppressions)
            add_audit_log("Delete Suppression Rule", token["sub"], f"Deleted suppression rule: {rule_id}")
            return {"message": "Suppression rule deleted"}
        raise HTTPException(status_code=404, detail="Rule not found")
    except Exception as e:
        logger.error(f"Error deleting suppression rule: {str(e)}")
        raise HTTPException(status_code=500, detail="Error deleting suppression rule")

@app.get("/api/suppressions/{rule_id}")
async def get_suppression(rule_id: str, token = Depends(verify_token)):
    """Get single suppression rule"""
    try:
        suppressions = load_suppressions()
        if rule_id in suppressions:
            return suppressions[rule_id]
        raise HTTPException(status_code=404, detail="Suppression rule not found")
    except Exception as e:
        logger.error(f"Error getting suppression rule: {str(e)}")
        raise HTTPException(status_code=500, detail="Error getting suppression rule")

@app.put("/api/suppressions/{rule_id}")
async def update_suppression(rule_id: str, rule: SuppressionRule, token = Depends(verify_token)):
    """Update suppression rule"""
    try:
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
    except Exception as e:
        logger.error(f"Error updating suppression rule: {str(e)}")
        raise HTTPException(status_code=500, detail="Error updating suppression rule")

# Login endpoint
@app.post("/api/login")
async def login(credentials: dict, db: Session = Depends(get_users_db)):
    try:
        username = credentials.get("username")
        password = credentials.get("password")
        
        if not username or not password:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username and password are required"
            )
        
        if verify_auth(username, password):
            token = create_access_token({"sub": username})
            add_audit_log("User logged in", username)
            return {"token": token}
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Error during login: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

### settings.html


@app.get("/settings")
async def get_settings(admin_user = Depends(is_admin)):
    """Get all settings from config.ini"""
    return read_config()

@app.post("/settings")
async def update_settings(settings: Dict, admin_user = Depends(is_admin)):
    """Update settings in config.ini"""
    logger.info(f"Received settings update: {settings}")
    
    try:
        # Validate settings
        if not isinstance(settings, dict):
            raise ValueError("Settings must be a dictionary")
            
        # Debug print
        print(f"Attempting to save settings: {settings}")
        
        save_config(settings)
        logger.info("Settings saved successfully")
        add_audit_log("Update Settings", admin_user.username, "Updated settings")
        return {"message": "Settings updated successfully"}
        
    except Exception as e:
        logger.error(f"Error updating settings: {str(e)}")
        logger.exception("Full traceback:")
        raise HTTPException(status_code=500, detail=f"Failed to update settings: {str(e)}")
    
@app.get("/isadmin")
async def check_admin(admin_user = Depends(is_admin)):
    return {"is_admin": True}    

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
async def save_template(
    template_name: str, 
    template: dict, 
    admin_user: User = Depends(is_admin)
):
    try:
        add_audit_log("Save Template", admin_user.username, f"Saved template: {template_name}")
        with open(f"{TEMPLATES_DIR}/{template_name}", 'w') as f:
            json.dump(template, f, indent=2)
        return {"message": "Template saved"}
    except Exception as e:
        logger.error(f"Error saving template {template_name}: {str(e)}")
        raise HTTPException(status_code=500, detail="Error saving template")

@app.delete("/templates/{template_name}")
async def delete_template(
    template_name: str, 
    admin_user: User = Depends(is_admin)
):
    try:
        os.remove(f"{TEMPLATES_DIR}/{template_name}")
        add_audit_log("Delete Template", admin_user.username, f"Deleted template: {template_name}")
        return {"message": "Template deleted"}
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Template not found")
    


#certificates
#download
@app.get("/api/certificate/download/{file_type}")
async def download_certificate(file_type: str, admin_user: User = Depends(is_admin)):
    try:
        if file_type not in ['cert', 'key']:
            raise HTTPException(status_code=400, detail="Invalid file type")
            
        filename = 'cert.pem' if file_type == 'cert' else 'key.pem'
        file_path = Path(filename)
        
        if not file_path.exists():
            raise HTTPException(status_code=404, detail="Certificate file not found")
            
        add_audit_log("Download Certificate", admin_user.username, f"Downloaded {filename}")
        
        return FileResponse(
            path=file_path,
            filename=filename,
            media_type='application/x-pem-file'
        )
        
    except Exception as e:
        logger.error(f"Certificate download error: {str(e)}")
        raise HTTPException(status_code=500, detail="Error downloading certificate")

#generate
@app.post("/api/certificate/generate")
async def generate_certificate(cert_data: dict, admin_user: User = Depends(is_admin)):
    try:
        # Create backup of existing certificates if they exist
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        for file in ['cert.pem', 'key.pem']:
            if os.path.exists(file):
                backup_file = f"{file}.{timestamp}.backup"
                shutil.copy2(file, backup_file)
                logger.info(f"Created backup: {backup_file}")
        
        # Generate OpenSSL config file
        config_content = generate_openssl_config(cert_data)
        config_file = "openssl.cnf"
        with open(config_file, "w") as f:
            f.write(config_content)
        
        # Generate new certificates using config file
        cmd = [
            'openssl', 'req', '-x509', '-newkey', 'rsa:4096', '-nodes',
            '-out', 'cert.pem', '-keyout', 'key.pem',
            '-days', '365', '-config', config_file
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        # Clean up config file
        os.remove(config_file)
        
        if result.returncode != 0:
            # Restore backups if generation fails
            for file in ['cert.pem', 'key.pem']:
                backup_file = f"{file}.{timestamp}.backup"
                if os.path.exists(backup_file):
                    shutil.copy2(backup_file, file)
            raise Exception(f"OpenSSL error: {result.stderr}")
        
        add_audit_log("Generate Certificate", admin_user.username, 
                     f"Generated new certificate for {cert_data['common_name']} with SANs")
        return {
            "message": "Certificate generated successfully with SANs",
            "backup_created": True,
            "backup_timestamp": timestamp
        }
        
    except Exception as e:
        logger.error(f"Certificate generation error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
    

    
app.add_middleware(HTTPSRedirectMiddleware)

# Mount static files - simplified to avoid conflicts
app.mount("/", StaticFiles(directory="static", html=True), name="static")
app.mount("/", StaticFiles(directory=".", html=True), name="static")

def start_server():
    global server_instance
    config = uvicorn.Config(
        app,
        host=SERVER_HOST,
        port=SERVER_PORT,
        ssl_keyfile=SSL_KEYFILE,
        ssl_certfile=SSL_CERTFILE,
        log_level="info"
    )
    server_instance = uvicorn.Server(config)
    server_instance.run()

if __name__ == "__main__":
    init_db()
    start_server()