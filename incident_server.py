# incident_server.py
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from datetime import datetime, timedelta
import asyncio
from typing import List, Tuple, Union, Dict, Optional
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
import logging
from sqlalchemy.orm import Session
from concurrent.futures import ThreadPoolExecutor
from functools import partial
import secrets
import uvicorn
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
import shutil
from utils import add_audit_log, init_db, hash_password, load_escalation_config, load_template, process_template_fields, clean_message_for_phone, load_contacts, save_config, read_config, load_suppressions, save_suppressions, verify_api_key 
from LinphoneController import LinphoneController




app = FastAPI()



# constants
BASE_DIR = './'
# Update constants at top of file
STATIC_DIR = './static/incidents'
TEMPLATES_DIR = './templates'
DEFAULT_TEMPLATE_PATH = os.path.join(TEMPLATES_DIR, 'default.json')
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

#tsl
SERVER_HOST = config.get('Server', 'host', fallback='0.0.0.0')
SERVER_PORT = int(config.get('Server', 'port', fallback=8334))

SSL_KEYFILE = config.get('SSL', 'keyfile', fallback='key.pem')
SSL_CERTFILE = config.get('SSL', 'certfile', fallback='cert.pem')

#data 
retention_days = int(config.get('Retention', 'days', fallback=30))


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
            # Check acknowledgment status from db
            incident = db.query(IncidentModel).filter(
                IncidentModel.id == incident_id
            ).first()
            
            if incident.acknowledged:
                return
                
            if phase['type'] == 'phone' and config['SIP'].get('enabled', 'False').lower() == 'true':
                if phase['delay'] > 0:
                    await asyncio.sleep(phase['delay'] * 60)
                
                # Recheck acknowledgment after delay
                incident = db.query(IncidentModel).filter(
                    IncidentModel.id == incident_id
                ).first()
                
                if incident.acknowledged:
                    return
                
                for contact_id in phase['contacts']:
                    try:
                        contact = contacts[contact_id]
                        print(f"📞 Calling {contact['name']} ({contact['phone']})")
                        # Remove special characters and create newline for new info per line
                        ack = await make_phone_call(contact, f"Security Alert. Please press 4 to acknowledge or 5 to skip. {phone_message}")
                        if ack:
                            incident.acknowledged = True
                            incident.acknowledged_by = contact['name']
                            db.commit()
                            add_audit_log("Incident Acknowledged by Phone Call", contact['name'])
                            return
                        else:
                            add_audit_log("Escalating further. Incident Not Acknowledged by Phone Call", contact['name'])
                            continue
                    except Exception as e:
                        print(f"Error making phone call: {e}")
                        continue

    except Exception as e:
        print(f"Error in notification process: {e}")
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
                        print(f"✉️ Email sent to {contact['name']} ({contact['email']}) with attachment")
                    except Exception as e:
                        print(f"Error sending email to {contact['email']}: {e}")

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
        print(f"Telegram notification error: {e}")
        raise




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



@app.post("/incidents/")
async def create_incident(
    incident: Incident,
    db: Session = Depends(get_incidents_db),
    api_key: str = Depends(verify_api_key)  # Add this line
):
    try:
        # Parse description
        if isinstance(incident.description, str):
            incident_data = json.loads(incident.description)
        else:
            incident_data = incident.description
            
        rule_id = incident_data['rule_id']
        
        # Check only for active (non-archived) incidents
        existing = db.query(IncidentModel).filter(
            IncidentModel.description.like(f'%"rule_id": "{rule_id}"%'),
            IncidentModel.archived == False
        ).first()
        
        if existing and not existing.archived:
            existing.update_count += 1
            existing.description = incident_data
            
            if not existing.acknowledged:
                existing.acknowledged = incident.acknowledged
                existing.acknowledged_by = incident.acknowledged_by
            if not existing.escalated:
                existing.escalated = incident.escalated
            
            db.commit()
            return {"message": "Incident updated", "id": existing.id}
            
        # Create new incident
        db_incident = IncidentModel(
            id=incident.id,
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
        
        asyncio.create_task(send_notifications(incident.id, db))
        return {"message": "Incident created", "id": incident.id}
        
    except Exception as e:
        db.rollback()
        print(f"Error creating incident: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    

def get_username_from_email(email: str) -> str:
    """Extract username from email address"""
    return email.split('@')[0] if '@' in email else email

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
        incident.acknowledged_by = get_username_from_email(token["sub"])
        
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
@app.get("/api/audit-logs")
async def get_audit_logs(token = Depends(verify_token)):
    logs = []
    if os.path.exists(CURRENT_LOG_FILE):
        with open(CURRENT_LOG_FILE, 'r') as f:
            logs = [json.loads(line) for line in f.readlines()]
    return logs[-100:]  # Return last 100 logs

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
        logging.error(f"Audit log download error: {str(e)}")
        raise HTTPException(status_code=500, detail="Error downloading audit logs")

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


class ContactCreate(BaseModel):
    name: str
    email: str
    phone: str | None = None
    department: str | None = None
    role: str = "analyst"

def generate_password(length=12):
    import secrets
    import string
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(secrets.choice(alphabet) for _ in range(length))
@app.post("/api/contacts")
async def create_contact(
    contact: ContactCreate,
    db: Session = Depends(get_users_db),
    token = Depends(verify_token)
):
    try:
        # Debug logging with model_dump instead of dict
        print(f"Attempting to create contact: {contact.model_dump()}")
        
        # Debug query for existing user
        existing_query = db.query(User).filter(
            (User.email == contact.email) | 
            (User.username == contact.email)
        )
        print(f"Checking for existing user with query: {str(existing_query)}")
        
        existing = existing_query.first()
        if existing:
            print(f"Found existing user:")
            print(f"  ID: {existing.id}")
            print(f"  Email: {existing.email}")
            print(f"  Username: {existing.username}")
            print(f"  Created at: {existing.created_at}")
            
            raise HTTPException(
                status_code=409,
                detail=f"User with email {contact.email} already exists"
            )
    
        # Create new user
        try:
            temp_password = generate_password()
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
            
            print(f"Created new user:")
            print(f"  ID: {user.id}")
            print(f"  Email: {user.email}")
            
            # Send email and log
            await send_email_notification(
                contact={"email": user.email, "name": user.name},
                message=f"Your temporary password is: {temp_password}"
            )
            add_audit_log("Create Contact", token["sub"], f"Created contact: {user.email}")
            
            return {"id": user.id, "message": "Contact created successfully"}
            
        except Exception as e:
            db.rollback()
            print(f"Database error: {str(e)}")
            raise HTTPException(status_code=500, detail=str(e))
            
    except HTTPException as he:
        print(f"HTTP Exception: {str(he.detail)}")
        raise
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
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
        
        return {"message": "Password updated successfully"}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/contacts/{contact_id}")
async def delete_contact(contact_id: str, db: Session = Depends(get_users_db), token = Depends(verify_token)):
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
async def update_contact(contact_id: str, contact: dict, db: Session = Depends(get_users_db), token = Depends(verify_token)):
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

class UserResponse(BaseModel):
    id: int
    username: str
    role: str 

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
    
# suppression
# Add helper functions

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

# Login endpoint
@app.post("/api/login")
async def login(credentials: dict, db: Session = Depends(get_users_db)):
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


@app.get("/settings")
async def get_settings(admin_user = Depends(is_admin)):
    """Get all settings from config.ini"""
    return read_config()

@app.post("/settings")
async def update_settings(settings: Dict, admin_user = Depends(is_admin)):
    """Update settings in config.ini"""
    logging.info(f"Received settings update: {settings}")
    
    try:
        # Validate settings
        if not isinstance(settings, dict):
            raise ValueError("Settings must be a dictionary")
            
        # Debug print
        print(f"Attempting to save settings: {settings}")
        
        save_config(settings)
        logging.info("Settings saved successfully")
        add_audit_log("Update Settings", admin_user.username, "Updated settings")
        return {"message": "Settings updated successfully"}
        
    except Exception as e:
        logging.error(f"Error updating settings: {str(e)}")
        logging.exception("Full traceback:")
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
    add_audit_log("Save Template", admin_user.username, f"Saved template: {template_name}")
    with open(f"{TEMPLATES_DIR}/{template_name}", 'w') as f:
        json.dump(template, f, indent=2)
    return {"message": "Template saved"}

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
        logging.error(f"Certificate download error: {str(e)}")
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
                logging.info(f"Created backup: {backup_file}")
        
        # Create subject string from sanitized inputs
        subj = f"/C={cert_data['country']}/ST={cert_data['state']}/L={cert_data['city']}/O={cert_data['organization']}/CN={cert_data['common_name']}/emailAddress={cert_data['email']}"
        
        # Generate new certificates
        cmd = [
            'openssl', 'req', '-x509', '-newkey', 'rsa:4096', '-nodes',
            '-out', 'cert.pem', '-keyout', 'key.pem',
            '-days', '365', '-subj', subj
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            # Restore backups if generation fails
            for file in ['cert.pem', 'key.pem']:
                backup_file = f"{file}.{timestamp}.backup"
                if os.path.exists(backup_file):
                    shutil.copy2(backup_file, file)
            raise Exception(f"OpenSSL error: {result.stderr}")
            
        add_audit_log("Generate Certificate", admin_user.username, f"Generated new certificate for {cert_data['common_name']}")
        return {
            "message": "Certificate generated successfully",
            "backup_created": True,
            "backup_timestamp": timestamp
        }
        
    except Exception as e:
        logging.error(f"Certificate generation error: {str(e)}")
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