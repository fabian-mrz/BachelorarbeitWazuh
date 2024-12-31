from datetime import datetime
import json
import bcrypt
from database import Base, users_engine, incidents_engine, get_incidents_db, get_users_db
import os
from models import User
from fastapi.security import APIKeyHeader
from fastapi import Security, HTTPException, status
import configparser
from pathlib import Path



# Constants
LOGS_DIR = "audit_logs"
CURRENT_LOG_FILE = os.path.join(LOGS_DIR, "current_audit.log")
TEMPLATES_DIR = './templates'
DEFAULT_TEMPLATE_PATH = os.path.join(TEMPLATES_DIR, 'default.json')
SUPPRESSIONS_FILE = Path("suppressions.json")

# Initialize ConfigParser
config = configparser.ConfigParser()

os.makedirs(LOGS_DIR, exist_ok=True)
os.makedirs(TEMPLATES_DIR, exist_ok=True)


os.makedirs(LOGS_DIR, exist_ok=True)

# Add after other constants
API_KEY_HEADER = APIKeyHeader(name="X-API-Key")
API_TOKENS = [
    "token1234",  # Replace later in config ini
    "token5678"
]

# Add before the endpoint
async def verify_api_key(api_key: str = Security(API_KEY_HEADER)):
    if api_key not in API_TOKENS:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key"
        )
    return api_key

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
    Base.metadata.create_all(users_engine)
    Base.metadata.create_all(incidents_engine)
    
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


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


def clean_message_for_phone(message: str) -> str:
    """Clean message text for phone TTS"""
    # First remove sample event section
    import re
    message = re.sub(r'\*Sample Event:\*[\s\S]*?```[\s\S]*?```', '', message)
    
    return (message
        .replace('🚨', '')           # Remove emoji
        .replace('*', '')            # Remove markdown
        .replace('```', '')          # Remove code blocks
        .replace('"', '')            # Remove quotes
        .replace("'", '')            # Remove single quotes
        .replace('{', '')            # Remove brackets
        .replace('}', '')
        .replace('_', ' ')           # Replace underscores with spaces
        .strip()                     # Remove leading/trailing whitespace
    )

def read_config() -> dict:
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

def save_config(settings: dict):
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
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error saving config: {str(e)}")
    
def load_suppressions() -> dict:
    """Load suppressions from file"""
    if not SUPPRESSIONS_FILE.exists():
        return {}
    with open(SUPPRESSIONS_FILE) as f:
        return json.load(f)
    

#load contacts from users.db
def load_contacts() -> dict:
    """Load contacts from users.db"""
    db = next(get_users_db())
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
 
 