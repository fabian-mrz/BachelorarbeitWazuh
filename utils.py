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
from logger import logger
from configparser import ConfigParser

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

# Add after other constants
API_KEY_HEADER = APIKeyHeader(name="X-API-Key")


def load_api_tokens() -> dict:
    """Load API tokens from config.ini"""
    tokens = {}
    config = ConfigParser()
    
    try:
        config.read('config.ini')
        if 'API' in config and 'tokens' in config['API']:
            token_pairs = config['API']['tokens'].split(',')
            for pair in token_pairs:
                name, token = pair.split(':')
                tokens[token.strip()] = name.strip()
        return tokens
    except Exception as e:
        logger.error(f"Error loading API tokens: {e}")
        return {}

# Initialize global API tokens
API_TOKENS = load_api_tokens()




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
    
    try:
        with open(CURRENT_LOG_FILE, 'a') as f:
            f.write(json.dumps(log_entry) + '\n')
    except Exception as e:
        print(f"Error writing audit log: {e}")

def init_db():
    try:
        Base.metadata.create_all(users_engine)
        Base.metadata.create_all(incidents_engine)
    except Exception as e:
        print(f"Error initializing database: {e}")

def hash_password(password: str) -> str:
    try:
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    except Exception as e:
        print(f"Error hashing password: {e}")
        return None

async def load_escalation_config(rule_id: str = None):
    """Load escalation config for specific rule or default"""
    try:
        with open('escalations.json') as f:
            escalations = json.load(f)
        
        if rule_id and rule_id in escalations['rules']:
            return escalations['rules'][rule_id]
        return escalations['default']
    except Exception as e:
        print(f"Error loading escalation config: {e}")
        return None

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

def clean_message_for_phone(message: str) -> str:
    """Clean message text for phone TTS"""
    import re
    try:
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
    except Exception as e:
        print(f"Error cleaning message: {e}")
        return message

def read_config() -> dict:
    try:
        config.read('config.ini')
        
        # Parse API tokens string into dictionary
        api_tokens = {}
        if 'API' in config and 'tokens' in config['API']:
            token_pairs = config['API']['tokens'].split(',')
            for pair in token_pairs:
                name, token = pair.split(':')
                api_tokens[name.strip()] = token.strip()
                
        return {
            "telegram": {
                "CHAT_ID": str(config['telegram']['CHAT_ID']),
                "BOT_TOKEN": config['telegram']['BOT_TOKEN'],
                "enabled": config['telegram']['enabled']
            },
            "smtp": dict(config['SMTP']),
            "sip": dict(config['SIP']),
            "api": {
                "tokens": api_tokens
            },
            "auth": {
                "secret_key": config['AUTH']['secret_key']
            }
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

    config['AUTH'] = {
        'secret_key': settings['auth']['secret_key']
    }
    
    # Handle API tokens
    if 'api' in settings and 'tokens' in settings['api']:
        if not 'API' in config:
            config['API'] = {}
            
        # Validate presence of default token
        if 'default' not in settings['api']['tokens']:
            logger.error("Default token missing in API settings")
            add_audit_log("Settings Update Failed", "system", "Default API token must be present")
            raise ValueError("Default API token must be present in settings")
            
        # Convert tokens dict to string format: name:token,name2:token2
        token_pairs = []
        for name, token in settings['api']['tokens'].items():
            token_pairs.append(f"{name}:{token}")
        config['API']['tokens'] = ','.join(token_pairs)
    
    try:
        with open('config.ini', 'w') as f:
            config.write(f)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error saving config: {str(e)}")
    
def load_suppressions() -> dict:
    """Load suppressions from file"""
    try:
        if not SUPPRESSIONS_FILE.exists():
            return {}
        with open(SUPPRESSIONS_FILE) as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading suppressions: {e}")
        return {}

def load_contacts() -> dict:
    """Load contacts from users.db"""
    try:
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
    except Exception as e:
        print(f"Error loading contacts: {e}")
        return {}

def save_suppressions(suppressions: dict):
    """Save suppressions to file"""
    try:
        with open(SUPPRESSIONS_FILE, 'w') as f:
            json.dump(suppressions, f, indent=2)
    except Exception as e:
        print(f"Error saving suppressions: {e}")

def generate_password():
    try:
        return secrets.token_urlsafe(12)
    except Exception as e:
        print(f"Error generating password: {e}")
        return None
    
def generate_openssl_config(cert_data: dict) -> str:
    return f"""[req]
default_bits = 4096
prompt = no
default_md = sha256
x509_extensions = v3_req
distinguished_name = dn

[dn]
C = {cert_data['country']}
ST = {cert_data['state']}
L = {cert_data['city']}
O = {cert_data['organization']}
CN = {cert_data['common_name']}
emailAddress = {cert_data['email']}

[v3_req]
basicConstraints = CA:TRUE
keyUsage = digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = {cert_data['common_name']}
DNS.2 = localhost
IP.1 = 127.0.0.1
"""