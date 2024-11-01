# incident_server.py
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from datetime import datetime
import asyncio
from typing import Dict

app = FastAPI()

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

@app.post("/incidents/")
async def create_incident(incident: Incident):
    incidents[incident.id] = incident
    asyncio.create_task(handle_incident_timer(incident.id))
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