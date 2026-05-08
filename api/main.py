import asyncio
import json
import logging
from datetime import datetime
from typing import Dict, List, Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Set up simple logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("soar_api")

app = FastAPI(title="SOAR Dashboard API", version="1.0.0")

# Allow CORS for the dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify the exact origin
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------------------------------------------------------
# Mock Data Generators (Replace with Elasticsearch queries later)
# ------------------------------------------------------------------

def get_mock_kpis() -> Dict[str, Any]:
    return {
        "totalAlerts": 142,
        "mitigated": 138,
        "mttr": "2m 15s",
        "activeThreats": 4,
        "lastUpdated": datetime.utcnow().isoformat() + "Z"
    }

def get_mock_incidents() -> List[Dict[str, Any]]:
    return [
        {
            "id": "inc-001",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "attack_type": "SYN Flood",
            "source_ip": "192.168.1.105",
            "target": "iot-device-1",
            "severity": "high",
            "status": "mitigated",
            "risk_score": 85
        },
        {
            "id": "inc-002",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "attack_type": "Brute Force",
            "source_ip": "10.0.0.50",
            "target": "iot-device-2",
            "severity": "critical",
            "status": "active",
            "risk_score": 92
        }
    ]

def get_mock_actions() -> List[Dict[str, Any]]:
    return [
        {
            "action_id": "ACT-001",
            "action_name": "Block Source IP Address",
            "status": "success",
            "target": "iot-device-1",
            "duration_ms": 150,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        },
        {
            "action_id": "ACT-021",
            "action_name": "Lock User Account After Brute Force",
            "status": "success",
            "target": "iot-device-2",
            "duration_ms": 230,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
    ]

def get_mock_assets() -> List[Dict[str, Any]]:
    return [
        {
            "id": "iot-device-1",
            "type": "docker",
            "name": "IoT Device 1 (Debian)",
            "status": "healthy",
            "network": "dmz_net",
            "last_alert": None
        },
        {
            "id": "iot-device-2",
            "type": "docker",
            "name": "IoT Device 2 (BusyBox)",
            "status": "compromised",
            "network": "dmz_net",
            "last_alert": "Brute Force"
        },
        {
            "id": "eve-router-1",
            "type": "eve-ng",
            "name": "Core Router",
            "status": "healthy",
            "network": "core",
            "last_alert": None
        },
        {
            "id": "eve-switch-1",
            "type": "eve-ng",
            "name": "DMZ Switch",
            "status": "healthy",
            "network": "dmz_net",
            "last_alert": None
        }
    ]

def get_mock_timeline() -> List[Dict[str, Any]]:
    # Generate some mock timeline data
    base_time = int(datetime.utcnow().timestamp() * 1000)
    data = []
    for i in range(24):
        data.append({
            "time": base_time - ((23 - i) * 3600 * 1000),
            "critical": max(0, 5 - abs(12 - i)),
            "high": max(0, 10 - abs(10 - i)),
            "medium": max(0, 15 - abs(8 - i)),
            "low": 20
        })
    return data

# ------------------------------------------------------------------
# REST Endpoints
# ------------------------------------------------------------------

@app.get("/api/v1/kpis")
async def get_kpis():
    return get_mock_kpis()

@app.get("/api/v1/incidents")
async def get_incidents():
    return {"incidents": get_mock_incidents()}

@app.get("/api/v1/actions")
async def get_actions():
    return {"actions": get_mock_actions()}

@app.get("/api/v1/assets")
async def get_assets():
    return {"assets": get_mock_assets()}

@app.get("/api/v1/timeline")
async def get_timeline():
    return {"timeline": get_mock_timeline()}

# ------------------------------------------------------------------
# WebSocket Connection Manager
# ------------------------------------------------------------------

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"Client connected. Total clients: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)
        logger.info(f"Client disconnected. Total clients: {len(self.active_connections)}")

    async def broadcast(self, message: Dict[str, Any]):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except RuntimeError:
                # Connection might be dropped
                pass

manager = ConnectionManager()

@app.websocket("/ws/telemetry")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Wait for any messages from client (e.g. heartbeat)
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# ------------------------------------------------------------------
# Background Task to simulate real-time events
# ------------------------------------------------------------------
import random

async def simulate_telemetry():
    """Background task to push random updates to the WebSocket."""
    while True:
        await asyncio.sleep(random.uniform(5.0, 15.0))
        if not manager.active_connections:
            continue
            
        event_types = ["new_incident", "action_result", "kpi_update"]
        event = random.choice(event_types)
        
        payload = {"type": event, "data": {}}
        now = datetime.utcnow().isoformat() + "Z"
        
        if event == "new_incident":
            payload["data"] = {
                "id": f"inc-{random.randint(100, 999)}",
                "timestamp": now,
                "attack_type": random.choice(["Port Scan", "SQLi", "Malware Comms"]),
                "source_ip": f"192.168.1.{random.randint(2, 254)}",
                "target": random.choice(["iot-device-1", "iot-device-2", "eve-router-1"]),
                "severity": random.choice(["low", "medium", "high", "critical"]),
                "status": "active",
                "risk_score": random.randint(40, 99)
            }
        elif event == "action_result":
            payload["data"] = {
                "action_id": f"ACT-{random.randint(1, 35):03d}",
                "action_name": "Simulated Remediation Action",
                "status": random.choice(["success", "success", "success", "failure"]),
                "target": random.choice(["iot-device-1", "iot-device-2"]),
                "duration_ms": random.randint(50, 500),
                "timestamp": now
            }
        elif event == "kpi_update":
            payload["data"] = get_mock_kpis()
            payload["data"]["totalAlerts"] += random.randint(1, 5)
            
        await manager.broadcast(payload)

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(simulate_telemetry())

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8080, reload=True)
