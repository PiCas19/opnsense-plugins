import pytest
import httpx
from app.main import app
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

BRIDGE_IP = os.getenv("BRIDGE_IP", "172.16.216.10")
BRIDGE_PORT = os.getenv("BRIDGE_PORT", "8443")
BASE_URL = f"https://{BRIDGE_IP}:{BRIDGE_PORT}"

@pytest.fixture
async def client():
    async with httpx.AsyncClient(app=app, base_url=BASE_URL, verify=False) as client:
        yield client

@pytest.mark.asyncio
async def test_nagios_firewall_rules(client):
    response = await client.get("/nagios/firewall-rules")
    assert response.status_code == 200
    assert "rules=" in response.text
    assert "OK - Firewall rules retrieved" in response.text

@pytest.mark.asyncio
async def test_nagios_system_health(client):
    response = await client.get("/nagios/system-health")
    assert response.status_code == 200
    assert "cpu_usage=" in response.text
    assert "memory_usage=" in response.text
    assert "OK - System health retrieved" in response.text