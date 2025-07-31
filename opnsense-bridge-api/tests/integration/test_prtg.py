import pytest
import httpx
from app.main import app
from dotenv import load_dotenv
import xml.etree.ElementTree as ET
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
async def test_prtg_system_health(client):
    response = await client.get("/prtg/system-health")
    assert response.status_code == 200
    xml = ET.fromstring(response.text)
    assert xml.tag == "prtg"
    assert any(result.find("channel").text == "CPU Usage" for result in xml.findall("result"))
    assert any(result.find("channel").text == "Memory Usage" for result in xml.findall("result"))

@pytest.mark.asyncio
async def test_prtg_firewall_statistics(client):
    response = await client.get("/prtg/firewall-statistics")
    assert response.status_code == 200
    xml = ET.fromstring(response.text)
    assert xml.tag == "prtg"
    assert any(result.find("channel").text == "Blocked Events" for result in xml.findall("result"))