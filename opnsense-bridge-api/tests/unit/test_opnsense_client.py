import pytest
import httpx
from unittest.mock import AsyncMock, patch
from app.services.opnsense_client import OPNsenseClient
from dotenv import load_dotenv
import os
import json

# Load environment variables
load_dotenv()

OPNSENSE_HOST = os.getenv("OPNSENSE_HOST", "192.168.216.1")
OPNSENSE_API_KEY = os.getenv("OPNSENSE_API_KEY")
OPNSENSE_API_SECRET = os.getenv("OPNSENSE_API_SECRET")
MOCK_OPNSENSE_API = os.getenv("MOCK_OPNSENSE_API", "false").lower() == "true"

@pytest.fixture
async def opnsense_client():
    return OPNsenseClient(
        host=OPNSENSE_HOST,
        api_key=OPNSENSE_API_KEY,
        api_secret=OPNSENSE_API_SECRET,
        verify_ssl=False
    )

@pytest.fixture
def firewall_rules():
    with open("tests/fixtures/firewall_rules.json", "r") as f:
        return json.load(f)

@pytest.fixture
def system_status():
    with open("tests/fixtures/system_status.json", "r") as f:
        return json.load(f)

@pytest.mark.asyncio
@patch("httpx.AsyncClient.get", new_callable=AsyncMock)
async def test_get_system_health(mock_get, opnsense_client, system_status):
    mock_get.return_value = httpx.Response(200, json=system_status)
    
    result = await opnsense_client.get_system_health()
    assert result == system_status
    mock_get.assert_called_once_with(
        f"{OPNSENSE_HOST}/api/diagnostics/systemhealth",
        auth=(OPNSENSE_API_KEY, OPNSENSE_API_SECRET),
        verify=False
    )

@pytest.mark.asyncio
@patch("httpx.AsyncClient.get", new_callable=AsyncMock)
async def test_get_firewall_rules(mock_get, opnsense_client, firewall_rules):
    mock_get.return_value = httpx.Response(200, json=firewall_rules)
    
    result = await opnsense_client.get_firewall_rules()
    assert result == firewall_rules
    mock_get.assert_called_once_with(
        f"{OPNSENSE_HOST}/api/firewall/filter/searchRule",
        auth=(OPNSENSE_API_KEY, OPNSENSE_API_SECRET),
        verify=False
    )