import pytest
from unittest.mock import AsyncMock, patch
from app.services.monitoring_service import MonitoringService
from dotenv import load_dotenv
import json

# Load environment variables
load_dotenv()

@pytest.fixture
async def monitoring_service():
    return MonitoringService()

@pytest.fixture
def system_status():
    with open("tests/fixtures/system_status.json", "r") as f:
        return json.load(f)

@pytest.mark.asyncio
@patch("app.services.opnsense_client.OPNsenseClient.get_system_health", new_callable=AsyncMock)
async def test_get_system_stats(mock_get_system_health, monitoring_service, system_status):
    mock_get_system_health.return_value = system_status
    
    result = await monitoring_service.get_system_stats()
    assert result == system_status
    assert result["cpu"]["usage_percent"] == 45.6
    assert result["memory"]["usage_percent"] == 60.2
    assert result["uptime"]["hours"] == 123
    mock_get_system_health.assert_called_once()