import pytest
from unittest.mock import AsyncMock, patch
from app.services.cyber_defense_service import CyberDefenseService
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

@pytest.fixture
async def cyber_defense_service():
    return CyberDefenseService()

@pytest.mark.asyncio
@patch("app.services.opnsense_client.OPNsenseClient.block_ip", new_callable=AsyncMock)
async def test_block_ip(mock_block_ip, cyber_defense_service):
    mock_block_ip.return_value = {"status": "success", "message": "IP blocked"}
    
    result = await cyber_defense_service.block_ip("1.2.3.4", "Test block")
    assert result == {"status": "success", "message": "IP blocked"}
    mock_block_ip.assert_called_once_with("1.2.3.4", "Test block")

@pytest.mark.asyncio
@patch("app.services.opnsense_client.OPNsenseClient.bulk_block_ips", new_callable=AsyncMock)
async def test_bulk_block_ips(mock_bulk_block, cyber_defense_service):
    mock_bulk_block.return_value = {"status": "success", "message": "IPs blocked"}
    ip_list = ["1.2.3.4", "5.6.7.8"]
    
    result = await cyber_defense_service.bulk_block_ips(ip_list, "Bulk test block")
    assert result == {"status": "success", "message": "IPs blocked"}
    mock_bulk_block.assert_called_once_with(ip_list, "Bulk test block")