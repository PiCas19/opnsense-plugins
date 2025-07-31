import logging
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, Request

from app.services.opnsense_client import get_opnsense_client
from app.utils.validators import validate_ip_address, validate_request_data

logger = logging.getLogger(__name__)
router = APIRouter()

@router.post("/block-ip")
async def emergency_block_ip(request: Request):
    """EMERGENCY: Block IP address immediately"""
    
    try:
        data = await request.json()
        
        # Validate request data
        if not validate_request_data(data, required_fields=["ip_address"]):
            raise HTTPException(status_code=400, detail="Invalid request data")
        
        ip_address = data.get("ip_address")
        reason = data.get("reason", "Emergency Block")
        
        # Validate IP address
        if not validate_ip_address(ip_address):
            raise HTTPException(status_code=400, detail="Invalid IP address format")
        
        operation_id = f"emergency_{int(datetime.now(timezone.utc).timestamp())}"
        
        logger.critical(f"EMERGENCY BLOCK: {operation_id} - IP: {ip_address} - Reason: {reason}")
        
        client = await get_opnsense_client()
        
        async with client:
            # Create emergency block rule
            result = await client.emergency_add_block_rule(
                ip_address=ip_address,
                reason=f"EMERGENCY: {reason} [Op: {operation_id}]"
            )
            
            if result.get("status") == "success":
                logger.critical(f"EMERGENCY BLOCK SUCCESS: {ip_address}")
                
                return {
                    "status": "success",
                    "operation_id": operation_id,
                    "ip_blocked": ip_address,
                    "rule_uuid": result.get("rule_uuid"),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "reason": reason
                }
            else:
                raise Exception("Block operation failed")
                
    except Exception as e:
        logger.critical(f"EMERGENCY BLOCK FAILED: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Emergency block failed: {str(e)}"
        )

@router.post("/bulk-block")
async def emergency_bulk_block(request: Request):
    """EMERGENCY: Block multiple IPs during attack"""
    
    try:
        data = await request.json()
        
        # Validate request data
        if not validate_request_data(data, required_fields=["ip_addresses"]):
            raise HTTPException(status_code=400, detail="Invalid request data")
        
        ip_addresses = data.get("ip_addresses", [])
        reason = data.get("reason", "Bulk Emergency Block")
        
        # Validate IP addresses
        for ip in ip_addresses:
            if not validate_ip_address(ip):
                raise HTTPException(status_code=400, detail=f"Invalid IP address: {ip}")
        
        operation_id = f"bulk_emergency_{int(datetime.now(timezone.utc).timestamp())}"
        
        logger.critical(f"BULK EMERGENCY BLOCK: {operation_id} - {len(ip_addresses)} IPs")
        
        results = {
            "operation_id": operation_id,
            "blocked_ips": [],
            "failed_ips": [],
            "total_requested": len(ip_addresses)
        }
        
        client = await get_opnsense_client()
        
        async with client:
            for ip in ip_addresses:
                try:
                    result = await client.emergency_add_block_rule(
                        ip_address=ip,
                        reason=f"BULK EMERGENCY: {reason} [Op: {operation_id}]"
                    )
                    
                    if result.get("status") == "success":
                        results["blocked_ips"].append({
                            "ip": ip,
                            "rule_uuid": result.get("rule_uuid")
                        })
                        logger.warning(f"BLOCKED: {ip}")
                    else:
                        results["failed_ips"].append({"ip": ip, "error": "Block failed"})
                        
                except Exception as e:
                    results["failed_ips"].append({"ip": ip, "error": str(e)})
                    logger.error(f"FAILED to block {ip}: {e}")
        
        logger.critical(f"BULK BLOCK COMPLETE: {len(results['blocked_ips'])} success, {len(results['failed_ips'])} failed")
        
        return {
            "status": "completed",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **results
        }
        
    except Exception as e:
        logger.critical(f"BULK EMERGENCY FAILED: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Bulk emergency block failed: {str(e)}"
        )

@router.post("/toggle-rule")
async def emergency_toggle_rule(request: Request):
    """Toggle firewall rule on/off (for cyber attack response)"""
    
    try:
        data = await request.json()
        
        # Validate request data
        if not validate_request_data(data, required_fields=["rule_uuid", "action"]):
            raise HTTPException(status_code=400, detail="Invalid request data")
        
        rule_uuid = data.get("rule_uuid")
        action = data.get("action")  # "enable" or "disable"
        reason = data.get("reason", "Emergency rule toggle")
        
        if action not in ["enable", "disable"]:
            raise HTTPException(status_code=400, detail="action must be 'enable' or 'disable'")
        
        logger.warning(f"EMERGENCY RULE TOGGLE: {rule_uuid} - {action} - {reason}")
        
        client = await get_opnsense_client()
        
        async with client:
            result = await client.toggle_firewall_rule(rule_uuid, action == "enable", reason)
            
            if result.get("status") == "success":
                logger.warning(f"RULE TOGGLE SUCCESS: {rule_uuid} - {action}")
                
                return {
                    "status": "success",
                    "rule_uuid": rule_uuid,
                    "action": action,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "reason": reason
                }
            else:
                raise Exception("Rule toggle failed")
                
    except Exception as e:
        logger.error(f"RULE TOGGLE FAILED: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Rule toggle failed: {str(e)}"
        )