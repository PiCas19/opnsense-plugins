#!/usr/bin/env python3

import aiohttp
import asyncio
import xml.etree.ElementTree as ET
import sys
import os
from dotenv import load_dotenv
from jose import jwt
from datetime import datetime, timedelta

# Load environment variables from .env file
load_dotenv()

# Retrieve environment variables
BRIDGE_IP = os.getenv("BRIDGE_IP", "172.16.216.10")
BRIDGE_PORT = os.getenv("BRIDGE_PORT", "8443")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")

# Generate JWT token
def generate_jwt_token():
    if not JWT_SECRET_KEY:
        print("<prtg><error>1</error><text>Error: JWT_SECRET_KEY not set in .env</text></prtg>")
        sys.exit(1)
    
    payload = {
        "exp": datetime.utcnow() + timedelta(hours=1),
        "iat": datetime.utcnow(),
        "sub": "prtg_monitor",
        "role": "monitor"  # Adjust role as needed for endpoint access
    }
    token = jwt.encode(payload, JWT_SECRET_KEY, algorithm="HS256")
    return token

async def fetch_system_health():
    if not all([BRIDGE_IP, BRIDGE_PORT]):
        print("<prtg><error>1</error><text>Error: BRIDGE_IP or BRIDGE_PORT not set in .env</text></prtg>")
        sys.exit(1)
    
    url = f"https://{BRIDGE_IP}:{BRIDGE_PORT}/monitoring/system-stats"
    headers = {"Authorization": f"Bearer {generate_jwt_token()}"}
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(url, headers=headers, ssl=False) as response:
                if response.status == 200:
                    data = await response.json()
                    return data
                else:
                    print(f"<prtg><error>1</error><text>HTTP Error: {response.status}</text></prtg>")
                    sys.exit(1)
        except Exception as e:
            print(f"<prtg><error>1</error><text>Error: {str(e)}</text></prtg>")
            sys.exit(1)

def generate_prtg_xml(data):
    prtg = ET.Element("prtg")
    
    result = ET.SubElement(prtg, "result")
    channel = ET.SubElement(result, "channel")
    channel.text = "CPU Usage"
    value = ET.SubElement(result, "value")
    value.text = str(data["cpu"]["usage_percent"])
    unit = ET.SubElement(result, "unit")
    unit.text = "Percent"
    
    result = ET.SubElement(prtg, "result")
    channel = ET.SubElement(result, "channel")
    channel.text = "Memory Usage"
    value = ET.SubElement(result, "value")
    value.text = str(data["memory"]["usage_percent"])
    unit = ET.SubElement(result, "unit")
    unit.text = "Percent"
    
    return ET.tostring(prtg, encoding="unicode", xml_declaration=True)

async def main():
    data = await fetch_system_health()
    xml_output = generate_prtg_xml(data)
    print(xml_output)

if __name__ == "__main__":
    asyncio.run(main())