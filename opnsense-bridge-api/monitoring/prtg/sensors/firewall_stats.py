#!/usr/bin/env python3

import aiohttp
import asyncio
import xml.etree.ElementTree as ET
import sys

async def fetch_firewall_stats():
    url = "https://172.16.216.10:8443/prtg/firewall-statistics"
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(url, ssl=False) as response:
                if response.status == 200:
                    data = await response.json()
                    return data
                else:
                    print("<prtg><error>1</error><text>HTTP Error: {}</text></prtg>".format(response.status))
                    sys.exit(1)
        except Exception as e:
            print("<prtg><error>1</error><text>Error: {}</text></prtg>".format(str(e)))
            sys.exit(1)

def generate_prtg_xml(data):
    prtg = ET.Element("prtg")
    
    result = ET.SubElement(prtg, "result")
    channel = ET.SubElement(result, "channel")
    channel.text = "Total Rules"
    value = ET.SubElement(result, "value")
    value.text = str(data["firewall_stats"]["total_rules"])
    unit = ET.SubElement(result, "unit")
    unit.text = "Count"
    
    result = ET.SubElement(prtg, "result")
    channel = ET.SubElement(result, "channel")
    channel.text = "Active Rules"
    value = ET.SubElement(result, "value")
    value.text = str(data["firewall_stats"]["enabled_vs_disabled"]["enabled"])
    unit = ET.SubElement(result, "unit")
    unit.text = "Count"
    
    return ET.tostring(prtg, encoding="unicode", xml_declaration=True)

async def main():
    data = await fetch_firewall_stats()
    xml_output = generate_prtg_xml(data)
    print(xml_output)

if __name__ == "__main__":
    asyncio.run(main())