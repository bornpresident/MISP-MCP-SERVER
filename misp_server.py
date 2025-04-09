#gFD7kvntstnXCN25q9phQ5Cb6U2WcpiLY7wMFIob
from mcp.server.fastmcp import FastMCP, Context
from pymisp import PyMISP, MISPEvent, MISPAttribute, MISPTag
import os
import json
from datetime import datetime, timedelta
import asyncio
import hashlib
import re
from typing import List, Dict, Optional, Any, Union

# Create an MCP server
mcp = FastMCP("MISP Threat Intelligence")

# MISP connection settings - should be configured through environment variables
MISP_URL = os.environ.get("MISP_URL", "")
MISP_API_KEY = os.environ.get("MISP_API_KEY", "")
MISP_VERIFY_SSL = os.environ.get("MISP_VERIFY_SSL", "True").lower() == "true"

# Initialize PyMISP
def get_misp():
    if not MISP_URL or not MISP_API_KEY:
        raise ValueError("MISP_URL and MISP_API_KEY environment variables must be set")
    return PyMISP(MISP_URL, MISP_API_KEY, MISP_VERIFY_SSL)

# Helper function to format MISP events
def format_event(event):
    result = {
        "id": event["Event"]["id"],
        "date": event["Event"]["date"],
        "info": event["Event"]["info"],
        "threat_level": event["Event"]["threat_level_id"],
        "analysis": event["Event"]["analysis"],
        "tags": [tag["Tag"]["name"] for tag in event["Event"].get("Tag", [])],
        "attributes": []
    }
    
    for attribute in event["Event"].get("Attribute", []):
        result["attributes"].append({
            "type": attribute["type"],
            "category": attribute["category"],
            "value": attribute["value"],
            "comment": attribute.get("comment", "")
        })
    
    return result

# Platform tag mapping
PLATFORM_TAGS = {
    "windows": ["windows", "microsoft", "win"],
    "macos": ["macos", "osx", "mac", "apple"],
    "linux": ["linux", "ubuntu", "debian", "centos", "redhat", "fedora"],
    "android": ["android", "mobile"],
    "ios": ["ios", "iphone", "ipad", "mobile"],
    "iot": ["iot", "embedded", "smart-device"]
}

# Tool to get the latest Mac-related malware samples
@mcp.tool()
async def get_mac_malware(days: int = 30, limit: int = 10, ctx: Context = None) -> str:
    """
    Get the latest Mac-related malware samples from MISP
    
    Args:
        days: Number of days to look back (default: 30)
        limit: Maximum number of results to return (default: 10)
    
    Returns:
        Formatted information about Mac-related malware samples
    """
    try:
        misp = get_misp()
        
        # Calculate the date range
        now = datetime.now()
        start_date = (now - timedelta(days=days)).strftime('%Y-%m-%d')
        
        # Search for Mac-related events
        mac_tags = PLATFORM_TAGS["macos"]
        result_events = []
        
        # Progress reporting
        if ctx:
            ctx.info(f"Searching for Mac malware in the last {days} days...")
        
        # Query for each tag
        for i, tag in enumerate(mac_tags):
            if ctx:
                await ctx.report_progress(i, len(mac_tags))
                ctx.info(f"Searching for tag: {tag}")
            
            # Search for events with the tag
            events = misp.search(
                tags=tag,
                date_from=start_date,
                limit=limit,
                pythonify=False
            )
            
            for event in events:
                # Skip if we already have this event
                if any(e["id"] == event["Event"]["id"] for e in result_events):
                    continue
                
                formatted = format_event(event)
                result_events.append(formatted)
                
                # Stop if we have enough events
                if len(result_events) >= limit:
                    break
            
            # Stop if we have enough events
            if len(result_events) >= limit:
                break
        
        if not result_events:
            return "No Mac-related malware samples found in the specified time period."
        
        # Format the results as a readable string
        output = f"Found {len(result_events)} Mac-related malware samples in the last {days} days:\n\n"
        
        for event in result_events:
            output += f"ID: {event['id']}\n"
            output += f"Date: {event['date']}\n"
            output += f"Info: {event['info']}\n"
            output += f"Tags: {', '.join(event['tags'])}\n"
            
            if event['attributes']:
                output += "Key Attributes:\n"
                for attr in event['attributes'][:5]:  # Limit to 5 attributes for readability
                    output += f"  - {attr['type']} ({attr['category']}): {attr['value']}\n"
                    if attr['comment']:
                        output += f"    Comment: {attr['comment']}\n"
            
            output += "\n---\n\n"
        
        return output
    
    except Exception as e:
        return f"Error querying MISP: {str(e)}"

# 1. ENHANCEMENT: Perform platform-specific malware searches
@mcp.tool()
async def get_platform_malware(platform: str, days: int = 30, limit: int = 10, ctx: Context = None) -> str:
    """
    Get the latest malware samples for a specific platform from MISP
    
    Args:
        platform: Platform to search for (windows, macos, linux, android, ios, iot)
        days: Number of days to look back (default: 30)
        limit: Maximum number of results to return (default: 10)
    
    Returns:
        Formatted information about platform-specific malware samples
    """
    try:
        if platform.lower() not in PLATFORM_TAGS:
            return f"Unknown platform: {platform}. Supported platforms: {', '.join(PLATFORM_TAGS.keys())}"
            
        misp = get_misp()
        
        # Calculate the date range
        now = datetime.now()
        start_date = (now - timedelta(days=days)).strftime('%Y-%m-%d')
        
        # Get tags for the specified platform
        platform_tags = PLATFORM_TAGS[platform.lower()]
        result_events = []
        
        # Progress reporting
        if ctx:
            ctx.info(f"Searching for {platform} malware in the last {days} days...")
        
        # Query for each tag
        for i, tag in enumerate(platform_tags):
            if ctx:
                await ctx.report_progress(i, len(platform_tags))
                ctx.info(f"Searching for tag: {tag}")
            
            # Search for events with the tag
            events = misp.search(
                tags=tag,
                date_from=start_date,
                limit=limit,
                pythonify=False
            )
            
            for event in events:
                # Skip if we already have this event
                if any(e["id"] == event["Event"]["id"] for e in result_events):
                    continue
                
                formatted = format_event(event)
                result_events.append(formatted)
                
                # Stop if we have enough events
                if len(result_events) >= limit:
                    break
            
            # Stop if we have enough events
            if len(result_events) >= limit:
                break
        
        if not result_events:
            return f"No {platform}-related malware samples found in the specified time period."
        
        # Format the results as a readable string
        output = f"Found {len(result_events)} {platform}-related malware samples in the last {days} days:\n\n"
        
        for event in result_events:
            output += f"ID: {event['id']}\n"
            output += f"Date: {event['date']}\n"
            output += f"Info: {event['info']}\n"
            output += f"Tags: {', '.join(event['tags'])}\n"
            
            if event['attributes']:
                output += "Key Attributes:\n"
                for attr in event['attributes'][:5]:  # Limit to 5 attributes for readability
                    output += f"  - {attr['type']} ({attr['category']}): {attr['value']}\n"
                    if attr['comment']:
                        output += f"    Comment: {attr['comment']}\n"
            
            output += "\n---\n\n"
        
        return output
    
    except Exception as e:
        return f"Error querying MISP: {str(e)}"

# 2. ENHANCEMENT: Tool for advanced MISP searches
@mcp.tool()
async def advanced_search(
    query_type: str,
    query_value: str,
    platform: str = None,
    days: int = 30,
    limit: int = 10,
    ctx: Context = None
) -> str:
    """
    Perform advanced searches in MISP
    
    Args:
        query_type: Type of search (attribute_type, tag, threatactor, tlp)
        query_value: Value to search for
        platform: Optional platform filter (windows, macos, linux, android, ios, iot)
        days: Number of days to look back (default: 30)
        limit: Maximum number of results to return (default: 10)
    
    Returns:
        Formatted search results
    """
    try:
        misp = get_misp()
        
        # Calculate the date range
        now = datetime.now()
        start_date = (now - timedelta(days=days)).strftime('%Y-%m-%d')
        
        # Define search parameters based on query type
        search_params = {
            "date_from": start_date,
            "limit": limit,
            "pythonify": False
        }
        
        # Add platform filter if specified
        platform_tags = []
        if platform:
            if platform.lower() not in PLATFORM_TAGS:
                return f"Unknown platform: {platform}. Supported platforms: {', '.join(PLATFORM_TAGS.keys())}"
            platform_tags = PLATFORM_TAGS[platform.lower()]
        
        # Construct search based on query type
        if query_type == "attribute_type":
            search_params["type"] = query_value
            search_desc = f"attribute type '{query_value}'"
        elif query_type == "tag":
            search_params["tags"] = query_value
            search_desc = f"tag '{query_value}'"
        elif query_type == "threatactor":
            search_params["tags"] = f"threat-actor:{query_value}"
            search_desc = f"threat actor '{query_value}'"
        elif query_type == "tlp":
            search_params["tags"] = f"tlp:{query_value}"
            search_desc = f"TLP '{query_value}'"
        else:
            return f"Unknown query type: {query_type}. Supported types: attribute_type, tag, threatactor, tlp"
        
        # Progress reporting
        if ctx:
            ctx.info(f"Performing advanced search for {search_desc}")
        
        # Perform the search
        events = misp.search(**search_params)
        
        # Filter by platform if specified
        result_events = []
        if platform and events:
            for event in events:
                event_tags = [tag["Tag"]["name"] for tag in event["Event"].get("Tag", [])]
                
                # Check if any platform tag matches
                if any(platform_tag in event_tags for platform_tag in platform_tags):
                    result_events.append(format_event(event))
                    
                    # Stop if we have enough events
                    if len(result_events) >= limit:
                        break
        else:
            result_events = [format_event(event) for event in events[:limit]]
        
        if not result_events:
            return f"No results found for {search_desc}" + (f" on {platform}" if platform else "")
        
        # Format the results as a readable string
        output = f"Found {len(result_events)} results for {search_desc}" + (f" on {platform}" if platform else "") + f" in the last {days} days:\n\n"
        
        for event in result_events:
            output += f"ID: {event['id']}\n"
            output += f"Date: {event['date']}\n"
            output += f"Info: {event['info']}\n"
            output += f"Tags: {', '.join(event['tags'])}\n"
            
            if event['attributes']:
                output += "Key Attributes:\n"
                for attr in event['attributes'][:5]:  # Limit to 5 attributes for readability
                    output += f"  - {attr['type']} ({attr['category']}): {attr['value']}\n"
                    if attr['comment']:
                        output += f"    Comment: {attr['comment']}\n"
            
            output += "\n---\n\n"
        
        return output
    
    except Exception as e:
        return f"Error performing advanced search: {str(e)}"

# 3. ENHANCEMENT: Submit new IoC to MISP
@mcp.tool()
async def submit_ioc(
    ioc_value: str,
    ioc_type: str,
    event_info: str,
    category: str = "Artifacts dropped",
    platform: str = None,
    tlp: str = "amber",
    comment: str = "",
    ctx: Context = None
) -> str:
    """
    Submit a new Indicator of Compromise (IoC) to MISP
    
    Args:
        ioc_value: The actual IoC value (e.g., hash, URL, IP)
        ioc_type: Type of IoC (e.g., md5, sha256, url, ip-dst, filename)
        event_info: Brief description of the event
        category: Category of the attribute (default: "Artifacts dropped")
        platform: Platform affected (windows, macos, linux, android, ios, iot)
        tlp: Traffic Light Protocol level (white, green, amber, red)
        comment: Optional comment for the IoC
    
    Returns:
        Confirmation message with event ID
    """
    try:
        misp = get_misp()
        
        # Validate IoC type
        valid_types = ["md5", "sha1", "sha256", "filename", "ip-src", "ip-dst", "domain", "url", "email"]
        if ioc_type not in valid_types:
            return f"Invalid IoC type: {ioc_type}. Valid types are: {', '.join(valid_types)}"
        
        # Validate TLP
        valid_tlp = ["white", "green", "amber", "red"]
        if tlp not in valid_tlp:
            return f"Invalid TLP: {tlp}. Valid values are: {', '.join(valid_tlp)}"
        
        # Create a new event
        event = MISPEvent()
        event.info = event_info
        event.distribution = 0  # Your organization only
        event.threat_level_id = 2  # Medium
        event.analysis = 0  # Initial
        
        # Add the IoC as an attribute
        attribute = event.add_attribute(
            type=ioc_type,
            value=ioc_value,
            category=category,
            comment=comment,
            distribution=0  # Your organization only
        )
        
        # Add TLP tag
        event.add_tag(f"tlp:{tlp}")
        
        # Add platform tag if specified
        if platform:
            if platform.lower() not in PLATFORM_TAGS:
                return f"Unknown platform: {platform}. Supported platforms: {', '.join(PLATFORM_TAGS.keys())}"
            event.add_tag(platform.lower())
        
        # Add a current date tag
        current_date = datetime.now().strftime('%Y-%m-%d')
        event.add_tag(f"first-seen:{current_date}")
        
        # Progress reporting
        if ctx:
            ctx.info(f"Submitting new IoC to MISP: {ioc_type} - {ioc_value}")
        
        # Add the event to MISP
        result = misp.add_event(event)
        
        if "errors" in result:
            return f"Error submitting IoC: {result['errors']}"
        
        event_id = result["Event"]["id"]
        
        return f"""
Successfully submitted new IoC to MISP:

Event ID: {event_id}
Event Info: {event_info}
IoC Type: {ioc_type}
IoC Value: {ioc_value}
Category: {category}
Platform: {platform if platform else "Not specified"}
TLP: {tlp}
Comment: {comment if comment else "None"}

You can view this event in MISP at: {MISP_URL}/events/view/{event_id}
"""
    
    except Exception as e:
        return f"Error submitting IoC to MISP: {str(e)}"

# 4. ENHANCEMENT: Generate threat intelligence report
@mcp.tool()
async def generate_threat_report(
    days: int = 30,
    platforms: str = "all",
    threat_level: str = "all",
    include_stats: bool = True,
    ctx: Context = None
) -> str:
    """
    Generate a comprehensive threat intelligence report based on MISP data
    
    Args:
        days: Number of days to include in the report (default: 30)
        platforms: Comma-separated list of platforms or "all" (windows, macos, linux, android, ios, iot)
        threat_level: Filter by threat level (low, medium, high, all)
        include_stats: Whether to include statistics (default: True)
    
    Returns:
        Formatted threat intelligence report
    """
    try:
        misp = get_misp()
        
        # Calculate the date range
        now = datetime.now()
        start_date = (now - timedelta(days=days)).strftime('%Y-%m-%d')
        
        # Parse platforms
        platform_list = []
        if platforms.lower() != "all":
            for platform in platforms.split(','):
                platform = platform.strip().lower()
                if platform not in PLATFORM_TAGS:
                    return f"Unknown platform: {platform}. Supported platforms: {', '.join(PLATFORM_TAGS.keys())}"
                platform_list.append(platform)
        
        # Map threat level to MISP threat level ID
        threat_level_map = {
            "low": "3", 
            "medium": "2",
            "high": "1",
            "all": None
        }
        
        if threat_level.lower() not in threat_level_map:
            return f"Invalid threat level: {threat_level}. Valid levels are: low, medium, high, all"
        
        threat_level_id = threat_level_map[threat_level.lower()]
        
        # Progress reporting
        if ctx:
            ctx.info(f"Generating threat intelligence report for the last {days} days")
        
        # Gather events for the report
        search_params = {
            "date_from": start_date,
            "pythonify": False
        }
        
        if threat_level_id:
            search_params["threat_level_id"] = threat_level_id
        
        # Get all events in the date range
        all_events = misp.search(**search_params)
        
        # Filter by platform if needed
        filtered_events = []
        platform_counts = {}
        threat_actor_counts = {}
        malware_type_counts = {}
        tlp_counts = {}
        
        # Initialize platform counts
        for platform in PLATFORM_TAGS.keys():
            platform_counts[platform] = 0
        
        # Process events
        for event in all_events:
            event_tags = [tag["Tag"]["name"] for tag in event["Event"].get("Tag", [])]
            
            # Check platform match if platforms are specified
            if platform_list:
                platform_match = False
                for platform in platform_list:
                    if any(tag in event_tags for tag in PLATFORM_TAGS[platform]):
                        platform_match = True
                        platform_counts[platform] += 1
                        break
                
                if not platform_match:
                    continue
            else:
                # Count all platforms for statistics
                for platform, tags in PLATFORM_TAGS.items():
                    if any(tag in event_tags for tag in tags):
                        platform_counts[platform] += 1
            
            # Count threat actors
            for tag in event_tags:
                if tag.startswith("threat-actor:"):
                    actor = tag.split(":", 1)[1]
                    threat_actor_counts[actor] = threat_actor_counts.get(actor, 0) + 1
                elif tag.startswith("malware:"):
                    malware = tag.split(":", 1)[1]
                    malware_type_counts[malware] = malware_type_counts.get(malware, 0) + 1
                elif tag.startswith("tlp:"):
                    tlp = tag.split(":", 1)[1]
                    tlp_counts[tlp] = tlp_counts.get(tlp, 0) + 1
            
            # Add to filtered events
            formatted = format_event(event)
            filtered_events.append(formatted)
        
        if not filtered_events:
            return f"No events found matching the criteria in the last {days} days."
        
        # Build the report
        report = f"# MISP Threat Intelligence Report\n\n"
        report += f"**Period:** Last {days} days ({start_date} to {now.strftime('%Y-%m-%d')})\n"
        report += f"**Platforms:** {platforms}\n"
        report += f"**Threat Level:** {threat_level}\n\n"
        
        # Include statistics if requested
        if include_stats:
            report += "## Threat Statistics\n\n"
            
            # Platform statistics
            report += "### Platform Distribution\n\n"
            for platform, count in platform_counts.items():
                if count > 0:
                    report += f"- {platform.capitalize()}: {count} events\n"
            
            report += "\n"
            
            # Threat actor statistics
            if threat_actor_counts:
                report += "### Top Threat Actors\n\n"
                sorted_actors = sorted(threat_actor_counts.items(), key=lambda x: x[1], reverse=True)
                for actor, count in sorted_actors[:5]:
                    report += f"- {actor}: {count} events\n"
                
                report += "\n"
            
            # Malware type statistics
            if malware_type_counts:
                report += "### Top Malware Types\n\n"
                sorted_malware = sorted(malware_type_counts.items(), key=lambda x: x[1], reverse=True)
                for malware, count in sorted_malware[:5]:
                    report += f"- {malware}: {count} events\n"
                
                report += "\n"
            
            # TLP statistics
            if tlp_counts:
                report += "### TLP Distribution\n\n"
                for tlp in ["white", "green", "amber", "red"]:
                    if tlp in tlp_counts:
                        report += f"- TLP:{tlp}: {tlp_counts[tlp]} events\n"
                
                report += "\n"
        
        # Recent significant events
        report += "## Recent Significant Events\n\n"
        
        # Sort events by threat level
        sorted_events = sorted(filtered_events, key=lambda x: x["threat_level"])
        
        # Include the top 10 most significant events
        for event in sorted_events[:10]:
            report += f"### {event['info']}\n\n"
            report += f"**Event ID:** {event['id']}\n"
            report += f"**Date:** {event['date']}\n"
            report += f"**Threat Level:** {['High', 'Medium', 'Low'][int(event['threat_level'])-1]}\n"
            report += f"**Tags:** {', '.join(event['tags'])}\n\n"
            
            if event['attributes']:
                report += "**Key Indicators:**\n\n"
                for attr in event['attributes'][:5]:
                    report += f"- {attr['type']} ({attr['category']}): `{attr['value']}`\n"
                    if attr['comment']:
                        report += f"  Comment: {attr['comment']}\n"
            
            report += "\n"
        
        # Recommendations section
        report += "## Recommendations\n\n"
        report += "Based on the analyzed threat data, the following recommendations are made:\n\n"
        
        # Generic recommendations based on platforms
        for platform, count in platform_counts.items():
            if count > 0:
                if platform == "windows":
                    report += "- **Windows Systems:** Ensure all systems are updated with the latest security patches, particularly focusing on Microsoft Office and Windows services that are common attack vectors.\n"
                elif platform == "macos":
                    report += "- **macOS Systems:** Review Gatekeeper settings and ensure only trusted applications are allowed to execute. Monitor for unauthorized kernel extensions.\n"
                elif platform == "linux":
                    report += "- **Linux Systems:** Audit SSH configurations, review running services, and ensure regular updates are applied to all packages, especially web services.\n"
                elif platform == "android":
                    report += "- **Android Devices:** Enforce application installation only from trusted sources (Google Play). Consider implementing mobile device management for corporate devices.\n"
                elif platform == "ios":
                    report += "- **iOS Devices:** Ensure devices are updated to the latest iOS version and review MDM profiles if applicable.\n"
                elif platform == "iot":
                    report += "- **IoT Devices:** Audit network access for IoT devices, segregate them onto separate network segments, and ensure firmware is up-to-date.\n"
        
        report += "\n"
        
        # Add a conclusion
        report += "## Conclusion\n\n"
        report += f"This report summarizes threat activity observed over the past {days} days. Organizations should remain vigilant and implement the recommendations provided based on their specific environment and threat landscape. Regular threat intelligence monitoring and security posture assessments are recommended to maintain an effective security program.\n"
        
        return report
    
    except Exception as e:
        return f"Error generating threat intelligence report: {str(e)}"

# Tool to search MISP for specific threats
@mcp.tool()
async def search_misp(query: str, days: int = 30) -> str:
    """
    Search MISP for specific threats
    
    Args:
        query: Search term (e.g., CVE ID, malware name, hash)
        days: Number of days to look back (default: 30)
    
    Returns:
        Formatted information about matching threats
    """
    try:
        misp = get_misp()
        
        # Calculate the date range
        now = datetime.now()
        start_date = (now - timedelta(days=days)).strftime('%Y-%m-%d')
        
        # Search for the query
        events = misp.search(
            value=query,
            date_from=start_date,
            pythonify=False
        )
        
        if not events:
            return f"No results found for '{query}' in the last {days} days."
        
        # Format the results as a readable string
        output = f"Found {len(events)} results for '{query}' in the last {days} days:\n\n"
        
        for event in events[:10]:  # Limit to 10 events for readability
            formatted = format_event(event)
            
            output += f"ID: {formatted['id']}\n"
            output += f"Date: {formatted['date']}\n"
            output += f"Info: {formatted['info']}\n"
            output += f"Tags: {', '.join(formatted['tags'])}\n"
            
            if formatted['attributes']:
                output += "Key Attributes:\n"
                for attr in formatted['attributes'][:5]:  # Limit to 5 attributes for readability
                    output += f"  - {attr['type']} ({attr['category']}): {attr['value']}\n"
                    if attr['comment']:
                        output += f"    Comment: {attr['comment']}\n"
            
            output += "\n---\n\n"
        
        if len(events) > 10:
            output += f"(Showing 10 of {len(events)} results)"
        
        return output
    
    except Exception as e:
        return f"Error searching MISP: {str(e)}"

# Resource to get recent MISP feed information
@mcp.resource("feeds://recent/{days}")
async def get_recent_feeds(days: int = 7) -> str:
    """Get information about recent MISP feeds"""
    try:
        misp = get_misp()
        
        # Get all feeds
        feeds = misp.feeds()
        
        # Format the output
        output = f"MISP Feed Information (Last {days} days):\n\n"
        
        for feed in feeds:
            feed_data = feed["Feed"]
            
            # Skip if the feed is disabled
            if feed_data.get("enabled") == "0":
                continue
            
            # Skip feeds older than the specified days
            last_fetched = feed_data.get("source_format")
            if not last_fetched:
                continue
            
            output += f"Name: {feed_data['name']}\n"
            output += f"Provider: {feed_data.get('provider', 'Unknown')}\n"
            output += f"Source Format: {feed_data.get('source_format', 'Unknown')}\n"
            output += f"URL: {feed_data.get('url', 'N/A')}\n"
            output += "\n---\n\n"
        
        return output
    
    except Exception as e:
        return f"Error fetching MISP feeds: {str(e)}"

# Tool to get MISP statistics
@mcp.tool()
async def get_misp_stats() -> str:
    """
    Get statistics about the MISP instance
    
    Returns:
        Formatted statistics about the MISP instance
    """
    try:
        misp = get_misp()
        
        # Get statistics
        stats = misp.stats()
        
        # Format the output
        output = "MISP Statistics:\n\n"
        
        if "stats" in stats:
            for section, data in stats["stats"].items():
                output += f"{section.upper()}:\n"
                
                if isinstance(data, dict):
                    for key, value in data.items():
                        output += f"  - {key}: {value}\n"
                else:
                    output += f"  - {data}\n"
                
                output += "\n"
        
        return output
    
    except Exception as e:
        return f"Error fetching MISP statistics: {str(e)}"

# Run the server
if __name__ == "__main__":
    mcp.run()