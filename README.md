# MISP MCP Server

A Model Context Protocol (MCP) server that integrates with the MISP (Malware Information Sharing Platform) to provide threat intelligence capabilities to Large Language Models.

## Features

- **Mac Malware Detection**: Search for the latest macOS-related malware samples
- **Cross-Platform Threat Intelligence**: Search for threats affecting Windows, macOS, Linux, Android, iOS, and IoT devices
- **Advanced Search Capabilities**: Search by attribute type, tag, threat actor, or TLP classification
- **IoC Submission**: Submit new Indicators of Compromise directly to your MISP instance
- **Threat Intelligence Reports**: Generate comprehensive reports based on MISP data
- **MISP Statistics**: Get insights into your MISP instance's data

## Prerequisites

- Python 3.10 or higher
- [MISP](https://github.com/MISP/MISP) instance with API access
- API key with appropriate permissions

## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/yourusername/misp-mcp-server.git
   cd misp-mcp-server
   ```

2. Create a virtual environment and install dependencies:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install "mcp[cli]" pymisp
   ```

## Configuration

Set the following environment variables to connect to your MISP instance:

- `MISP_URL` - URL of your MISP instance (e.g., "https://misp.example.com")
- `MISP_API_KEY` - Your MISP API key
- `MISP_VERIFY_SSL` - Whether to verify SSL certificates (True/False)

## Usage

### Running as a standalone server

```bash
python misp_server.py
```

### Testing with MCP Inspector

```bash
mcp dev misp_server.py
```

### Installing in Claude Desktop

Edit your Claude Desktop configuration file:

**macOS:**
```
~/Library/Application Support/Claude/claude_desktop_config.json
```

**Windows:**
```
%APPDATA%\Claude\claude_desktop_config.json
```

Add the MISP MCP server configuration:

```json
{
  "mcpServers": {
    "misp-intelligence": {
      "command": "python",
      "args": ["/path/to/misp_server.py"],
      "env": {
        "MISP_URL": "https://your-misp-instance.com",
        "MISP_API_KEY": "your-api-key-here",
        "MISP_VERIFY_SSL": "True"
      }
    }
  }
}
```

Alternatively, use the MCP CLI:

```bash
mcp install misp_server.py --name "MISP Threat Intelligence" -v MISP_URL=https://your-misp-instance.com -v MISP_API_KEY=your-api-key
```

## Available Tools

### get_mac_malware
Get the latest Mac-related malware samples from MISP.

**Parameters:**
- `days` (default: 30): Number of days to look back
- `limit` (default: 10): Maximum number of results to return

### get_platform_malware
Get the latest malware samples for a specific platform from MISP.

**Parameters:**
- `platform`: Platform to search for (windows, macos, linux, android, ios, iot)
- `days` (default: 30): Number of days to look back
- `limit` (default: 10): Maximum number of results to return

### advanced_search
Perform advanced searches in MISP.

**Parameters:**
- `query_type`: Type of search (attribute_type, tag, threatactor, tlp)
- `query_value`: Value to search for
- `platform` (optional): Platform filter (windows, macos, linux, android, ios, iot)
- `days` (default: 30): Number of days to look back
- `limit` (default: 10): Maximum number of results to return

### submit_ioc
Submit a new Indicator of Compromise (IoC) to MISP.

**Parameters:**
- `ioc_value`: The actual IoC value (e.g., hash, URL, IP)
- `ioc_type`: Type of IoC (e.g., md5, sha256, url, ip-dst, filename)
- `event_info`: Brief description of the event
- `category` (default: "Artifacts dropped"): Category of the attribute
- `platform` (optional): Platform affected (windows, macos, linux, android, ios, iot)
- `tlp` (default: "amber"): Traffic Light Protocol level (white, green, amber, red)
- `comment` (optional): Optional comment for the IoC

### generate_threat_report
Generate a comprehensive threat intelligence report based on MISP data.

**Parameters:**
- `days` (default: 30): Number of days to include in the report
- `platforms` (default: "all"): Comma-separated list of platforms or "all"
- `threat_level` (default: "all"): Filter by threat level (low, medium, high, all)
- `include_stats` (default: True): Whether to include statistics

### search_misp
Search MISP for specific threats.

**Parameters:**
- `query`: Search term (e.g., CVE ID, malware name, hash)
- `days` (default: 30): Number of days to look back

### get_misp_stats
Get statistics about the MISP instance.

## Available Resources

### feeds://recent/{days}
Get information about recent MISP feeds.

**Parameters:**
- `days` (default: 7): Number of days to look back

## Example Queries with Claude

1. "What are the latest Mac-related malware samples?"
2. "Show me Windows malware from the last 2 weeks"
3. "Search for CVE-2023-12345 in MISP"
4. "Submit this IoC to MISP: 1a2b3c4d5e6f7g8h9i0j, type: md5, description: suspicious file found in phishing email"
5. "Generate a threat intelligence report for the last month"
6. "What are the current MISP statistics?"
7. "Get information about recent MISP feeds"
8. "Perform an advanced search for TLP:RED events related to banking trojans"

## Security Considerations

- Use a read-only API key if you don't need to submit IoCs
- Consider network segmentation and proper access controls for your MISP instance
- Be cautious with self-signed certificates (`MISP_VERIFY_SSL=False`)
- Review the logs regularly for unauthorized access attempts

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- [MISP Project](https://github.com/MISP/MISP) for the excellent threat intelligence platform
- [Model Context Protocol](https://modelcontextprotocol.io) for enabling secure LLM integrations
