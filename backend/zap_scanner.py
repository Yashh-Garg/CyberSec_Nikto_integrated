"""OWASP ZAP scanner integration via Docker."""

import docker
import os
import time
import logging
import json
from datetime import datetime
from typing import Dict, Optional, List
from pathlib import Path

logger = logging.getLogger(__name__)


class ZapScanner:
    """OWASP ZAP scanner wrapper using Docker."""
    
    ZAP_IMAGE = "ghcr.io/zaproxy/zaproxy:stable"  # Official OWASP ZAP Docker image
    DEFAULT_TIMEOUT = 3600  # 1 hour
    SCAN_RESULTS_DIR = Path("scan_results")
    
    def __init__(self, docker_client: Optional[docker.DockerClient] = None):
        """Initialize ZAP scanner.
        
        Args:
            docker_client: Docker client instance. If None, creates new client.
        """
        if docker_client:
            self.client = docker_client
        else:
            # Try to initialize Docker client with fallback options
            socket_path = '/var/run/docker.sock'
            is_in_container = os.path.exists(socket_path)
            
            try:
                if is_in_container:
                    logger.info("Detected Docker container environment, using Unix socket")
                    original_docker_host = os.environ.pop('DOCKER_HOST', None)
                    try:
                        self.client = docker.DockerClient(base_url='unix:///var/run/docker.sock')
                        self.client.ping()
                        logger.info("Successfully connected to Docker via Unix socket")
                    finally:
                        if original_docker_host:
                            os.environ['DOCKER_HOST'] = original_docker_host
                else:
                    logger.info("Detected host environment, using default Docker client")
                    self.client = docker.from_env()
                    self.client.ping()
                    logger.info("Successfully connected to Docker via default client")
            except Exception as e:
                logger.warning(f"Failed to connect with primary method: {e}")
                try:
                    logger.info("Trying Unix socket connection...")
                    self.client = docker.DockerClient(base_url='unix:///var/run/docker.sock')
                    self.client.ping()
                    logger.info("Successfully connected via Unix socket")
                except Exception as e2:
                    logger.warning(f"Unix socket failed: {e2}")
                    if os.name == 'nt' and not is_in_container:
                        try:
                            logger.info("Trying Windows named pipe...")
                            self.client = docker.DockerClient(base_url='npipe:////./pipe/docker_engine')
                            self.client.ping()
                            logger.info("Successfully connected via Windows named pipe")
                        except Exception as e3:
                            logger.warning(f"Windows named pipe failed: {e3}")
                            raise
                    else:
                        docker_host = os.environ.get('DOCKER_HOST')
                        if docker_host and docker_host.startswith('tcp://'):
                            logger.info(f"Trying TCP connection to {docker_host}...")
                            self.client = docker.DockerClient(base_url=docker_host)
                            self.client.ping()
                            logger.info("Successfully connected via TCP")
                        else:
                            error_msg = (
                                "Cannot connect to Docker. Please ensure Docker is running.\n"
                                "For Windows:\n"
                                "1. Open Docker Desktop → Settings → General\n"
                                "2. Enable 'Expose daemon on tcp://localhost:2375 without TLS'\n"
                                "3. Restart Docker Desktop\n"
                                "4. Use: docker-compose -f docker-compose.windows.yml up -d\n"
                                "Or use WSL2 backend in Docker Desktop settings."
                            )
                            raise Exception(error_msg)
        self.SCAN_RESULTS_DIR.mkdir(exist_ok=True)
        
    def scan(
        self,
        target: str,
        port: int = 80,
        ssl: bool = False,
        options: Optional[List[str]] = None,
        timeout: int = DEFAULT_TIMEOUT
    ) -> Dict:
        """Execute ZAP scan via Docker container.
        
        Args:
            target: Target hostname or IP address
            port: Target port (default: 80)
            ssl: Use SSL/TLS (default: False)
            options: Additional ZAP options (default: None)
            timeout: Scan timeout in seconds (default: 3600)
            
        Returns:
            Dictionary with scan results and metadata
        """
        scan_id = f"zap_{int(time.time())}"
        logger.info(f"Starting ZAP scan {scan_id} for {target}:{port}")
        
        try:
            # Pull image if not present
            self._ensure_image()
            
            # Clean target - remove protocol and port if present
            clean_target = target.strip()
            original_target = clean_target
            
            # Remove protocol if present
            if clean_target.startswith("http://"):
                clean_target = clean_target[7:]
                ssl = False  # Override ssl flag if http:// is in target
            elif clean_target.startswith("https://"):
                clean_target = clean_target[8:]
                ssl = True  # Override ssl flag if https:// is in target
            
            # Remove trailing slash
            clean_target = clean_target.rstrip("/")
            
            # Remove port if present in target (format: hostname:port)
            if ":" in clean_target:
                parts = clean_target.rsplit(":", 1)
                if parts[1].isdigit():
                    clean_target = parts[0]
                    # Port in URL takes precedence
                    port = int(parts[1])
            
            # Build target URL with proper protocol
            # Fix port/protocol mismatch: HTTPS should use 443, HTTP should use 80
            if ssl:
                # If SSL is selected but port is 80, use 443 instead
                if port == 80:
                    port = 443
                protocol = "https"
            else:
                # If HTTP is selected but port is 443, use 80 instead
                if port == 443:
                    port = 80
                protocol = "http"
            
            # Only add port if it's not the default port for the protocol
            if (ssl and port == 443) or (not ssl and port == 80):
                target_url = f"{protocol}://{clean_target}"
            else:
                target_url = f"{protocol}://{clean_target}:{port}"
            
            # ZAP command: zap-baseline.py or zap-full-scan.py
            # Using zap-baseline.py for faster scans (can be changed to zap-full-scan.py for comprehensive)
            scan_type = "baseline"
            if options:
                for i, opt in enumerate(options):
                    if opt == "-t" or opt == "--scan-type":
                        if i + 1 < len(options):
                            scan_type = options[i + 1].lower()
                            break
                    elif opt in ["full", "baseline", "quick"]:
                        scan_type = opt.lower()
                        break
            
            # Determine scan script
            if scan_type == "full":
                zap_script = "zap-full-scan.py"
            elif scan_type == "quick":
                zap_script = "zap-quick-scan.py"
            else:
                zap_script = "zap-baseline.py"
            
            # Build ZAP command
            # ZAP baseline scripts use: -J for JSON (uppercase), -x for XML, -r for HTML
            # Output files go to /zap/wrk directory
            zap_args = [
                zap_script,
                "-t", target_url,
                "-J", "/zap/wrk/zap_report.json",  # JSON report (uppercase -J)
                "-x", "/zap/wrk/zap_report.xml",    # XML report
                "-r", "/zap/wrk/zap_report.html"    # HTML report (optional, for reference)
            ]
            
            # Add additional options
            if options:
                filtered_options = []
                skip_next = False
                for i, opt in enumerate(options):
                    if skip_next:
                        skip_next = False
                        continue
                    # Skip conflicting options
                    if opt in ["-t", "--target", "-J", "-j", "-x", "-r", "-w", "--json", "--xml", "--html"]:
                        skip_next = True
                        continue
                    filtered_options.append(opt)
                zap_args.extend(filtered_options)
            
            logger.info(f"Running ZAP with command: {' '.join(zap_args)}")
            logger.info(f"Target URL: {target_url}")
            
            # Run ZAP in Docker container
            # ZAP needs /zap/wrk directory mounted for output files
            container = self.client.containers.run(
                self.ZAP_IMAGE,
                command=zap_args,
                detach=True,
                remove=False,
                network_mode="host",  # Allow network access
                volumes={
                    str(self.SCAN_RESULTS_DIR.absolute()): {
                        'bind': '/zap/wrk',  # ZAP expects /zap/wrk for output files
                        'mode': 'rw'
                    }
                }
            )
            
            logger.info(f"Container {container.id} started for scan {scan_id}")
            
            # Wait for container to complete
            time.sleep(2)  # Give ZAP time to initialize
            
            wait_result = container.wait(timeout=timeout)
            if isinstance(wait_result, dict):
                exit_code = wait_result.get('StatusCode', 0)
            else:
                exit_code = int(wait_result) if wait_result else 0
            
            logger.info(f"Container exited with code: {exit_code}")
            
            # Get logs - get ALL logs, not just tail
            logs = container.logs(stdout=True, stderr=True).decode('utf-8')
            logger.info(f"Container logs length: {len(logs)} chars")
            if len(logs) > 0:
                logger.info(f"Container logs (first 1000 chars): {logs[:1000]}")
                logger.info(f"Container logs (last 500 chars): {logs[-500:]}")
                # Also log a sample from the middle to see warnings
                if len(logs) > 2000:
                    middle_start = len(logs) // 2
                    logger.info(f"Container logs (middle 500 chars): {logs[middle_start:middle_start+500]}")
            
            # Parse logs into structured events
            log_events = self._parse_log_events(logs)
            
            # Try to read results from mounted volume
            xml_output = ""
            json_output = ""
            
            try:
                # List all files in results directory for debugging
                result_files = list(self.SCAN_RESULTS_DIR.glob("*"))
                logger.info(f"Files in results directory: {[f.name for f in result_files]}")
                
                # Try XML file first (files are in /zap/wrk which is mounted to SCAN_RESULTS_DIR)
                xml_file = self.SCAN_RESULTS_DIR / "zap_report.xml"
                if xml_file.exists():
                    xml_output = xml_file.read_text(encoding='utf-8')
                    logger.info(f"Found XML file, size: {len(xml_output)} chars")
                else:
                    # Try to find any XML file with 'zap' in the name (but exclude scan_*.xml files)
                    xml_files = [
                        f for f in self.SCAN_RESULTS_DIR.glob("*zap*.xml")
                        if not f.name.startswith("scan_")
                    ]
                    if xml_files:
                        xml_file = xml_files[0]
                        xml_output = xml_file.read_text(encoding='utf-8')
                        logger.info(f"Found XML file {xml_file.name}, size: {len(xml_output)} chars")
                
                # Try JSON file (only look for actual ZAP report files, not scan result files)
                json_file = self.SCAN_RESULTS_DIR / "zap_report.json"
                if json_file.exists():
                    json_output = json_file.read_text(encoding='utf-8')
                    logger.info(f"Found JSON file, size: {len(json_output)} chars")
                else:
                    # Try to find any JSON file with 'zap' in the name (but exclude scan_*.json files)
                    json_files = [
                        f for f in self.SCAN_RESULTS_DIR.glob("*zap*.json")
                        if not f.name.startswith("scan_") and not f.name.startswith("Latest_")
                    ]
                    if json_files:
                        json_file = json_files[0]
                        json_output = json_file.read_text(encoding='utf-8')
                        logger.info(f"Found JSON file {json_file.name}, size: {len(json_output)} chars")
                
                # If no XML but have JSON, convert JSON to XML
                if not xml_output and json_output:
                    logger.info("Converting JSON to XML format")
                    xml_output = self._convert_json_to_xml(json_output, clean_target, port)
                
                # If still no output, try to extract from logs
                if not xml_output:
                    logger.warning("No XML file found, trying to extract from logs")
                    xml_output = self._extract_xml_from_logs(logs)
                
                # If still empty, create minimal XML from logs
                if not xml_output or xml_output.strip() == '':
                    if "ZAP" in logs or "Alert" in logs or "alerts" in logs.lower():
                        logger.warning("XML output empty but scan appears to have run. Creating XML from logs.")
                        xml_output = self._create_xml_from_logs(logs, clean_target, port, target_url)
                        if xml_output:
                            logger.info(f"Created XML from logs, length: {len(xml_output)} chars")
                    
                    if not xml_output or xml_output.strip() == '':
                        logger.error(f"Empty XML output. Logs length: {len(logs)}")
                        raise Exception(
                            f"Scan completed but no XML output was generated. "
                            f"Exit code: {exit_code}. "
                            f"Check logs for details. "
                            f"Logs: {logs[:500]}"
                        )
                else:
                    logger.info(f"Successfully extracted XML, length: {len(xml_output)}")
                    
            except Exception as e:
                logger.warning(f"Could not read results file: {e}", exc_info=True)
                xml_output = self._extract_xml_from_logs(logs)
                if not xml_output or xml_output.strip() == '':
                    if "ZAP" in logs or "Alert" in logs:
                        xml_output = self._create_xml_from_logs(logs, clean_target, port, target_url)
                    if not xml_output or xml_output.strip() == '':
                        raise Exception(
                            f"Failed to extract XML output from scan. "
                            f"Exit code: {exit_code}. "
                            f"Error: {str(e)}. "
                            f"Logs: {logs[:500]}"
                        )
            
            # Clean up container
            container.remove()
            
            return {
                "scan_id": scan_id,
                "target": target,
                "port": port,
                "ssl": ssl,
                "exit_code": exit_code,
                "raw_output": xml_output,
                "json_output": json_output,  # Also include JSON if available
                "logs": logs,
                "log_events": log_events,
                "output_format": "xml"  # Always return as XML for consistency
            }
            
        except docker.errors.ContainerError as e:
            logger.error(f"Container error: {e}")
            raise Exception(f"Scan failed: {e}")
        except docker.errors.ImageNotFound:
            logger.error(f"Image {self.ZAP_IMAGE} not found")
            raise Exception(f"Docker image {self.ZAP_IMAGE} not available")
        except Exception as e:
            logger.error(f"Unexpected error during scan: {e}")
            raise
    
    def _ensure_image(self):
        """Ensure ZAP Docker image is available."""
        try:
            self.client.images.get(self.ZAP_IMAGE)
            logger.debug(f"Image {self.ZAP_IMAGE} already present")
        except docker.errors.ImageNotFound:
            logger.info(f"Pulling image {self.ZAP_IMAGE}")
            self.client.images.pull(self.ZAP_IMAGE)
    
    def _extract_xml_from_logs(self, logs: str) -> str:
        """Extract XML output from container logs if available."""
        import re
        
        # Try to find complete XML structure
        xml_match = re.search(r'<OWASPZAPReport>.*</OWASPZAPReport>', logs, re.DOTALL)
        if xml_match:
            return xml_match.group(0)
        
        # Try to find XML declaration and root
        xml_match = re.search(r'<\?xml.*?<OWASPZAPReport>.*?</OWASPZAPReport>', logs, re.DOTALL)
        if xml_match:
            return xml_match.group(0)
        
        logger.warning(f"No XML found in logs. Logs contain: {logs[:200]}")
        return ""
    
    def _create_xml_from_logs(self, logs: str, target: str, port: int, target_url: str) -> str:
        """Create XML from ZAP text output when XML generation fails."""
        import re
        
        # Parse ZAP summary line: "FAIL-NEW: 0	FAIL-INPROG: 0	WARN-NEW: 26	WARN-INPROG: 0	INFO: 0	IGNORE: 0	PASS: 41"
        # Try multiple patterns to catch the summary line
        summary_patterns = [
            r'FAIL-NEW:\s*(\d+).*?WARN-NEW:\s*(\d+)',  # FAIL first, then WARN
            r'WARN-NEW:\s*(\d+).*?FAIL-NEW:\s*(\d+)',  # WARN first, then FAIL
            r'WARN-NEW:\s*(\d+)',  # Just WARN
            r'FAIL-NEW:\s*(\d+)',  # Just FAIL
        ]
        
        warn_count = 0
        fail_count = 0
        
        for pattern in summary_patterns:
            summary_match = re.search(pattern, logs)
            if summary_match:
                if len(summary_match.groups()) == 2:
                    # Both FAIL and WARN found
                    if 'FAIL-NEW:' in summary_match.group(0) and 'WARN-NEW:' in summary_match.group(0):
                        # Determine order
                        if summary_match.group(0).find('FAIL-NEW') < summary_match.group(0).find('WARN-NEW'):
                            fail_count = int(summary_match.group(1))
                            warn_count = int(summary_match.group(2))
                        else:
                            warn_count = int(summary_match.group(1))
                            fail_count = int(summary_match.group(2))
                    else:
                        warn_count = int(summary_match.group(1)) if 'WARN' in pattern else 0
                        fail_count = int(summary_match.group(2)) if len(summary_match.groups()) > 1 else 0
                elif len(summary_match.groups()) == 1:
                    if 'WARN' in pattern:
                        warn_count = int(summary_match.group(1))
                    elif 'FAIL' in pattern:
                        fail_count = int(summary_match.group(1))
                break
        
        logger.info(f"Parsed ZAP summary: {warn_count} warnings, {fail_count} failures")
        
        # Extract findings from logs
        findings = []
        
        # Pattern 1: ZAP alert format with plugin ID: "WARN-NEW: Alert Name [10040]"
        # Pattern 2: "PASS: Alert Name [10040]" or "FAIL: Alert Name [10040]"
        # Pattern 3: Lines with plugin IDs in brackets: "Alert Name [10040]"
        # Pattern 4: Just look for lines with WARN/FAIL and plugin IDs
        alert_patterns = [
            r'(WARN-NEW|FAIL-NEW|INFO-NEW|WARN|FAIL):\s*([^[]+?)\s*\[(\d+)\]',  # "WARN-NEW: Alert Name [10040]"
            r'\[(\d+)\]\s*(.+)',  # "[10040] Alert Name"
            r'(High|Medium|Low|Informational):\s*(.+?)(?:\s*\[(\d+)\])?',  # "Medium: Alert Name [10040]"
        ]
        
        # Also search for WARN/FAIL keywords in the logs
        warn_fail_lines = [line for line in logs.split('\n') if 'WARN' in line.upper() or 'FAIL' in line.upper()]
        if warn_fail_lines:
            logger.info(f"Found {len(warn_fail_lines)} lines containing WARN/FAIL keywords")
            # Log first few for debugging
            for line in warn_fail_lines[:5]:
                logger.info(f"WARN/FAIL line: {line[:200]}")
        
        seen_plugin_ids = set()
        
        for line in logs.split('\n'):
            line = line.strip()
            if not line:
                continue
            
            # Skip summary lines and metadata
            if 'FAIL-NEW:' in line and 'WARN-NEW:' in line:
                continue
            if line.startswith('Total of') or line.startswith('Using the') or line.startswith('Automation'):
                continue
            
            # Try each pattern
            for pattern in alert_patterns:
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    if len(match.groups()) >= 2:
                        # Extract plugin ID and alert name
                        if 'WARN-NEW' in line or 'FAIL-NEW' in line:
                            severity = 'WARN-NEW' if 'WARN-NEW' in line else 'FAIL-NEW'
                            alert_name = match.group(2).strip()
                            plugin_id = match.group(3) if len(match.groups()) >= 3 else str(len(findings) + 1)
                        elif match.lastindex >= 2:
                            plugin_id = match.group(1) if match.lastindex >= 1 else str(len(findings) + 1)
                            alert_name = match.group(2).strip() if match.lastindex >= 2 else line
                            severity = 'WARN-NEW'  # Default
                        else:
                            continue
                        
                        # Avoid duplicates
                        if plugin_id in seen_plugin_ids:
                            continue
                        seen_plugin_ids.add(plugin_id)
                        
                        if alert_name and len(alert_name) > 3:
                            findings.append({
                                'pluginid': plugin_id,
                                'name': alert_name,
                                'severity': severity,
                                'line': line
                            })
                    break
        
        # If we found a summary but no individual findings, create findings from the summary
        if (warn_count > 0 or fail_count > 0) and len(findings) == 0:
            logger.warning(f"Found {warn_count} warnings and {fail_count} failures in summary but couldn't parse individual alerts from logs")
            logger.info(f"Creating {warn_count + fail_count} findings from summary counts")
            # Create placeholder findings - these will be generic but at least show the count
            for i in range(fail_count):
                findings.append({
                    'pluginid': str(9000 + i),
                    'name': f'ZAP High Risk Finding {i+1} (from scan summary)',
                    'severity': 'FAIL-NEW',
                    'line': 'High risk finding detected by ZAP baseline scan'
                })
            for i in range(warn_count):
                findings.append({
                    'pluginid': str(10000 + i),
                    'name': f'ZAP Warning {i+1} (from scan summary)',
                    'severity': 'WARN-NEW',
                    'line': 'Warning detected by ZAP baseline scan'
                })
        
        logger.info(f"Extracted {len(findings)} findings from ZAP logs")
        
        # Create XML structure
        xml_parts = ['<?xml version="1.0"?>', '<OWASPZAPReport>']
        xml_parts.append(f'<site name="{target_url}" host="{target}" port="{port}">')
        
        for finding in findings[:200]:  # Limit to 200 findings
            plugin_id = finding.get('pluginid', '0')
            name = finding.get('name', 'ZAP Finding')
            severity = finding.get('severity', 'WARN-NEW')
            
            # Map severity to risk code
            risk_code = "3" if "FAIL" in severity else "2"  # High for FAIL, Medium for WARN
            
            xml_parts.append('<alertitem>')
            xml_parts.append(f'<pluginid>{self._escape_xml(plugin_id)}</pluginid>')
            xml_parts.append(f'<alert>{self._escape_xml(name)}</alert>')
            xml_parts.append(f'<name>{self._escape_xml(name)}</name>')
            xml_parts.append(f'<riskcode>{risk_code}</riskcode>')
            xml_parts.append(f'<confidence>2</confidence>')  # Default to Medium
            xml_parts.append(f'<uri>{self._escape_xml(target_url)}</uri>')
            xml_parts.append(f'<description>{self._escape_xml(finding.get("line", name))}</description>')
            xml_parts.append('</alertitem>')
        
        xml_parts.append('</site>')
        xml_parts.append('</OWASPZAPReport>')
        
        return '\n'.join(xml_parts)
    
    def _convert_json_to_xml(self, json_content: str, target: str, port: int) -> str:
        """Convert ZAP JSON output to XML format."""
        try:
            data = json.loads(json_content)
            
            xml_parts = ['<?xml version="1.0"?>', '<OWASPZAPReport>']
            
            # ZAP JSON structure: {"@version": "...", "site": [...]}
            sites = []
            if isinstance(data, dict):
                if 'site' in data:
                    sites = data['site'] if isinstance(data['site'], list) else [data['site']]
                elif 'sites' in data:
                    sites = data['sites'] if isinstance(data['sites'], list) else [data['sites']]
            elif isinstance(data, list):
                sites = data
            
            for site in sites:
                site_name = site.get('@name', f"http://{target}:{port}")
                xml_parts.append(f'<site name="{self._escape_xml(site_name)}" host="{target}" port="{port}">')
                
                alerts = site.get('alerts', [])
                if not isinstance(alerts, list):
                    alerts = [alerts] if alerts else []
                
                for alert in alerts:
                    xml_parts.append('<alertitem>')
                    xml_parts.append(f'<pluginid>{alert.get("pluginid", "")}</pluginid>')
                    xml_parts.append(f'<alert>{self._escape_xml(alert.get("alert", ""))}</alert>')
                    xml_parts.append(f'<name>{self._escape_xml(alert.get("name", ""))}</name>')
                    xml_parts.append(f'<riskcode>{self._map_risk_to_code(alert.get("risk", "Medium"))}</riskcode>')
                    xml_parts.append(f'<confidence>{self._map_confidence_to_code(alert.get("confidence", "Medium"))}</confidence>')
                    xml_parts.append(f'<uri>{self._escape_xml(alert.get("uri", site_name))}</uri>')
                    xml_parts.append(f'<description>{self._escape_xml(alert.get("description", ""))}</description>')
                    xml_parts.append('</alertitem>')
                
                xml_parts.append('</site>')
            
            xml_parts.append('</OWASPZAPReport>')
            return '\n'.join(xml_parts)
        except Exception as e:
            logger.warning(f"Failed to convert JSON to XML: {e}")
            return ""
    
    def _map_risk_to_code(self, risk: str) -> str:
        """Map ZAP risk level to risk code."""
        risk_map = {
            "Informational": "0",
            "Low": "1",
            "Medium": "2",
            "High": "3",
            "Critical": "4"
        }
        return risk_map.get(risk, "2")  # Default to Medium
    
    def _map_confidence_to_code(self, confidence: str) -> str:
        """Map ZAP confidence level to confidence code."""
        confidence_map = {
            "False Positive": "0",
            "Low": "1",
            "Medium": "2",
            "High": "3",
            "Confirmed": "4"
        }
        return confidence_map.get(confidence, "2")  # Default to Medium
    
    def _parse_log_events(self, logs: str) -> List[Dict]:
        """Parse raw logs into structured events."""
        events = []
        if not logs:
            return events
        
        lines = logs.split('\n')
        for i, line in enumerate(lines):
            line = line.strip()
            if not line:
                continue
            
            event = {
                "line_number": i + 1,
                "timestamp": datetime.now().isoformat(),
                "message": line,
                "level": "INFO"
            }
            
            # Classify log level
            line_lower = line.lower()
            if "error" in line_lower or "failed" in line_lower:
                event["level"] = "ERROR"
            elif "warning" in line_lower or "warn" in line_lower:
                event["level"] = "WARNING"
            elif "debug" in line_lower:
                event["level"] = "DEBUG"
            
            # Extract key information
            if "alert" in line_lower:
                event["type"] = "alert"
            elif "scan" in line_lower and "start" in line_lower:
                event["type"] = "scan_start"
            elif "scan" in line_lower and ("complete" in line_lower or "end" in line_lower):
                event["type"] = "scan_end"
            elif "spider" in line_lower:
                event["type"] = "spider"
            elif "active scan" in line_lower:
                event["type"] = "active_scan"
            
            events.append(event)
        
        return events
    
    def _escape_xml(self, text: str) -> str:
        """Escape XML special characters."""
        if not text:
            return ''
        return (text.replace('&', '&amp;')
                   .replace('<', '&lt;')
                   .replace('>', '&gt;')
                   .replace('"', '&quot;')
                   .replace("'", '&apos;'))

