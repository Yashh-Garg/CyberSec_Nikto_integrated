"""Nikto scanner integration via Docker."""

import docker
import os
import time
import logging
from datetime import datetime
from typing import Dict, Optional, List
from pathlib import Path

logger = logging.getLogger(__name__)


class NiktoScanner:
    """Nikto scanner wrapper using Docker."""
    
    NIKTO_IMAGE = "frapsoft/nikto:latest"  # Using frapsoft/nikto which has nikto.pl directly
    DEFAULT_TIMEOUT = 3600  # 1 hour
    SCAN_RESULTS_DIR = Path("scan_results")
    
    def __init__(self, docker_client: Optional[docker.DockerClient] = None):
        """Initialize Nikto scanner.
        
        Args:
            docker_client: Docker client instance. If None, creates new client.
        """
        if docker_client:
            self.client = docker_client
        else:
            # Try to initialize Docker client with fallback options
            # In Docker container, use the mounted socket
            # On host, use environment or default
            
            # Check if we're in a Docker container (socket should be mounted)
            socket_path = '/var/run/docker.sock'
            is_in_container = os.path.exists(socket_path)
            
            try:
                if is_in_container:
                    # We're in a container, use the mounted Unix socket directly
                    # Don't use docker.from_env() as it may read problematic DOCKER_HOST env vars
                    logger.info("Detected Docker container environment, using Unix socket")
                    # Temporarily unset DOCKER_HOST if it exists to avoid conflicts
                    original_docker_host = os.environ.pop('DOCKER_HOST', None)
                    try:
                        self.client = docker.DockerClient(base_url='unix:///var/run/docker.sock')
                        self.client.ping()
                        logger.info("Successfully connected to Docker via Unix socket")
                    finally:
                        # Restore original DOCKER_HOST if it was set
                        if original_docker_host:
                            os.environ['DOCKER_HOST'] = original_docker_host
                else:
                    # We're on the host, try default (from environment)
                    logger.info("Detected host environment, using default Docker client")
                    self.client = docker.from_env()
                    self.client.ping()
                    logger.info("Successfully connected to Docker via default client")
            except Exception as e:
                logger.warning(f"Failed to connect with primary method: {e}")
                # Try alternative connection methods
                try:
                    # Try unix socket explicitly (for Linux/Mac hosts)
                    logger.info("Trying Unix socket connection...")
                    self.client = docker.DockerClient(base_url='unix:///var/run/docker.sock')
                    self.client.ping()
                    logger.info("Successfully connected via Unix socket")
                except Exception as e2:
                    logger.warning(f"Unix socket failed: {e2}")
                    # Try Windows named pipe (only on Windows host, not in container)
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
                        # Last resort: try TCP (if Docker Desktop exposes it)
                        docker_host = os.environ.get('DOCKER_HOST')
                        if docker_host and docker_host.startswith('tcp://'):
                            logger.info(f"Trying TCP connection to {docker_host}...")
                            self.client = docker.DockerClient(base_url=docker_host)
                            self.client.ping()
                            logger.info("Successfully connected via TCP")
                        else:
                            # For Windows, suggest TCP endpoint
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
        """Execute Nikto scan via Docker container.
        
        Args:
            target: Target hostname or IP address
            port: Target port (default: 80)
            ssl: Use SSL/TLS (default: False)
            options: Additional Nikto options (default: None)
            timeout: Scan timeout in seconds (default: 3600)
            
        Returns:
            Dictionary with scan results and metadata
        """
        scan_id = f"nikto_{int(time.time())}"
        logger.info(f"Starting Nikto scan {scan_id} for {target}:{port}")
        
        try:
            # Pull image if not present
            self._ensure_image()
            
            # Clean target - remove protocol and trailing slashes
            clean_target = target.strip()
            if clean_target.startswith("http://"):
                clean_target = clean_target[7:]
            elif clean_target.startswith("https://"):
                clean_target = clean_target[8:]
            clean_target = clean_target.rstrip("/")
            
            # Build command for frapsoft/nikto
            # frapsoft/nikto uses nikto.pl as entrypoint and -host/-port format
            # Format: nikto.pl -host <target> -port <port> -Format xml -output <file>
            nikto_args = ["-host", clean_target, "-port", str(port)]
            
            # Add format and output
            # Try CSV first as it doesn't require DTD validation
            # If CSV works, we can convert to XML later
            nikto_args.extend(["-Format", "csv"])
            nikto_args.extend(["-output", "/tmp/results/nikto_output.csv"])
            
            # Add display
            nikto_args.extend(["-Display", "V"])
            
            # Handle tuning options
            # Check if tuning is specified in options
            tuning_specified = False
            if options:
                for i, opt in enumerate(options):
                    if opt == "-Tuning" and i + 1 < len(options):
                        tuning_specified = True
                        break
            
            # If no tuning specified, use default (all tests)
            if not tuning_specified:
                nikto_args.extend(["-Tuning", "x"])
            
            # Add SSL if needed
            if ssl:
                nikto_args.append("-ssl")
            
            # Add custom options (filter out conflicting ones)
            if options:
                filtered_options = []
                skip_next = False
                for i, opt in enumerate(options):
                    if skip_next:
                        skip_next = False
                        continue
                    # Skip conflicting options
                    if opt in ["-h", "-host", "-o", "-output", "-Format", "-port", "-Display"]:
                        skip_next = True
                        continue
                    # Include -Tuning and its value
                    if opt == "-Tuning":
                        filtered_options.append(opt)
                        if i + 1 < len(options):
                            filtered_options.append(options[i + 1])
                            skip_next = True
                        continue
                    filtered_options.append(opt)
                nikto_args.extend(filtered_options)
            
            logger.info(f"Running nikto.pl with args: {' '.join(nikto_args)}")
            logger.info(f"Clean target: {clean_target}, Port: {port}")
            
            # frapsoft/nikto has nikto.pl at /usr/bin/nikto.pl
            # Set NIKTO_BASE to /etc/nikto so it can find DTD files
            # Copy DTD to output directory and run nikto from /etc/nikto directory
            # This ensures nikto can find all its files and the DTD for XML validation
            container = self.client.containers.run(
                self.NIKTO_IMAGE,
                command=["/bin/sh", "-c", f"mkdir -p /tmp/results && cp /etc/nikto/docs/nikto.dtd /tmp/results/ 2>/dev/null || true && cd /etc/nikto && export NIKTO_BASE=/etc/nikto && /usr/bin/nikto.pl {' '.join(repr(arg) for arg in nikto_args)}"],
                entrypoint="",  # Override entrypoint to use shell
                detach=True,
                remove=False,
                network_mode="host",  # Allow network access
                environment={"NIKTO_BASE": "/etc/nikto"},  # Set NIKTO base directory
                volumes={
                    str(self.SCAN_RESULTS_DIR.absolute()): {
                        'bind': '/tmp/results',
                        'mode': 'rw'
                    }
                }
            )
            
            logger.info(f"Container {container.id} started for scan {scan_id}")
            
            # Wait for container to complete
            # Add a small delay to ensure nikto has time to start
            time.sleep(2)  # Give nikto time to initialize
            
            wait_result = container.wait(timeout=timeout)
            # Handle both dict (newer docker-py) and int (older) return types
            if isinstance(wait_result, dict):
                exit_code = wait_result.get('StatusCode', 0)
            else:
                exit_code = int(wait_result) if wait_result else 0
            
            logger.info(f"Container exited with code: {exit_code}")
            
            # Get logs before container removal - get all logs, not just recent
            logs = container.logs(stdout=True, stderr=True).decode('utf-8')
            logger.info(f"Container logs length: {len(logs)} chars")
            if len(logs) > 0:
                logger.info(f"Container logs (first 1000 chars): {logs[:1000]}")
                logger.info(f"Container logs (last 500 chars): {logs[-500:]}")
            
            # Parse logs into structured events
            log_events = self._parse_log_events(logs)
            
            # If logs are very short, the scan might have failed immediately
            if len(logs) < 100:
                logger.warning(f"Logs are very short ({len(logs)} chars), scan may have failed immediately")
                # Try to get more detailed error
                try:
                    detailed_logs = container.logs(stdout=True, stderr=True, tail=1000).decode('utf-8')
                    if len(detailed_logs) > len(logs):
                        logs = detailed_logs
                        logger.info(f"Retrieved more detailed logs: {len(logs)} chars")
                except:
                    pass
            
            # Try to read results from mounted volume (not from container)
            xml_output = ""
            try:
                # First try CSV file (we're using CSV format now)
                csv_file = self.SCAN_RESULTS_DIR / "nikto_output.csv"
                if csv_file.exists():
                    csv_content = csv_file.read_text(encoding='utf-8')
                    if csv_content.strip():
                        logger.info(f"Found CSV file, size: {len(csv_content)} chars")
                        # Convert CSV to XML
                        xml_output = self._convert_csv_to_xml(csv_content, clean_target, port)
                        logger.info(f"Converted CSV to XML, size: {len(xml_output)} chars")
                        
                        # Keep a copy of CSV for reference (with scan ID in filename)
                        csv_backup = self.SCAN_RESULTS_DIR / f"nikto_{scan_id}_output.csv"
                        try:
                            csv_backup.write_text(csv_content, encoding='utf-8')
                            logger.info(f"CSV backup saved to {csv_backup}")
                        except Exception as e:
                            logger.warning(f"Failed to save CSV backup: {e}")
                
                # If CSV didn't work, try XML file
                if not xml_output or xml_output.strip() == '':
                    output_file = self.SCAN_RESULTS_DIR / "nikto_output.xml"
                    if output_file.exists():
                        xml_output = output_file.read_text(encoding='utf-8')
                        logger.info(f"Found XML file, size: {len(xml_output)} chars")
                
                # If file doesn't exist or is empty, try to find any XML file
                if not xml_output or xml_output.strip() == '':
                    xml_files = list(self.SCAN_RESULTS_DIR.glob("*.xml"))
                    for xml_file in xml_files:
                        if xml_file.name != "nikto.dtd":  # Skip DTD file
                            content = xml_file.read_text(encoding='utf-8')
                            if content.strip():
                                xml_output = content
                                logger.info(f"Found XML file {xml_file.name}, size: {len(xml_output)} chars")
                                break
                
                # If still empty, try to extract from logs
                if not xml_output or xml_output.strip() == '':
                    logger.warning("No XML file found in volume, trying to extract from logs")
                    xml_output = self._extract_xml_from_logs(logs)
                    
                # If still empty but scan seems to have run (has findings in logs), create minimal XML
                if not xml_output or xml_output.strip() == '':
                    # Check if scan actually ran by looking for findings in logs
                    # Look for various indicators that nikto ran
                    scan_indicators = ["Target IP:", "+ ", "Server:", "Retrieved", "200 for", "404 for", "403 for"]
                    has_scan_output = any(indicator in logs for indicator in scan_indicators)
                    
                    if has_scan_output:
                        logger.warning("XML output empty but scan appears to have run. Creating XML from logs.")
                        logger.info(f"Logs contain scan indicators. Full logs length: {len(logs)}")
                        xml_output = self._create_xml_from_logs(logs, clean_target, port)
                        if xml_output:
                            logger.info(f"Created XML from logs, length: {len(xml_output)} chars")
                    
                    if not xml_output or xml_output.strip() == '':
                        logger.error(f"Empty XML output. Logs length: {len(logs)}")
                        logger.error(f"Logs preview: {logs[:1000]}")
                        logger.error(f"Results directory contents: {list(self.SCAN_RESULTS_DIR.iterdir())}")
                        logger.error(f"Exit code: {exit_code}")
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
                    # Try creating XML from logs as last resort
                    if "Target IP:" in logs or "+ " in logs:
                        xml_output = self._create_xml_from_logs(logs, clean_target, port)
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
                "logs": logs,
                "log_events": log_events,  # Structured log events
                "output_format": "xml"  # Always return as XML for consistency
            }
            
        except docker.errors.ContainerError as e:
            logger.error(f"Container error: {e}")
            raise Exception(f"Scan failed: {e}")
        except docker.errors.ImageNotFound:
            logger.error(f"Image {self.NIKTO_IMAGE} not found")
            raise Exception(f"Docker image {self.NIKTO_IMAGE} not available")
        except Exception as e:
            logger.error(f"Unexpected error during scan: {e}")
            raise
    
    def _ensure_image(self):
        """Ensure Nikto Docker image is available."""
        try:
            self.client.images.get(self.NIKTO_IMAGE)
            logger.debug(f"Image {self.NIKTO_IMAGE} already present")
        except docker.errors.ImageNotFound:
            logger.info(f"Pulling image {self.NIKTO_IMAGE}")
            self.client.images.pull(self.NIKTO_IMAGE)
    
    def _extract_xml_from_logs(self, logs: str) -> str:
        """Extract XML output from container logs if available."""
        # Nikto may output XML in logs
        # Try to find XML content between tags
        import re
        
        # Try to find complete XML structure
        xml_match = re.search(r'<niktoscan>.*</niktoscan>', logs, re.DOTALL)
        if xml_match:
            return xml_match.group(0)
        
        # Try to find XML declaration and root
        xml_match = re.search(r'<\?xml.*?<niktoscan>.*?</niktoscan>', logs, re.DOTALL)
        if xml_match:
            return xml_match.group(0)
        
        # If no XML found, log what we have
        logger.warning(f"No XML found in logs. Logs contain: {logs[:200]}")
        return ""
    
    def _create_xml_from_logs(self, logs: str, target: str, port: int) -> str:
        """Create minimal XML from nikto text output when XML generation fails."""
        import re
        
        # Extract findings from logs (lines starting with "+ ")
        findings = []
        for line in logs.split('\n'):
            if line.strip().startswith('+ ') and not line.strip().startswith('+ Target'):
                # This is a finding
                finding_text = line.strip()[2:]  # Remove "+ "
                if finding_text and len(finding_text) > 5:  # Ignore very short lines
                    findings.append(finding_text)
        
        # Create minimal XML structure
        xml_parts = ['<?xml version="1.0"?>', '<niktoscan>']
        xml_parts.append(f'<scandata targetip="{target}" targethostname="{target}" targetport="{port}" />')
        
        for i, finding in enumerate(findings[:100], 1):  # Limit to 100 findings
            xml_parts.append(f'<item id="{i}">')
            xml_parts.append(f'<description>{self._escape_xml(finding)}</description>')
            xml_parts.append(f'<uri>/</uri>')
            xml_parts.append('</item>')
        
        xml_parts.append('</niktoscan>')
        
        return '\n'.join(xml_parts)
    
    def _convert_csv_to_xml(self, csv_content: str, target: str, port: int) -> str:
        """Convert Nikto CSV output to XML format."""
        import csv
        import io
        
        xml_parts = ['<?xml version="1.0"?>', '<niktoscan>']
        xml_parts.append(f'<scandata targetip="{target}" targethostname="{target}" targetport="{port}" />')
        
        # Parse CSV
        csv_reader = csv.DictReader(io.StringIO(csv_content))
        item_id = 1
        
        for row in csv_reader:
            # Skip empty rows
            if not row or not any(row.values()):
                continue
            
            # Extract fields (CSV columns may vary, common ones: Host, Port, Path, Method, Description, etc.)
            description = row.get('Description', row.get('description', ''))
            uri = row.get('Path', row.get('path', row.get('URI', row.get('uri', '/'))))
            method = row.get('Method', row.get('method', 'GET'))
            osvdb = row.get('OSVDB', row.get('osvdb', ''))
            
            # Skip metadata lines
            if self._is_metadata_line(description):
                continue
            
            # Create XML item
            xml_parts.append(f'<item id="{item_id}" osvdb="{osvdb}">')
            xml_parts.append(f'<description>{self._escape_xml(description)}</description>')
            xml_parts.append(f'<uri>{self._escape_xml(uri)}</uri>')
            xml_parts.append(f'<namelink>{self._escape_xml(method)}</namelink>')
            xml_parts.append('</item>')
            item_id += 1
        
        xml_parts.append('</niktoscan>')
        return '\n'.join(xml_parts)
    
    def _is_metadata_line(self, text: str) -> bool:
        """Check if a line is metadata (not a real finding)."""
        if not text:
            return True
        
        text_lower = text.lower()
        metadata_patterns = [
            'start time:', 'end time:', 'target ip:', 'target hostname:',
            'target port:', 'host(s) tested', 'items checked:', 'error(s)',
            'item(s) reported', 'server:', 'retrieved x-powered-by header:',
            'nikto v', 'scan started', 'scan ended'
        ]
        
        return any(pattern in text_lower for pattern in metadata_patterns)
    
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
            if "+ " in line:
                event["type"] = "finding"
                event["finding"] = line.replace("+ ", "").strip()
            elif "Target IP:" in line or "Target hostname:" in line:
                event["type"] = "target_info"
            elif "items checked:" in line_lower:
                event["type"] = "progress"
            elif "Start Time:" in line:
                event["type"] = "scan_start"
            elif "End Time:" in line:
                event["type"] = "scan_end"
            
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

