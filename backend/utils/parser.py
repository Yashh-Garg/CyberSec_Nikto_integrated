"""Result parser and normalizer for scanner outputs."""

import json
import logging
import xml.etree.ElementTree as ET
from dataclasses import dataclass, asdict
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone, timedelta

# Initialize logger first
logger = logging.getLogger(__name__)

# Import CVE lookup (optional - will gracefully fail if requests not available)
try:
    from utils.cve_lookup import CVELookup
    CVE_LOOKUP_AVAILABLE = True
except ImportError:
    CVE_LOOKUP_AVAILABLE = False
    logger.warning("CVE lookup not available (requests library may be missing)")

def get_local_time():
    """Get current time in local timezone (IST/Kolkata)."""
    try:
        local_tz = datetime.now().astimezone().tzinfo
        return datetime.now(local_tz)
    except:
        # Default to IST (UTC+5:30) if system timezone not available
        ist = timezone(timedelta(hours=5, minutes=30))
        return datetime.now(ist)

logger = logging.getLogger(__name__)


@dataclass
class Vulnerability:
    """Normalized vulnerability data structure."""
    id: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    title: str
    description: str
    affected_component: str
    uri: Optional[str] = None
    method: Optional[str] = None
    cve_ids: List[str] = None
    osvdb_id: Optional[str] = None
    cvss_score: Optional[float] = None
    remediation: Optional[str] = None
    cve_details: List[Dict] = None
    scanner: str = "nikto"
    
    def __post_init__(self):
        if self.cve_ids is None:
            self.cve_ids = []
        if self.cve_details is None:
            self.cve_details = []


class NiktoParser:
    """Parser for Nikto XML/JSON output."""
    
    @staticmethod
    def parse_xml(xml_content: str) -> List[Vulnerability]:
        """Parse Nikto XML output into normalized vulnerabilities."""
        vulnerabilities = []
        
        # Check if XML content is empty or just whitespace
        if not xml_content or not xml_content.strip():
            logger.warning("Empty XML content provided")
            return vulnerabilities
        
        try:
            root = ET.fromstring(xml_content)
            
            # Nikto XML structure: <niktoscan><item>...</item></niktoscan>
            for item in root.findall('.//item'):
                # Extract Nikto item attributes
                item_id = item.get('id', '')
                osvdb_id = item.get('osvdb', '')
                
                # Extract description
                description_elem = item.find('description')
                description = description_elem.text if description_elem is not None else ''
                
                # Skip metadata lines
                if NiktoParser._is_metadata_line(description):
                    continue
                
                # Extract URI - try to get from URI element, or extract from description
                uri_elem = item.find('uri')
                uri = uri_elem.text if uri_elem is not None else ''
                
                # If URI is missing or just '/', try to extract from description
                if not uri or uri == '/':
                    uri = NiktoParser._extract_uri_from_description(description)
                
                # Extract method
                method_elem = item.find('namelink')
                method = method_elem.text if method_elem is not None else 'GET'
                
                # Determine severity (Nikto doesn't provide explicit severity)
                # We'll classify based on common patterns
                severity = NiktoParser._classify_severity(description, osvdb_id)
                
                # Extract CVE IDs from description if present
                cve_ids = NiktoParser._extract_cves(description)
                cve_details = []
                cvss_score = None
                remediation = None
                
                # Enrich with CVE lookup if available
                if CVE_LOOKUP_AVAILABLE:
                    try:
                        enriched_data = CVELookup.enrich_with_cves(description, osvdb_id, uri)
                        # Merge CVE IDs
                        cve_ids.extend(enriched_data.get("cve_ids", []))
                        cve_ids = list(set(cve_ids))  # Remove duplicates
                        # Get CVE details
                        cve_details = enriched_data.get("cve_details", [])
                        # Get CVSS score (use highest from enriched data or existing)
                        enriched_cvss = enriched_data.get("cvss_score")
                        if enriched_cvss:
                            cvss_score = enriched_cvss
                        # Get remediation
                        remediation = enriched_data.get("remediation")
                    except Exception as e:
                        logger.debug(f"Failed to enrich CVEs: {e}")
                
                # Create better title (first sentence or key part)
                title = NiktoParser._create_title(description, uri)
                
                vuln = Vulnerability(
                    id=f"NIKTO-{item_id}",
                    severity=severity,
                    title=title,
                    description=description,
                    affected_component=uri or '/',
                    uri=uri,
                    method=method,
                    cve_ids=cve_ids,
                    osvdb_id=osvdb_id if osvdb_id else None,
                    cvss_score=cvss_score,
                    remediation=remediation,
                    cve_details=cve_details,
                    scanner="nikto"
                )
                vulnerabilities.append(vuln)
                
        except ET.ParseError as e:
            raise ValueError(f"Failed to parse XML: {e}")
        
        return vulnerabilities
    
    @staticmethod
    def parse_json(json_content: str) -> List[Vulnerability]:
        """Parse Nikto JSON output into normalized vulnerabilities."""
        vulnerabilities = []
        
        try:
            data = json.loads(json_content)
            
            # Handle different JSON structures
            items = []
            if isinstance(data, dict):
                if 'niktoscan' in data:
                    items = data['niktoscan'].get('item', [])
                elif 'item' in data:
                    items = data['item']
            elif isinstance(data, list):
                items = data
            
            for item in items:
                if isinstance(item, dict):
                    item_id = item.get('id', '')
                    osvdb_id = item.get('osvdb', '')
                    description = item.get('description', '')
                    
                    # Skip metadata lines
                    if NiktoParser._is_metadata_line(description):
                        continue
                    
                    uri = item.get('uri', '')
                    # If URI is missing or just '/', try to extract from description
                    if not uri or uri == '/':
                        uri = NiktoParser._extract_uri_from_description(description)
                    
                    method = item.get('namelink', 'GET')
                    
                    severity = NiktoParser._classify_severity(description, osvdb_id)
                    cve_ids = NiktoParser._extract_cves(description)
                    cve_details = []
                    cvss_score = None
                    remediation = None
                    
                    # Enrich with CVE lookup if available
                    if CVE_LOOKUP_AVAILABLE:
                        try:
                            enriched_data = CVELookup.enrich_with_cves(description, osvdb_id, uri)
                            # Merge CVE IDs
                            cve_ids.extend(enriched_data.get("cve_ids", []))
                            cve_ids = list(set(cve_ids))  # Remove duplicates
                            # Get CVE details
                            cve_details = enriched_data.get("cve_details", [])
                            # Get CVSS score
                            enriched_cvss = enriched_data.get("cvss_score")
                            if enriched_cvss:
                                cvss_score = enriched_cvss
                            # Get remediation
                            remediation = enriched_data.get("remediation")
                        except Exception as e:
                            logger.debug(f"Failed to enrich CVEs: {e}")
                    
                    # Create better title
                    title = NiktoParser._create_title(description, uri)
                    
                    vuln = Vulnerability(
                        id=f"NIKTO-{item_id}",
                        severity=severity,
                        title=title,
                        description=description,
                        affected_component=uri or '/',
                        uri=uri,
                        method=method,
                        cve_ids=cve_ids,
                        osvdb_id=osvdb_id if osvdb_id else None,
                        cvss_score=cvss_score,
                        remediation=remediation,
                        cve_details=cve_details,
                        scanner="nikto"
                    )
                    vulnerabilities.append(vuln)
                    
        except json.JSONDecodeError as e:
            raise ValueError(f"Failed to parse JSON: {e}")
        
        return vulnerabilities
    
    @staticmethod
    def _classify_severity(description: str, osvdb_id: str) -> str:
        """Classify severity based on description and OSVDB ID."""
        description_lower = description.lower()
        
        # Critical indicators
        if any(keyword in description_lower for keyword in [
            'rce', 'remote code execution', 'sql injection', 'command injection',
            'path traversal', 'arbitrary file', 'authentication bypass',
            'code execution', 'execute', 'shell', 'eval('
        ]):
            return "CRITICAL"
        
        # High indicators
        if any(keyword in description_lower for keyword in [
            'xss', 'cross-site scripting', 'script injection', 'injection',
            'information disclosure', 'sensitive data', 'credentials',
            'password', 'secret', 'private key', 'ssl', 'tls', 'certificate',
            'leaks', 'exposed', 'accessible', 'wildcard'
        ]):
            return "HIGH"
        
        # Medium indicators
        if any(keyword in description_lower for keyword in [
            'version disclosure', 'server header', 'directory listing',
            'robots.txt', 'backup file', 'debug', 'misconfiguration',
            'default file', 'missing header', 'x-frame-options',
            'x-powered-by', 'software identification'
        ]):
            return "MEDIUM"
        
        # Default to LOW
        return "LOW"
    
    @staticmethod
    def _is_metadata_line(description: str) -> bool:
        """Check if a description is metadata (not a real finding)."""
        if not description:
            return True
        
        description_lower = description.lower()
        metadata_patterns = [
            'start time:', 'end time:', 'target ip:', 'target hostname:',
            'target port:', 'host(s) tested', 'items checked:', 'error(s)',
            'item(s) reported', 'nikto v', 'scan started', 'scan ended',
            'retrieved x-powered-by header:', 'server:'
        ]
        
        # Check if it's just a metadata line
        if any(pattern in description_lower for pattern in metadata_patterns):
            return True
        
        # Check if it's too short to be meaningful
        if len(description.strip()) < 10:
            return True
        
        return False
    
    @staticmethod
    def _extract_uri_from_description(description: str) -> str:
        """Extract URI/path from description text."""
        import re
        
        if not description:
            return '/'
        
        # Look for file paths in description - more comprehensive patterns
        path_patterns = [
            # Explicit file mentions
            r'file\s+([/\w\-\.]+)',  # "file /path/to/file"
            r'header found with file\s+([/\w\-\.]+)',  # "header found with file /path"
            r'found\s+([/\w\-\.]+\.(xml|txt|conf|config|bak|old|log|php|html|htm|js|css|json|yaml|yml))',  # "found /file.ext"
            r'contains\s+([/\w\-\.]+)',  # "contains /path"
            r'accessible\s+([/\w\-\.]+)',  # "accessible /path"
            r'([/\w\-\.]+\.(xml|txt|conf|config|bak|old|log|php|html|htm|js|css|json|yaml|yml|sql|db))',  # Common file extensions
            r'/([\w\-\.]+\.(xml|txt|conf|config|bak|old|log|php|html|htm|js|css|json|yaml|yml|sql|db))',  # Path with extension
            # Directory patterns
            r'/([\w\-]+/[\w\-\.]+)',  # "/directory/file"
            r'/([\w\-]+/)',  # "/directory/"
            # Common vulnerable paths
            r'/(admin|config|backup|test|debug|api|v1|v2|wp-admin|phpmyadmin|\.git|\.svn)',  # Common paths
        ]
        
        for pattern in path_patterns:
            match = re.search(pattern, description, re.IGNORECASE)
            if match:
                uri = match.group(1) if match.lastindex >= 1 else match.group(0)
                # Clean up the URI
                uri = uri.strip()
                if uri:
                    if uri.startswith('/'):
                        # Remove trailing slashes for files, keep for directories
                        if '.' in uri.split('/')[-1]:  # Has file extension
                            return uri.rstrip('/')
                        return uri
                    else:
                        return '/' + uri
        
        # For header-based findings, check if description mentions a specific endpoint
        # Many header findings apply to root, but some might mention specific paths
        header_keywords = ['header', 'cookie', 'server', 'x-', 'content-']
        if any(keyword in description.lower() for keyword in header_keywords):
            # Header findings typically apply to root unless a path is mentioned
            # Check if there's any path-like content
            path_like = re.search(r'/([\w\-\./]+)', description)
            if path_like:
                return '/' + path_like.group(1).split()[0]  # Take first path-like segment
        
        # If no path found, return root (this is correct for header-based findings)
        return '/'
    
    @staticmethod
    def _create_title(description: str, uri: str) -> str:
        """Create a concise title from description."""
        if not description:
            return "Nikto Finding"
        
        # Remove common prefixes
        title = description.strip()
        
        # If description starts with common patterns, clean them up
        if title.startswith('+ '):
            title = title[2:].strip()
        
        # Extract first sentence or meaningful part
        # Split by common separators
        for separator in ['. ', ' See ', ' See http', ' See https']:
            if separator in title:
                title = title.split(separator)[0].strip()
                break
        
        # If title is still too long, truncate intelligently
        if len(title) > 120:
            # Try to truncate at word boundary
            truncated = title[:117]
            last_space = truncated.rfind(' ')
            if last_space > 80:
                title = truncated[:last_space] + '...'
            else:
                title = truncated + '...'
        
        return title if title else "Nikto Finding"
    
    @staticmethod
    def _extract_cves(description: str) -> List[str]:
        """Extract CVE IDs from description."""
        import re
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        cves = re.findall(cve_pattern, description, re.IGNORECASE)
        return [cve.upper() for cve in cves]


class ZapParser:
    """Parser for OWASP ZAP XML/JSON output."""
    
    @staticmethod
    def parse_xml(xml_content: str) -> List[Vulnerability]:
        """Parse ZAP XML output into normalized vulnerabilities."""
        vulnerabilities = []
        
        if not xml_content or not xml_content.strip():
            logger.warning("Empty XML content provided")
            return vulnerabilities
        
        try:
            root = ET.fromstring(xml_content)
            logger.info(f"ZAP XML root tag: {root.tag}")
            
            # ZAP XML structure: <OWASPZAPReport><site><alertitem>...</alertitem></site></OWASPZAPReport>
            sites = root.findall('.//site')
            logger.info(f"Found {len(sites)} site(s) in ZAP XML")
            
            for site in sites:
                site_name = site.get('name', '')
                logger.info(f"Processing site: {site_name}")
                
                alertitems = site.findall('.//alertitem')
                logger.info(f"Found {len(alertitems)} alertitem(s) in site {site_name}")
                
                for alertitem in alertitems:
                    pluginid = alertitem.find('pluginid')
                    pluginid_text = pluginid.text if pluginid is not None else ''
                    
                    alert_elem = alertitem.find('alert')
                    alert_text = alert_elem.text if alert_elem is not None else ''
                    
                    name_elem = alertitem.find('name')
                    name_text = name_elem.text if name_elem is not None else alert_text
                    
                    desc_elem = alertitem.find('description')
                    description = desc_elem.text if desc_elem is not None else alert_text
                    
                    uri_elem = alertitem.find('uri')
                    uri = uri_elem.text if uri_elem is not None else site_name
                    
                    riskcode_elem = alertitem.find('riskcode')
                    riskcode = riskcode_elem.text if riskcode_elem is not None else '2'
                    
                    confidence_elem = alertitem.find('confidence')
                    confidence = confidence_elem.text if confidence_elem is not None else '2'
                    
                    # Map risk code to severity
                    severity = ZapParser._map_riskcode_to_severity(riskcode)
                    
                    # Extract CVE IDs from description
                    cve_ids = ZapParser._extract_cves(description)
                    cve_details = []
                    cvss_score = None
                    remediation = None
                    
                    # Enrich with CVE lookup if available
                    if CVE_LOOKUP_AVAILABLE:
                        try:
                            enriched_data = CVELookup.enrich_with_cves(description, None, uri)
                            cve_ids.extend(enriched_data.get("cve_ids", []))
                            cve_ids = list(set(cve_ids))
                            cve_details = enriched_data.get("cve_details", [])
                            enriched_cvss = enriched_data.get("cvss_score")
                            if enriched_cvss:
                                cvss_score = enriched_cvss
                            remediation = enriched_data.get("remediation")
                        except Exception as e:
                            logger.debug(f"Failed to enrich CVEs: {e}")
                    
                    # Create title
                    title = name_text if name_text else ZapParser._create_title(description, uri)
                    
                    vuln = Vulnerability(
                        id=f"ZAP-{pluginid_text}",
                        severity=severity,
                        title=title,
                        description=description,
                        affected_component=uri or site_name,
                        uri=uri,
                        method="GET",  # ZAP doesn't always specify method
                        cve_ids=cve_ids,
                        osvdb_id=None,
                        cvss_score=cvss_score,
                        remediation=remediation,
                        cve_details=cve_details,
                        scanner="zap"
                    )
                    vulnerabilities.append(vuln)
            
            logger.info(f"ZAP parser found {len(vulnerabilities)} total vulnerabilities")
                    
        except ET.ParseError as e:
            logger.error(f"Failed to parse ZAP XML: {e}")
            raise ValueError(f"Failed to parse XML: {e}")
        
        return vulnerabilities
    
    @staticmethod
    def parse_json(json_content: str) -> List[Vulnerability]:
        """Parse ZAP JSON output into normalized vulnerabilities."""
        vulnerabilities = []
        
        try:
            data = json.loads(json_content)
            logger.info(f"ZAP JSON top-level keys: {list(data.keys()) if isinstance(data, dict) else 'list'}")
            
            # ZAP JSON structure: {"@version": "...", "site": [...]}
            sites = []
            if isinstance(data, dict):
                if 'site' in data:
                    sites = data['site'] if isinstance(data['site'], list) else [data['site']]
                elif 'sites' in data:
                    sites = data['sites'] if isinstance(data['sites'], list) else [data['sites']]
            elif isinstance(data, list):
                sites = data
            
            logger.info(f"Found {len(sites)} site(s) in ZAP JSON")
            
            for site in sites:
                site_name = site.get('@name', '')
                logger.info(f"Processing site: {site_name}")
                alerts = site.get('alerts', [])
                if not isinstance(alerts, list):
                    alerts = [alerts] if alerts else []
                logger.info(f"Found {len(alerts)} alert(s) in site {site_name}")
                
                for alert in alerts:
                    pluginid = str(alert.get('pluginid', ''))
                    name = alert.get('name', alert.get('alert', ''))
                    description = alert.get('description', alert.get('alert', ''))
                    uri = alert.get('uri', site_name)
                    risk = alert.get('risk', 'Medium')
                    confidence = alert.get('confidence', 'Medium')
                    
                    # Map risk to severity
                    severity = ZapParser._map_risk_to_severity(risk)
                    
                    # Extract CVE IDs
                    cve_ids = ZapParser._extract_cves(description)
                    cve_details = []
                    cvss_score = None
                    remediation = None
                    
                    # Enrich with CVE lookup if available
                    if CVE_LOOKUP_AVAILABLE:
                        try:
                            enriched_data = CVELookup.enrich_with_cves(description, None, uri)
                            cve_ids.extend(enriched_data.get("cve_ids", []))
                            cve_ids = list(set(cve_ids))
                            cve_details = enriched_data.get("cve_details", [])
                            enriched_cvss = enriched_data.get("cvss_score")
                            if enriched_cvss:
                                cvss_score = enriched_cvss
                            remediation = enriched_data.get("remediation")
                        except Exception as e:
                            logger.debug(f"Failed to enrich CVEs: {e}")
                    
                    vuln = Vulnerability(
                        id=f"ZAP-{pluginid}",
                        severity=severity,
                        title=name,
                        description=description,
                        affected_component=uri or site_name,
                        uri=uri,
                        method="GET",
                        cve_ids=cve_ids,
                        osvdb_id=None,
                        cvss_score=cvss_score,
                        remediation=remediation,
                        cve_details=cve_details,
                        scanner="zap"
                    )
                    vulnerabilities.append(vuln)
            
            logger.info(f"ZAP parser found {len(vulnerabilities)} total vulnerabilities from JSON")
                    
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse ZAP JSON: {e}")
            raise ValueError(f"Failed to parse JSON: {e}")
        
        return vulnerabilities
    
    @staticmethod
    def _map_riskcode_to_severity(riskcode: str) -> str:
        """Map ZAP risk code to severity."""
        risk_map = {
            "0": "LOW",      # Informational
            "1": "LOW",      # Low
            "2": "MEDIUM",   # Medium
            "3": "HIGH",     # High
            "4": "CRITICAL"  # Critical
        }
        return risk_map.get(str(riskcode), "MEDIUM")
    
    @staticmethod
    def _map_risk_to_severity(risk: str) -> str:
        """Map ZAP risk level string to severity."""
        risk_map = {
            "Informational": "LOW",
            "Low": "LOW",
            "Medium": "MEDIUM",
            "High": "HIGH",
            "Critical": "CRITICAL"
        }
        return risk_map.get(risk, "MEDIUM")
    
    @staticmethod
    def _extract_cves(description: str) -> List[str]:
        """Extract CVE IDs from description."""
        import re
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        cves = re.findall(cve_pattern, description, re.IGNORECASE)
        return [cve.upper() for cve in cves]
    
    @staticmethod
    def _create_title(description: str, uri: str) -> str:
        """Create a concise title from description."""
        if not description:
            return "ZAP Finding"
        
        title = description.strip()
        
        # Extract first sentence or meaningful part
        for separator in ['. ', '\n', ' See ', ' See http']:
            if separator in title:
                title = title.split(separator)[0].strip()
                break
        
        # Truncate if too long
        if len(title) > 120:
            truncated = title[:117]
            last_space = truncated.rfind(' ')
            if last_space > 80:
                title = truncated[:last_space] + '...'
            else:
                title = truncated + '...'
        
        return title if title else "ZAP Finding"


class NucleiParser:
    """Parser for Nuclei JSON (newline-delimited) output."""

    @staticmethod
    def parse_json(json_content: str) -> List[Vulnerability]:
        """Parse Nuclei JSON/NDJSON into normalized vulnerabilities."""
        vulnerabilities: List[Vulnerability] = []

        if not json_content or not json_content.strip():
            logger.warning("Empty Nuclei JSON content provided")
            return vulnerabilities

        lines = [line for line in json_content.splitlines() if line.strip()]
        for line in lines:
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                # Some builds may emit a single JSON array; try once
                try:
                    data = json.loads(json_content)
                    if isinstance(data, list):
                        for item in data:
                            NucleiParser._parse_record(item, vulnerabilities)
                        return vulnerabilities
                except json.JSONDecodeError:
                    logger.debug("Skipping non-JSON line in Nuclei output")
                    continue
            else:
                NucleiParser._parse_record(record, vulnerabilities)

        return vulnerabilities

    @staticmethod
    def _parse_record(record: Dict[str, Any], out: List[Vulnerability]) -> None:
        """Parse a single Nuclei result record into a Vulnerability."""
        if not isinstance(record, dict):
            return

        host = record.get("host") or record.get("ip") or ""
        url = record.get("url") or record.get("matched-at") or host
        template_id = record.get("template-id", "")

        info = record.get("info", {}) or {}
        name = info.get("name", template_id or "Nuclei Finding")
        description = info.get("description", "") or record.get("description", "")
        severity_raw = (info.get("severity") or "medium").upper()

        severity_map = {
            "INFO": "LOW",
            "INFORMATIONAL": "LOW",
            "LOW": "LOW",
            "MEDIUM": "MEDIUM",
            "HIGH": "HIGH",
            "CRITICAL": "CRITICAL",
        }
        severity = severity_map.get(severity_raw, "MEDIUM")

        classification = info.get("classification", {}) or {}
        cve_ids: List[str] = []
        cve_field = classification.get("cve-id") or classification.get("cve-ids")
        if isinstance(cve_field, str):
            cve_ids = [cve_field]
        elif isinstance(cve_field, list):
            cve_ids = [str(cve) for cve in cve_field]

        if not cve_ids:
            # Try to extract CVEs from description
            cve_ids = NiktoParser._extract_cves(description)

        cvss_score = None
        try:
            cvss_score_val = classification.get("cvss-score")
            if cvss_score_val is not None:
                cvss_score = float(cvss_score_val)
        except (TypeError, ValueError):
            cvss_score = None

        remediation = info.get("remediation") or info.get("reference")

        # Map into the simplified schema fields the user highlighted
        vuln = Vulnerability(
            id=f"NUCLEI-{template_id or host}",
            severity=severity,
            title=name,
            description=description or name,
            affected_component=url or host,
            uri=url,
            method=None,
            cve_ids=cve_ids,
            osvdb_id=None,
            cvss_score=cvss_score,
            remediation=remediation,
            cve_details=[],
            scanner="nuclei",
        )
        out.append(vuln)


class WapitiParser:
    """Parser for Wapiti JSON output."""

    @staticmethod
    def parse_json(json_content: str) -> List[Vulnerability]:
        """Parse Wapiti JSON report into normalized vulnerabilities."""
        vulnerabilities: List[Vulnerability] = []

        if not json_content or not json_content.strip():
            logger.warning("Empty Wapiti JSON content provided")
            return vulnerabilities

        try:
            data = json.loads(json_content)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Wapiti JSON: {e}")
            return vulnerabilities

        # Wapiti 3 uses "vulnerabilities" with modules; structure may vary slightly
        vulns = data.get("vulnerabilities") or data.get("vulns") or {}
        if isinstance(vulns, dict):
            # {module: [{...}, {...}], ...}
            for module_name, findings in vulns.items():
                if isinstance(findings, list):
                    for finding in findings:
                        WapitiParser._parse_finding(finding, module_name, vulnerabilities)
        elif isinstance(vulns, list):
            for finding in vulns:
                WapitiParser._parse_finding(finding, None, vulnerabilities)

        return vulnerabilities

    @staticmethod
    def _parse_finding(
        finding: Dict[str, Any],
        module_name: Optional[str],
        out: List[Vulnerability],
    ) -> None:
        if not isinstance(finding, dict):
            return

        url = finding.get("url") or finding.get("path") or "/"
        method = finding.get("method") or "GET"
        vuln_type = finding.get("vulnerability") or finding.get("type") or module_name or "Wapiti Finding"
        description = finding.get("info") or finding.get("description") or vuln_type

        severity_raw = (finding.get("severity") or finding.get("level") or "medium").upper()
        severity_map = {
            "INFO": "LOW",
            "INFORMATIONAL": "LOW",
            "LOW": "LOW",
            "MEDIUM": "MEDIUM",
            "HIGH": "HIGH",
            "CRITICAL": "CRITICAL",
        }
        severity = severity_map.get(severity_raw, "MEDIUM")

        cve_ids: List[str] = []
        cve_field = finding.get("cve") or finding.get("cve_id") or finding.get("cve_ids")
        if isinstance(cve_field, str):
            cve_ids = [cve_field]
        elif isinstance(cve_field, list):
            cve_ids = [str(cve) for cve in cve_field]

        if not cve_ids:
            cve_ids = NiktoParser._extract_cves(description)

        cvss_score = None
        try:
            cvss_val = finding.get("cvss") or finding.get("cvss_score")
            if cvss_val is not None:
                cvss_score = float(cvss_val)
        except (TypeError, ValueError):
            cvss_score = None

        remediation = finding.get("solution") or finding.get("remediation")

        title = vuln_type
        vuln = Vulnerability(
            id=f"WAPITI-{finding.get('id', url)}",
            severity=severity,
            title=title,
            description=description,
            affected_component=url,
            uri=url,
            method=method,
            cve_ids=cve_ids,
            osvdb_id=None,
            cvss_score=cvss_score,
            remediation=remediation,
            cve_details=[],
            scanner="wapiti",
        )
        out.append(vuln)


def normalize_results(
    raw_output: str,
    output_format: str = "xml",
    scanner: str = "nikto"
) -> Dict[str, Any]:
    """Normalize scanner results into standard format."""
    
    # Normalize scanner name to lowercase for case-insensitive matching
    scanner_lower = scanner.lower().strip() if scanner else "nikto"
    
    logger.info(f"Normalizing results for scanner: {scanner} (normalized: {scanner_lower})")
    
    if scanner_lower == "nikto":
        parser = NiktoParser()
        if output_format.lower() == "xml":
            vulnerabilities = parser.parse_xml(raw_output)
        elif output_format.lower() == "json":
            vulnerabilities = parser.parse_json(raw_output)
        else:
            raise ValueError(f"Unsupported format: {output_format}")
    elif scanner_lower == "zap":
        parser = ZapParser()
        if output_format.lower() == "xml":
            vulnerabilities = parser.parse_xml(raw_output)
        elif output_format.lower() == "json":
            vulnerabilities = parser.parse_json(raw_output)
        else:
            raise ValueError(f"Unsupported format: {output_format}")
    elif scanner_lower == "nuclei":
        parser = NucleiParser()
        if output_format.lower() != "json":
            raise ValueError("Nuclei parser currently supports only JSON output")
        vulnerabilities = parser.parse_json(raw_output)
    elif scanner_lower == "wapiti":
        parser = WapitiParser()
        if output_format.lower() != "json":
            raise ValueError("Wapiti parser currently supports only JSON output")
        vulnerabilities = parser.parse_json(raw_output)
    else:
        logger.error(f"Unsupported scanner received: '{scanner}' (normalized: '{scanner_lower}')")
        raise ValueError(f"Unsupported scanner: {scanner}")
    
    return {
        "findings_count": len(vulnerabilities),
        "findings": [asdict(vuln) for vuln in vulnerabilities],
        "scanner": scanner,
        "parsed_at": get_local_time().isoformat()
    }

