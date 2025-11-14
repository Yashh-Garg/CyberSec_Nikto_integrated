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


def normalize_results(
    raw_output: str,
    output_format: str = "xml",
    scanner: str = "nikto"
) -> Dict[str, Any]:
    """Normalize scanner results into standard format."""
    
    if scanner == "nikto":
        parser = NiktoParser()
        if output_format.lower() == "xml":
            vulnerabilities = parser.parse_xml(raw_output)
        elif output_format.lower() == "json":
            vulnerabilities = parser.parse_json(raw_output)
        else:
            raise ValueError(f"Unsupported format: {output_format}")
    else:
        raise ValueError(f"Unsupported scanner: {scanner}")
    
    return {
        "findings_count": len(vulnerabilities),
        "findings": [asdict(vuln) for vuln in vulnerabilities],
        "scanner": scanner,
        "parsed_at": get_local_time().isoformat()
    }

