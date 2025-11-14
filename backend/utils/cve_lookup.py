"""CVE lookup utility for enriching vulnerability data."""

import logging
import re
from typing import List, Optional, Dict
import requests
from datetime import datetime

logger = logging.getLogger(__name__)

# NVD API base URL (free tier, no API key required for basic queries)
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class CVELookup:
    """Lookup CVE information from various sources."""
    
    @staticmethod
    def extract_cves_from_text(text: str) -> List[str]:
        """Extract CVE IDs directly from text."""
        if not text:
            return []
        
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        cves = re.findall(cve_pattern, text, re.IGNORECASE)
        return [cve.upper() for cve in cves]
    
    @staticmethod
    def lookup_by_keywords(description: str, osvdb_id: Optional[str] = None) -> List[str]:
        """Lookup CVEs based on vulnerability description keywords."""
        if not description:
            return []
        
        description_lower = description.lower()
        cves = []
        
        # Map common vulnerability patterns to potential CVEs
        # This is a simplified lookup - for production, use NVD API
        
        # SQL Injection patterns
        if any(keyword in description_lower for keyword in ['sql injection', 'sqli']):
            # Common SQL injection CVEs (examples - would need full database)
            # For now, return empty - full lookup requires NVD API integration
            pass
        
        # XSS patterns
        if any(keyword in description_lower for keyword in ['xss', 'cross-site scripting']):
            pass
        
        # For now, return empty list - full CVE lookup requires external API
        # This would be implemented in Phase 2 as per problem statement
        return cves
    
    @staticmethod
    def lookup_by_osvdb(osvdb_id: str) -> List[str]:
        """Lookup CVEs by OSVDB ID (requires OSVDB to CVE mapping)."""
        if not osvdb_id:
            return []
        
        # OSVDB was discontinued, but we can try to map known IDs
        # This would require a mapping database
        return []
    
    @staticmethod
    def query_nvd_api(keywords: List[str], max_results: int = 10) -> List[Dict]:
        """Query NVD API for CVEs matching keywords. Returns list of CVE dicts with details."""
        try:
            # Build query string
            query_string = " ".join(keywords[:3])  # Limit to 3 keywords
            
            # NVD API v2.0 requires keyword search
            params = {
                "keywordSearch": query_string,
                "resultsPerPage": max_results
            }
            
            # Make request (with timeout to avoid blocking)
            response = requests.get(
                NVD_API_BASE,
                params=params,
                timeout=5  # 5 second timeout
            )
            
            if response.status_code == 200:
                data = response.json()
                cve_details = []
                
                # Extract CVE details from response
                if "vulnerabilities" in data:
                    for vuln in data["vulnerabilities"]:
                        if "cve" in vuln:
                            cve_data = vuln["cve"]
                            cve_id = cve_data.get("id", "")
                            
                            # Extract CVSS score
                            cvss_score = None
                            cvss_version = None
                            if "metrics" in cve_data:
                                # Try CVSS v3.1 first
                                if "cvssMetricV31" in cve_data["metrics"]:
                                    cvss_v31 = cve_data["metrics"]["cvssMetricV31"][0]
                                    cvss_score = cvss_v31.get("cvssData", {}).get("baseScore")
                                    cvss_version = "3.1"
                                # Fallback to CVSS v3.0
                                elif "cvssMetricV30" in cve_data["metrics"]:
                                    cvss_v30 = cve_data["metrics"]["cvssMetricV30"][0]
                                    cvss_score = cvss_v30.get("cvssData", {}).get("baseScore")
                                    cvss_version = "3.0"
                                # Fallback to CVSS v2.0
                                elif "cvssMetricV2" in cve_data["metrics"]:
                                    cvss_v2 = cve_data["metrics"]["cvssMetricV2"][0]
                                    cvss_score = cvss_v2.get("cvssData", {}).get("baseScore")
                                    cvss_version = "2.0"
                            
                            # Extract description
                            description = ""
                            if "descriptions" in cve_data:
                                for desc in cve_data["descriptions"]:
                                    if desc.get("lang") == "en":
                                        description = desc.get("value", "")
                                        break
                            
                            cve_details.append({
                                "id": cve_id,
                                "cvss_score": cvss_score,
                                "cvss_version": cvss_version,
                                "description": description,
                                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                            })
                
                return cve_details[:5]  # Return top 5 matches
            else:
                logger.warning(f"NVD API returned status {response.status_code}")
                return []
                
        except requests.exceptions.Timeout:
            logger.warning("NVD API request timed out")
            return []
        except requests.exceptions.RequestException as e:
            logger.warning(f"Failed to query NVD API: {e}")
            return []
        except Exception as e:
            logger.warning(f"Error querying NVD API: {e}")
            return []
    
    @staticmethod
    def enrich_with_cves(description: str, osvdb_id: Optional[str] = None, 
                        uri: Optional[str] = None) -> Dict:
        """Enrich vulnerability with CVE IDs and details from multiple sources.
        
        Returns:
            Dict with keys: 'cve_ids' (List[str]), 'cve_details' (List[Dict]), 
            'cvss_score' (float or None), 'remediation' (str or None)
        """
        cve_ids = []
        cve_details = []
        cvss_scores = []
        
        # 1. Extract CVEs directly from description
        direct_cves = CVELookup.extract_cves_from_text(description)
        cve_ids.extend(direct_cves)
        
        # 2. If no CVEs found and we have keywords, try NVD lookup
        if not cve_ids and description:
            # Extract keywords from description
            keywords = CVELookup._extract_keywords(description)
            if keywords:
                try:
                    nvd_results = CVELookup.query_nvd_api(keywords, max_results=3)
                    for cve_info in nvd_results:
                        cve_id = cve_info.get("id")
                        if cve_id:
                            cve_ids.append(cve_id)
                            cve_details.append(cve_info)
                            if cve_info.get("cvss_score"):
                                cvss_scores.append(cve_info["cvss_score"])
                except:
                    pass  # Silently fail if NVD lookup fails
        
        # 3. Try OSVDB lookup if available
        if not cve_ids and osvdb_id:
            osvdb_cves = CVELookup.lookup_by_osvdb(osvdb_id)
            cve_ids.extend(osvdb_cves)
        
        # Remove duplicate CVE IDs
        cve_ids = list(set(cve_ids))
        
        # Get highest CVSS score
        cvss_score = max(cvss_scores) if cvss_scores else None
        
        # Generate remediation guidance
        remediation = CVELookup._generate_remediation(description, cve_details)
        
        return {
            "cve_ids": cve_ids,
            "cve_details": cve_details,
            "cvss_score": cvss_score,
            "remediation": remediation
        }
    
    @staticmethod
    def _generate_remediation(description: str, cve_details: List[Dict]) -> Optional[str]:
        """Generate remediation guidance based on vulnerability description."""
        description_lower = description.lower()
        
        # X-Frame-Options
        if "x-frame-options" in description_lower or "clickjacking" in description_lower:
            return "Add X-Frame-Options header: 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN'"
        
        # Wildcard entries
        if "wildcard" in description_lower:
            if "crossdomain.xml" in description_lower:
                return "Restrict crossdomain.xml to specific trusted domains instead of wildcard (*)"
            elif "clientaccesspolicy.xml" in description_lower:
                return "Restrict clientaccesspolicy.xml to specific trusted domains instead of wildcard (*)"
        
        # ETag leaks
        if "etag" in description_lower or "inode" in description_lower:
            return "Disable ETag headers or configure server to not leak inode information"
        
        # Information disclosure
        if "information disclosure" in description_lower or "leaks" in description_lower:
            return "Review and restrict information disclosure. Remove sensitive headers and version information"
        
        # SQL Injection
        if "sql injection" in description_lower:
            return "Use parameterized queries, input validation, and prepared statements. Update affected software"
        
        # XSS
        if "xss" in description_lower or "cross-site scripting" in description_lower:
            return "Implement Content Security Policy (CSP), input validation, and output encoding"
        
        # Default
        if cve_details:
            return "Review CVE details and apply security patches or updates as recommended"
        
        return None
    
    @staticmethod
    def _extract_keywords(description: str) -> List[str]:
        """Extract relevant keywords from description for CVE lookup."""
        description_lower = description.lower()
        keywords = []
        
        # Common vulnerability keywords
        vuln_keywords = [
            'sql injection', 'xss', 'cross-site scripting', 'command injection',
            'path traversal', 'remote code execution', 'rce', 'authentication bypass',
            'file upload', 'directory traversal', 'information disclosure',
            'clickjacking', 'wildcard', 'etag', 'inode'
        ]
        
        for keyword in vuln_keywords:
            if keyword in description_lower:
                keywords.append(keyword)
        
        # Also extract software/technology names
        software_patterns = [
            r'nginx[/\s]?(\d+\.\d+)',
            r'apache[/\s]?(\d+\.\d+)',
            r'php[/\s]?(\d+\.\d+)',
            r'php\s+(\d+\.\d+)',
        ]
        
        for pattern in software_patterns:
            match = re.search(pattern, description_lower, re.IGNORECASE)
            if match:
                keywords.append(match.group(0))
        
        return keywords[:5]  # Limit to 5 keywords


def enrich_finding_with_cves(finding: Dict) -> Dict:
    """Enrich a finding dictionary with CVE IDs."""
    description = finding.get('description', '')
    osvdb_id = finding.get('osvdb_id')
    uri = finding.get('uri', '')
    
    # Get existing CVEs
    existing_cves = finding.get('cve_ids', [])
    
    # Enrich with additional CVEs
    new_cves = CVELookup.enrich_with_cves(description, osvdb_id, uri)
    
    # Combine and deduplicate
    all_cves = list(set(existing_cves + new_cves))
    
    # Update finding
    finding['cve_ids'] = all_cves
    
    return finding

