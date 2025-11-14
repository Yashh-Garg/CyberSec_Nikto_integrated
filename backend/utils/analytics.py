"""Analytics and insights generation for scan data."""

import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from collections import Counter, defaultdict

logger = logging.getLogger(__name__)


class ScanAnalytics:
    """Generate insights and analytics from scan data."""
    
    @staticmethod
    def generate_insights(scans: List[Dict]) -> Dict[str, Any]:
        """Generate comprehensive insights from scan history."""
        if not scans:
            return {
                "total_scans": 0,
                "insights": [],
                "trends": {},
                "recommendations": []
            }
        
        insights = []
        trends = {}
        
        # Basic statistics
        total_scans = len(scans)
        completed_scans = [s for s in scans if s.get("status") == "completed"]
        failed_scans = [s for s in scans if s.get("status") == "failed"]
        running_scans = [s for s in scans if s.get("status") == "running"]
        
        # Vulnerability statistics
        all_findings = []
        severity_counts = Counter()
        cve_counts = Counter()
        uri_counts = Counter()
        
        for scan in completed_scans:
            if scan.get("results") and scan["results"].get("findings"):
                findings = scan["results"]["findings"]
                all_findings.extend(findings)
                
                for finding in findings:
                    severity_counts[finding.get("severity", "UNKNOWN")] += 1
                    
                    # Count CVEs
                    cve_ids = finding.get("cve_ids", [])
                    for cve in cve_ids:
                        cve_counts[cve] += 1
                    
                    # Count affected URIs
                    uri = finding.get("uri", "/")
                    uri_counts[uri] += 1
        
        # Generate insights
        insights.append({
            "type": "summary",
            "title": "Scan Overview",
            "data": {
                "total_scans": total_scans,
                "completed": len(completed_scans),
                "failed": len(failed_scans),
                "running": len(running_scans),
                "total_findings": len(all_findings),
                "unique_cves": len(cve_counts),
                "affected_endpoints": len(uri_counts)
            }
        })
        
        # Severity distribution
        if severity_counts:
            insights.append({
                "type": "severity_distribution",
                "title": "Vulnerability Severity Distribution",
                "data": dict(severity_counts)
            })
        
        # Top vulnerabilities
        if all_findings:
            # Most common vulnerability types
            title_counts = Counter(f.get("title", "Unknown")[:50] for f in all_findings)
            insights.append({
                "type": "top_vulnerabilities",
                "title": "Most Common Vulnerabilities",
                "data": dict(title_counts.most_common(10))
            })
        
        # Top CVEs
        if cve_counts:
            insights.append({
                "type": "top_cves",
                "title": "Most Frequent CVEs",
                "data": dict(cve_counts.most_common(10))
            })
        
        # Most affected endpoints
        if uri_counts:
            insights.append({
                "type": "top_endpoints",
                "title": "Most Affected Endpoints",
                "data": dict(uri_counts.most_common(10))
            })
        
        # Trend analysis (last 7 days)
        trends = ScanAnalytics._analyze_trends(completed_scans)
        
        # Generate recommendations
        recommendations = ScanAnalytics._generate_recommendations(
            all_findings, severity_counts, completed_scans
        )
        
        return {
            "total_scans": total_scans,
            "insights": insights,
            "trends": trends,
            "recommendations": recommendations,
            "generated_at": datetime.now().isoformat()
        }
    
    @staticmethod
    def _analyze_trends(scans: List[Dict]) -> Dict[str, Any]:
        """Analyze trends over time."""
        if not scans:
            return {}
        
        # Group by date
        daily_counts = defaultdict(int)
        daily_findings = defaultdict(int)
        
        for scan in scans:
            created_at = scan.get("created_at")
            if created_at:
                try:
                    # Parse ISO format date
                    date_obj = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                    date_key = date_obj.date().isoformat()
                    daily_counts[date_key] += 1
                    
                    # Count findings
                    if scan.get("results") and scan["results"].get("findings"):
                        daily_findings[date_key] += len(scan["results"]["findings"])
                except:
                    pass
        
        return {
            "scans_per_day": dict(daily_counts),
            "findings_per_day": dict(daily_findings),
            "average_findings_per_scan": sum(daily_findings.values()) / len(scans) if scans else 0
        }
    
    @staticmethod
    def _generate_recommendations(
        findings: List[Dict],
        severity_counts: Counter,
        scans: List[Dict]
    ) -> List[Dict]:
        """Generate actionable recommendations."""
        recommendations = []
        
        # Critical vulnerabilities
        critical_count = severity_counts.get("CRITICAL", 0)
        if critical_count > 0:
            recommendations.append({
                "priority": "HIGH",
                "title": f"Address {critical_count} Critical Vulnerabilities",
                "description": "Critical vulnerabilities pose immediate security risks and should be patched immediately.",
                "action": "Review and patch critical vulnerabilities first"
            })
        
        # High severity
        high_count = severity_counts.get("HIGH", 0)
        if high_count > 5:
            recommendations.append({
                "priority": "MEDIUM",
                "title": f"Review {high_count} High-Severity Issues",
                "description": "Multiple high-severity vulnerabilities detected. Prioritize remediation.",
                "action": "Create remediation plan for high-severity findings"
            })
        
        # Missing security headers
        missing_headers = [f for f in findings if "header" in f.get("title", "").lower() and "not present" in f.get("title", "").lower()]
        if missing_headers:
            recommendations.append({
                "priority": "MEDIUM",
                "title": "Implement Security Headers",
                "description": f"{len(missing_headers)} security headers are missing. These are easy wins for security.",
                "action": "Configure security headers (X-Frame-Options, CSP, etc.)"
            })
        
        # Wildcard entries
        wildcard_issues = [f for f in findings if "wildcard" in f.get("title", "").lower()]
        if wildcard_issues:
            recommendations.append({
                "priority": "MEDIUM",
                "title": "Restrict Wildcard Policies",
                "description": f"{len(wildcard_issues)} wildcard entries found in security policies.",
                "action": "Review and restrict crossdomain.xml and clientaccesspolicy.xml"
            })
        
        # Frequent scanning
        if len(scans) < 3:
            recommendations.append({
                "priority": "LOW",
                "title": "Increase Scan Frequency",
                "description": "Regular scanning helps identify new vulnerabilities early.",
                "action": "Schedule regular security scans"
            })
        
        return recommendations
    
    @staticmethod
    def calculate_risk_score(findings: List[Dict]) -> Dict[str, Any]:
        """Calculate overall risk score for a scan."""
        if not findings:
            return {
                "score": 0,
                "level": "NONE",
                "breakdown": {}
            }
        
        # Weighted scoring
        severity_weights = {
            "CRITICAL": 10,
            "HIGH": 7,
            "MEDIUM": 4,
            "LOW": 1
        }
        
        total_score = 0
        breakdown = {}
        
        for finding in findings:
            severity = finding.get("severity", "LOW")
            weight = severity_weights.get(severity, 1)
            total_score += weight
            
            if severity not in breakdown:
                breakdown[severity] = {"count": 0, "score": 0}
            breakdown[severity]["count"] += 1
            breakdown[severity]["score"] += weight
        
        # Normalize to 0-100 scale (max reasonable: 50 findings * 10 = 500)
        normalized_score = min(100, (total_score / 50) * 10)
        
        # Risk level
        if normalized_score >= 70:
            level = "CRITICAL"
        elif normalized_score >= 50:
            level = "HIGH"
        elif normalized_score >= 30:
            level = "MEDIUM"
        elif normalized_score >= 10:
            level = "LOW"
        else:
            level = "MINIMAL"
        
        return {
            "score": round(normalized_score, 1),
            "level": level,
            "breakdown": breakdown,
            "total_findings": len(findings)
        }

