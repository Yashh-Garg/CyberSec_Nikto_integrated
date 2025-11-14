"""Unit tests for scanner functionality."""

import pytest
from unittest.mock import Mock, patch, MagicMock
from nikto_scanner import NiktoScanner
from utils.parser import NiktoParser, normalize_results


class TestNiktoParser:
    """Test Nikto parser functionality."""
    
    def test_parse_xml_basic(self):
        """Test parsing basic XML output."""
        xml_content = """<?xml version="1.0"?>
        <niktoscan>
            <item id="1" osvdb="3092">
                <description>Server: Apache/2.4.41</description>
                <uri>/</uri>
                <namelink>GET</namelink>
            </item>
        </niktoscan>
        """
        
        parser = NiktoParser()
        vulnerabilities = parser.parse_xml(xml_content)
        
        assert len(vulnerabilities) == 1
        assert vulnerabilities[0].id == "NIKTO-1"
        assert vulnerabilities[0].severity in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        assert vulnerabilities[0].scanner == "nikto"
    
    def test_parse_json_basic(self):
        """Test parsing basic JSON output."""
        json_content = """{
            "niktoscan": {
                "item": [
                    {
                        "id": "1",
                        "osvdb": "3092",
                        "description": "Server: Apache/2.4.41",
                        "uri": "/",
                        "namelink": "GET"
                    }
                ]
            }
        }
        """
        
        parser = NiktoParser()
        vulnerabilities = parser.parse_json(json_content)
        
        assert len(vulnerabilities) == 1
        assert vulnerabilities[0].id == "NIKTO-1"
    
    def test_extract_cves(self):
        """Test CVE extraction from description."""
        parser = NiktoParser()
        description = "Vulnerability CVE-2023-1234 and CVE-2024-5678 found"
        cves = parser._extract_cves(description)
        
        assert "CVE-2023-1234" in cves
        assert "CVE-2024-5678" in cves
    
    def test_classify_severity(self):
        """Test severity classification."""
        parser = NiktoParser()
        
        # Test critical
        assert parser._classify_severity("SQL injection vulnerability", "") == "CRITICAL"
        
        # Test high
        assert parser._classify_severity("Information disclosure", "") == "HIGH"
        
        # Test medium
        assert parser._classify_severity("Server header disclosure", "") == "MEDIUM"
        
        # Test low (default)
        assert parser._classify_severity("Some finding", "") == "LOW"


class TestNiktoScanner:
    """Test Nikto scanner functionality."""
    
    @patch('nikto_scanner.docker.from_env')
    def test_scanner_initialization(self, mock_docker):
        """Test scanner initialization."""
        mock_client = Mock()
        mock_docker.return_value = mock_client
        
        scanner = NiktoScanner()
        
        assert scanner.client == mock_client
        mock_docker.assert_called_once()
    
    @patch('nikto_scanner.docker.from_env')
    def test_build_command(self, mock_docker):
        """Test command building."""
        scanner = NiktoScanner()
        
        command = scanner._build_command("example.com", 80, False, None)
        assert "example.com" in command
        assert "-h" in command
        assert "-Format" in command
    
    @patch('nikto_scanner.docker.from_env')
    def test_build_command_ssl(self, mock_docker):
        """Test command building with SSL."""
        scanner = NiktoScanner()
        
        command = scanner._build_command("example.com", 443, True, None)
        assert "https://" in command


class TestNormalizeResults:
    """Test result normalization."""
    
    def test_normalize_xml(self):
        """Test normalizing XML results."""
        xml_content = """<?xml version="1.0"?>
        <niktoscan>
            <item id="1" osvdb="3092">
                <description>Test finding</description>
                <uri>/</uri>
                <namelink>GET</namelink>
            </item>
        </niktoscan>
        """
        
        result = normalize_results(xml_content, "xml", "nikto")
        
        assert "findings_count" in result
        assert "findings" in result
        assert result["scanner"] == "nikto"
        assert len(result["findings"]) == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

