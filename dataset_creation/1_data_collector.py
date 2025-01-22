#!/usr/bin/env python3

import os
import json
import logging
import requests
import xml.etree.ElementTree as ET
from bs4 import BeautifulSoup
from datetime import datetime, timedelta
from typing import Dict, List, Union, Optional
from pathlib import Path
import feedparser
import pandas as pd
import yaml

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class CyberDataCollector:
    def __init__(self, output_dir: str = "raw_data"):
        """Initialize the data collector with output directory configuration."""
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # API endpoints and configurations
        self.endpoints = {
            # NIST and CVE Sources
            'nvd_cve': 'https://services.nvd.nist.gov/rest/json/cves/2.0',
            'nist_standards': 'https://csrc.nist.gov/CSRC/media/Publications/sp/800-53/rev-5/download/json/sp800-53r5-control-catalog.json',
            'mitre_attack': 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json',
            'mitre_capec': 'https://capec.mitre.org/data/xml/views/3000.xml',
            
            # Threat Intelligence Feeds
            'alienvault_otx': 'https://otx.alienvault.com/api/v1/pulses/subscribed',
            'threatfox_api': 'https://threatfox-api.abuse.ch/api/v1/',
            
            # Security Advisories
            'microsoft_security': 'https://api.msrc.microsoft.com/cvrf/v2.0/updates',
            'ubuntu_usn': 'https://ubuntu.com/security/notices/rss.xml',
            'redhat_security': 'https://access.redhat.com/labs/securitydataapi/cve.json',
            
            # Research and Reports
            'arxiv_cs_crypto': 'http://export.arxiv.org/api/query?search_query=cat:cs.CR&max_results=100',
            'exploit_db': 'https://www.exploit-db.com/download/',
            
            # Malware Information
            'malware_bazaar': 'https://mb-api.abuse.ch/api/v1/',
            'virustotal': 'https://www.virustotal.com/vtapi/v2/',
        }
        
        # Initialize session for better performance
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'CyberLLM-DataCollector/1.0'
        })

    def fetch_cve_data(self, start_index: int = 0, results_per_page: int = 2000) -> Optional[Dict]:
        """
        Fetch CVE data from NVD database.
        
        Args:
            start_index: Starting index for pagination
            results_per_page: Number of results per page
            
        Returns:
            Dictionary containing CVE data or None if failed
        """
        try:
            params = {
                'startIndex': start_index,
                'resultsPerPage': results_per_page
            }
            response = self.session.get(self.endpoints['nvd_cve'], params=params)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching CVE data: {str(e)}")
            return None

    def fetch_nist_standards(self) -> Optional[Dict]:
        """
        Fetch NIST cybersecurity standards.
        
        Returns:
            Dictionary containing NIST standards or None if failed
        """
        try:
            response = self.session.get(self.endpoints['nist_standards'])
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching NIST standards: {str(e)}")
            return None

    def fetch_mitre_attack(self) -> Optional[Dict]:
        """Fetch MITRE ATT&CK framework data."""
        try:
            response = self.session.get(self.endpoints['mitre_attack'])
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching MITRE ATT&CK data: {str(e)}")
            return None

    def fetch_capec_data(self) -> Optional[Dict]:
        """Fetch MITRE CAPEC (Common Attack Pattern Enumeration and Classification) data."""
        try:
            response = self.session.get(self.endpoints['mitre_capec'])
            response.raise_for_status()
            return {'xml_data': response.text}
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching CAPEC data: {str(e)}")
            return None

    def fetch_ubuntu_security_notices(self) -> Optional[Dict]:
        """Fetch Ubuntu Security Notices."""
        try:
            feed = feedparser.parse(self.endpoints['ubuntu_usn'])
            return {'entries': feed.entries}
        except Exception as e:
            logger.error(f"Error fetching Ubuntu Security Notices: {str(e)}")
            return None

    def fetch_arxiv_papers(self) -> Optional[Dict]:
        """Fetch recent cybersecurity papers from arXiv."""
        try:
            response = self.session.get(self.endpoints['arxiv_cs_crypto'])
            response.raise_for_status()
            feed = feedparser.parse(response.text)
            return {'papers': feed.entries}
        except Exception as e:
            logger.error(f"Error fetching arXiv papers: {str(e)}")
            return None

    def fetch_redhat_security(self) -> Optional[Dict]:
        """Fetch Red Hat Security Data."""
        try:
            response = self.session.get(self.endpoints['redhat_security'])
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching Red Hat Security data: {str(e)}")
            return None

    def fetch_microsoft_security(self) -> Optional[Dict]:
        """Fetch Microsoft Security Updates."""
        try:
            response = self.session.get(self.endpoints['microsoft_security'])
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching Microsoft Security Updates: {str(e)}")
            return None

    def fetch_malware_bazaar(self, query_type: str = "get_recent") -> Optional[Dict]:
        """Fetch recent malware data from MalwareBazaar."""
        try:
            data = {"query": query_type, "selector": 100}
            response = self.session.post(self.endpoints['malware_bazaar'], data=data)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching MalwareBazaar data: {str(e)}")
            return None

    def scrape_security_articles(self, url: str) -> Optional[Dict]:
        """
        Scrape cybersecurity articles from provided URL.
        
        Args:
            url: URL to scrape
            
        Returns:
            Dictionary containing scraped data or None if failed
        """
        try:
            response = self.session.get(url)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract relevant information (customize based on website structure)
            data = {
                'title': soup.title.string if soup.title else None,
                'text': soup.get_text(),
                'url': url,
                'timestamp': datetime.now().isoformat()
            }
            return data
        except (requests.exceptions.RequestException, AttributeError) as e:
            logger.error(f"Error scraping article from {url}: {str(e)}")
            return None

    def save_data(self, data: Union[Dict, List], source: str, format: str = 'json') -> bool:
        """
        Save collected data to file.
        
        Args:
            data: Data to save
            source: Source identifier for filename
            format: File format (json, xml, yaml)
            
        Returns:
            Boolean indicating success
        """
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = self.output_dir / f"{source}_{timestamp}.{format}"
            
            if format == 'json':
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2)
            elif format == 'xml':
                root = ET.Element("data")
                # Convert dictionary to XML (simplified version)
                for key, value in data.items():
                    child = ET.SubElement(root, key)
                    child.text = str(value)
                tree = ET.ElementTree(root)
                tree.write(filename)
            elif format == 'yaml':
                with open(filename, 'w', encoding='utf-8') as f:
                    yaml.dump(data, f, allow_unicode=True)
            elif format == 'csv':
                pd.DataFrame(data).to_csv(filename, index=False)
            
            logger.info(f"Successfully saved data to {filename}")
            return True
        except Exception as e:
            logger.error(f"Error saving data: {str(e)}")
            return False

def main():
    """Main function to demonstrate usage."""
    collector = CyberDataCollector()
    
    # Fetch and save data from various sources
    sources = {
        'cve_data': collector.fetch_cve_data,
        'nist_standards': collector.fetch_nist_standards,
        'mitre_attack': collector.fetch_mitre_attack,
        'capec_data': collector.fetch_capec_data,
        'ubuntu_security': collector.fetch_ubuntu_security_notices,
        'arxiv_papers': collector.fetch_arxiv_papers,
        'redhat_security': collector.fetch_redhat_security,
        'microsoft_security': collector.fetch_microsoft_security,
        'malware_bazaar': collector.fetch_malware_bazaar
    }

    for source_name, fetch_function in sources.items():
        logger.info(f"Fetching data from {source_name}...")
        data = fetch_function()
        if data:
            collector.save_data(data, source_name)
        else:
            logger.warning(f"No data retrieved from {source_name}")

if __name__ == "__main__":
    main() 