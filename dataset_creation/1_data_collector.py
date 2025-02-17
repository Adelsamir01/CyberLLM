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
import time
import shutil

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class CyberDataCollector:
    def __init__(self, output_dir: str = "raw_data"):
        """Initialize the data collector with output directory configuration.
        
        Required API Keys (set as environment variables):
        - VIRUSTOTAL_API_KEY: Required for VirusTotal API access
        - ALIENVAULT_API_KEY: Required for AlienVault OTX API
        - HTB_API_KEY: Required for HackTheBox API
        
        Rate Limits:
        - CTFtime API: 30 requests per minute
        - NVD API: 5 requests per 30 seconds
        - VirusTotal API: Depends on subscription tier
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Load API keys from environment variables
        self.api_keys = {
            'virustotal': os.getenv('VIRUSTOTAL_API_KEY'),
            'alienvault': os.getenv('ALIENVAULT_API_KEY'),
            'hackthebox': os.getenv('HTB_API_KEY'),
            'malpedia': os.getenv('MALPEDIA_API_KEY'),
            'malshare': os.getenv('MALSHARE_API_KEY'),
            'shodan': os.getenv('SHODAN_API_KEY'),
            'phishtank': os.getenv('PHISHTANK_API_KEY'),
        }
        
        # Initialize rate limiting
        self.rate_limits = {
            'nvd_cve': {'requests': 5, 'period': 30},
            'ctftime': {'requests': 30, 'period': 60},
            'github': {'requests': 60, 'period': 3600},  # GitHub API limit
            'virustotal': {'requests': 4, 'period': 60},
            'shodan': {'requests': 1, 'period': 1},
            'malshare': {'requests': 25, 'period': 60},
        }
        self.last_request_time = {}
        
        # Add request timeout settings
        self.timeouts = {
            'default': 30,
            'download': 180,  # Longer timeout for downloading larger files
            'scraping': 60,   # Longer timeout for web scraping
        }
        
        # Add retry configurations
        self.retry_config = {
            'max_retries': 3,
            'base_delay': 5,
            'max_delay': 60,
            'exponential_backoff': True,
        }
        
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
            'malpedia': 'https://malpedia.caad.fkie.fraunhofer.de/api/v1/',
            'malshare': 'https://malshare.com/api.php',
            'thezoo': 'https://github.com/ytisf/theZoo/raw/master/malware.yml',
            'vxug': 'https://vx-underground.org/samples.html',
            
            # CTF Resources
            'ctftime': 'https://ctftime.org/api/v1/events/',
            'root_me': 'https://api.www.root-me.org/challenges',
            'hackthebox': 'https://www.hackthebox.com/api/v4/challenge/list',
            
            # Security Testing Resources
            'metasploit_modules': 'https://raw.githubusercontent.com/rapid7/metasploit-framework/master/modules/',
            'pentesterlab': 'https://pentesterlab.com/exercises/api/v1/',
            'vulnhub': 'https://www.vulnhub.com/api/v1/entries/',
            'offensive_security': 'https://offsec.tools/api/tools',
            'securitytube': 'https://www.securitytube.net/api/v1/videos',
            'pentestmonkey': 'https://github.com/pentestmonkey/php-reverse-shell/raw/master/php-reverse-shell.php',
            'payloadsallthethings': 'https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/',
            
            # Social Engineering Resources
            'phishtank': 'https://data.phishtank.com/data/online-valid.json',
            'openphish': 'https://openphish.com/feed.txt',
            'social_engineer_toolkit': 'https://github.com/trustedsec/social-engineer-toolkit/raw/master/src/templates/',
            'gophish': 'https://github.com/gophish/gophish/raw/master/templates/',
            
            # DoS/DDoS Resources
            'ddosdb': 'https://ddosdb.org/api/v1/',
            'netscout_atlas': 'https://atlas.netscout.com/api/v2/',
            
            # MITM & Injection Resources
            'bettercap': 'https://raw.githubusercontent.com/bettercap/bettercap/master/modules/',
            'sqlmap': 'https://raw.githubusercontent.com/sqlmapproject/sqlmap/master/data/',
            'nosqlmap': 'https://raw.githubusercontent.com/codingo/NoSQLMap/master/attacks/',
            
            # Zero-Day & Password Resources
            'zerodayinitiative': 'https://www.zerodayinitiative.com/rss/published/',
            'project_zero': 'https://bugs.chromium.org/p/project-zero/issues/list?rss=true',
            'rockyou': 'https://github.com/danielmiessler/SecLists/raw/master/Passwords/Leaked-Databases/',
            'hashcat': 'https://hashcat.net/hashcat/',
            
            # IoT Security Resources
            'iot_vulndb': 'https://www.exploit-db.com/download/iot/',
            'iot_sentinel': 'https://iotsentinel.csec.ch/api/v1/',
            'shodan_iot': 'https://api.shodan.io/shodan/host/search?key={}&query=iot',
        }
        
        # Initialize session for better performance
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'CyberLLMInstruct-DataCollector/1.0'
        })

    def _check_rate_limit(self, endpoint: str) -> None:
        """
        Implement rate limiting for APIs.
        Sleeps if necessary to respect rate limits.
        """
        if endpoint not in self.rate_limits:
            return
            
        current_time = time.time()
        if endpoint in self.last_request_time:
            elapsed = current_time - self.last_request_time[endpoint]
            limit = self.rate_limits[endpoint]
            if elapsed < (limit['period'] / limit['requests']):
                sleep_time = (limit['period'] / limit['requests']) - elapsed
                logger.debug(f"Rate limiting {endpoint}, sleeping for {sleep_time:.2f}s")
                time.sleep(sleep_time)
                
        self.last_request_time[endpoint] = current_time

    def _make_request(self, endpoint: str, url: str, params: Dict = None, headers: Dict = None, 
                     timeout: int = None, method: str = 'get', data: Dict = None) -> Optional[requests.Response]:
        """
        Enhanced request method with better error handling and retries.
        """
        self._check_rate_limit(endpoint)
        
        if headers is None:
            headers = {}
            
        # Add API keys to headers based on endpoint
        for key, value in self.api_keys.items():
            if endpoint.startswith(key) and value:
                if key == 'virustotal':
                    headers['x-apikey'] = value
                elif key == 'alienvault':
                    headers['X-OTX-API-KEY'] = value
                # ... add other API key headers as needed
        
        timeout = timeout or self.timeouts['default']
        retry_count = 0
        last_error = None
        
        while retry_count < self.retry_config['max_retries']:
            try:
                if method.lower() == 'get':
                    response = self.session.get(url, params=params, headers=headers, timeout=timeout)
                elif method.lower() == 'post':
                    response = self.session.post(url, params=params, headers=headers, json=data, timeout=timeout)
                
                response.raise_for_status()
                return response
                
            except requests.exceptions.RequestException as e:
                last_error = e
                retry_count += 1
                
                if retry_count == self.retry_config['max_retries']:
                    break
                    
                # Calculate delay with exponential backoff
                if self.retry_config['exponential_backoff']:
                    delay = min(
                        self.retry_config['base_delay'] * (2 ** (retry_count - 1)),
                        self.retry_config['max_delay']
                    )
                else:
                    delay = self.retry_config['base_delay']
                    
                logger.warning(f"Request failed (attempt {retry_count}/{self.retry_config['max_retries']}): {str(e)}")
                logger.info(f"Retrying in {delay} seconds...")
                time.sleep(delay)
        
        logger.error(f"All retry attempts failed for {url}: {str(last_error)}")
        return None

    def fetch_cve_data(self, start_index: int = 0, results_per_page: int = 2000) -> Optional[Dict]:
        """
        Fetch CVE data from NVD database.
        
        Note: Implements rate limiting of 5 requests per 30 seconds
        """
        try:
            params = {
                'startIndex': start_index,
                'resultsPerPage': results_per_page
            }
            response = self._make_request('nvd_cve', self.endpoints['nvd_cve'], params=params)
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching CVE data: {str(e)}")
            return None

    def fetch_nist_standards(self) -> Optional[Dict]:
        """
        Fetch NIST cyber security standards.
        
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
        """Fetch recent cyber security papers from arXiv."""
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

    def fetch_malware_data(self) -> Optional[Dict]:
        """
        Fetch malware data from various sources.
        
        Note: Some sources require API keys and may contain live malware samples.
        Use with caution in a controlled environment.
        """
        try:
            malware_data = {
                'timestamp': datetime.now().isoformat(),
                'sources': []
            }

            # Fetch from MalwareBazaar
            response = self._make_request('malware_bazaar', self.endpoints['malware_bazaar'], 
                                       data={"query": "get_recent", "selector": 100})
            if response:
                malware_data['sources'].append({
                    'source': 'MalwareBazaar',
                    'content': response.json()
                })

            # Fetch from Malpedia (requires API key)
            if self.api_keys.get('malpedia'):
                response = self._make_request('malpedia', self.endpoints['malpedia'],
                                           headers={'Authorization': f"apitoken {self.api_keys['malpedia']}"})
                if response:
                    malware_data['sources'].append({
                        'source': 'Malpedia',
                        'content': response.json()
                    })

            return malware_data

        except Exception as e:
            logger.error(f"Error fetching malware data: {str(e)}")
            return None

    def fetch_social_engineering_data(self) -> Optional[Dict]:
        """
        Fetch social engineering resources and phishing data.
        """
        try:
            se_data = {
                'timestamp': datetime.now().isoformat(),
                'sources': []
            }

            # Fetch from PhishTank
            response = self._make_request('phishtank', self.endpoints['phishtank'])
            if response:
                se_data['sources'].append({
                    'source': 'PhishTank',
                    'content': response.json()
                })

            # Fetch SET templates
            response = self._make_request('github', self.endpoints['social_engineer_toolkit'])
            if response:
                se_data['sources'].append({
                    'source': 'SET',
                    'content': response.text
                })

            return se_data

        except Exception as e:
            logger.error(f"Error fetching social engineering data: {str(e)}")
            return None

    def scrape_security_articles(self, url: str) -> Optional[Dict]:
        """
        Scrape cyber security articles from provided URL.
        
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
        Enhanced save_data method with better error handling and backup.
        """
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = self.output_dir / f"{source}_{timestamp}.{format}"
            
            # Create backup directory
            backup_dir = self.output_dir / 'backups'
            backup_dir.mkdir(exist_ok=True)
            
            # Save data with proper encoding and error handling
            if format == 'json':
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
                    f.flush()
                    os.fsync(f.fileno())  # Ensure data is written to disk
                    
            elif format == 'xml':
                # Improved XML handling
                root = ET.Element("data")
                self._dict_to_xml(data, root)
                tree = ET.ElementTree(root)
                tree.write(filename, encoding='utf-8', xml_declaration=True)
                
            elif format == 'yaml':
                with open(filename, 'w', encoding='utf-8') as f:
                    yaml.dump(data, f, allow_unicode=True, default_flow_style=False)
                    f.flush()
                    os.fsync(f.fileno())
                    
            elif format == 'csv':
                df = pd.DataFrame(data)
                df.to_csv(filename, index=False, encoding='utf-8')
            
            # Create backup
            backup_file = backup_dir / f"{source}_{timestamp}_backup.{format}"
            shutil.copy2(filename, backup_file)
            
            logger.info(f"Successfully saved data to {filename} with backup at {backup_file}")
            return True
            
        except Exception as e:
            logger.error(f"Error saving data: {str(e)}")
            return False

    def _dict_to_xml(self, data: Union[Dict, List, str, int, float], parent: ET.Element):
        """Helper method for converting dictionary to XML."""
        if isinstance(data, dict):
            for key, value in data.items():
                child = ET.SubElement(parent, str(key))
                self._dict_to_xml(value, child)
        elif isinstance(data, (list, tuple)):
            for item in data:
                child = ET.SubElement(parent, 'item')
                self._dict_to_xml(item, child)
        else:
            parent.text = str(data)

    def fetch_ctf_data(self) -> Optional[Dict]:
        """
        Fetch CTF event data and challenges from various platforms.
        
        Returns:
            Dictionary containing CTF data or None if failed
        """
        try:
            # Get upcoming and ongoing CTF events from CTFtime
            # CTFtime API requires start and end time parameters
            start_time = datetime.now()
            end_time = start_time + timedelta(days=90)  # Get events for next 90 days
            
            params = {
                'start': int(start_time.timestamp()),
                'finish': int(end_time.timestamp()),
                'limit': 100
            }
            
            response = self.session.get(self.endpoints['ctftime'], params=params)
            response.raise_for_status()
            ctftime_events = response.json()
            
            # Compile CTF data from different sources
            ctf_data = {
                'ctftime_events': ctftime_events,
                'timestamp': datetime.now().isoformat(),
                'metadata': {
                    'source': 'CTFtime API',
                    'event_timeframe': f"{start_time.date()} to {end_time.date()}"
                }
            }
            
            return ctf_data
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching CTF data: {str(e)}")
            return None

    def fetch_security_testing_resources(self) -> Optional[Dict]:
        """
        Fetch security testing scripts and resources from educational sources.
        
        Note: Some endpoints may be blocked by corporate firewalls or security policies.
        GitHub rate limits apply for raw.githubusercontent.com requests.
        """
        try:
            security_resources = {
                'timestamp': datetime.now().isoformat(),
                'resources': []
            }

            # Fetch PayloadsAllTheThings resources
            payload_categories = [
                'Web-Shells/README.md',
                'Methodology-and-Resources/Reverse-Shell-Cheatsheet.md',
                'SQL-Injection/README.md',
                'XSS-Injection/README.md'
            ]

            # Add error recovery - if some resources fail, continue with others
            for category in payload_categories:
                try:
                    response = self._make_request(
                        'github', 
                        f"{self.endpoints['payloadsallthethings']}{category}"
                    )
                    security_resources['resources'].append({
                        'category': category.split('/')[0],
                        'content': response.text,
                        'source': 'PayloadsAllTheThings'
                    })
                except requests.exceptions.RequestException as e:
                    logger.warning(f"Failed to fetch {category}: {str(e)}")
                    continue

            # Fetch Metasploit module list
            msf_categories = ['exploits', 'payloads', 'auxiliary']
            for category in msf_categories:
                response = self.session.get(f"{self.endpoints['metasploit_modules']}{category}")
                if response.status_code == 200:
                    security_resources['resources'].append({
                        'category': f'metasploit_{category}',
                        'content': response.text,
                        'source': 'Metasploit Framework'
                    })

            # Fetch VulnHub entries
            response = self.session.get(self.endpoints['vulnhub'])
            if response.status_code == 200:
                security_resources['resources'].append({
                    'category': 'vulnerable_machines',
                    'content': response.json(),
                    'source': 'VulnHub'
                })

            return security_resources

        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching security testing resources: {str(e)}")
            return None

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
        'malware_data': collector.fetch_malware_data,
        'social_engineering': collector.fetch_social_engineering_data,
        'ctf_data': collector.fetch_ctf_data,  # Add CTF data source
        'security_testing': collector.fetch_security_testing_resources,
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