from typing import Dict
import ssl
import socket
import whois
import dns.resolver
from datetime import datetime
from utils.logger import setup_logger

logger = setup_logger('security_checks')

class SecurityChecker:
    @staticmethod
    def get_ssl_info(domain: str) -> Dict:
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    return {
                        'has_ssl': True,
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'subject': dict(x[0] for x in cert['subject']),
                        'version': cert.get('version', ''),
                        'serialNumber': cert.get('serialNumber', ''),
                        'notBefore': cert.get('notBefore', ''),
                        'notAfter': cert.get('notAfter', '')
                    }
        except Exception as e:
            logger.error(f"SSL check error for {domain}: {str(e)}")
            return {'has_ssl': False, 'error': str(e)}

    @staticmethod
    def get_domain_age(domain: str) -> Dict:
        try:
            w = whois.whois(domain)
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            age = (datetime.now() - creation_date).days if creation_date else 0
            
            return {
                'age_days': age,
                'registrar': w.registrar,
                'creation_date': creation_date,
                'expiration_date': w.expiration_date
            }
        except Exception as e:
            logger.error(f"Domain age check error for {domain}: {str(e)}")
            return {'age_days': 0, 'error': str(e)}

    @staticmethod
    def check_dns_records(domain: str) -> Dict:
        records = {}
        try:
            for record_type in ['A', 'MX', 'TXT', 'NS']:
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    records[record_type] = [str(rdata) for rdata in answers]
                except dns.exception.DNSException:
                    records[record_type] = []
            return records
        except Exception as e:
            logger.error(f"DNS check error for {domain}: {str(e)}")
            return {'error': str(e)}
