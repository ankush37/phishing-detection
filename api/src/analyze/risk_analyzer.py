from typing import Dict, List
import re
from config.default import Config
from utils.logger import setup_logger

logger = setup_logger('risk_analyzer')

class RiskAnalyzer:
    def __init__(self):
        self.suspicious_patterns = [
            r'paypal.*\.com',
            r'.*\.tk$',
            r'\d{4,}',
            r'.*-.*\.com',
            r'.*\.temp\..+',
            r'.*\.xyz$',
            r'.*\.(work|click|loan|top|gq|ml|ga|cf)$'
        ]
        
        self.suspicious_keywords = [
            'login', 'signin', 'security', 'update', 'verify',
            'authenticate', 'account', 'banking', 'password'
        ]

    def analyze_risk(self, url: str, domain_info: Dict, 
                    security_checks: Dict, threat_intel: Dict) -> Dict:
        risk_factors = []
        risk_score = 0
        
        # Domain age analysis
        domain_age = security_checks.get('domain_age', {}).get('age_days', 0)
        if domain_age < 30:
            risk_factors.append('Domain is less than 30 days old')
            risk_score += 30 * Config.RISK_WEIGHTS['domain_age']

        # SSL analysis
        ssl_info = security_checks.get('ssl_info', {})
        if not ssl_info.get('has_ssl'):
            risk_factors.append('No SSL/TLS security')
            risk_score += 25 * Config.RISK_WEIGHTS['ssl_score']

        # Pattern analysis
        for pattern in self.suspicious_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                risk_factors.append(f'Suspicious pattern detected: {pattern}')
                risk_score += 20 * Config.RISK_WEIGHTS['url_patterns']

        # Threat intelligence
        if threat_intel.get('is_malicious'):
            risk_factors.append('URL found in threat feeds')
            risk_score += 40 * Config.RISK_WEIGHTS['threat_intel']

        return {
            'risk_score': min(100, risk_score),
            'risk_factors': risk_factors,
            'risk_level': self._get_risk_level(risk_score)
        }

    def _get_risk_level(self, score: float) -> str:
        if score >= 80:
            return 'Critical'
        elif score >= 60:
            return 'High'
        elif score >= 40:
            return 'Medium'
        return 'Low'
