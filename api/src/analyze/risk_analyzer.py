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
                    security_checks: Dict) -> Dict:
        """
        Analyzes various risk factors and returns raw scores
        Based on weights from Config.RISK_WEIGHTS:
            domain_age: 0.3
            ssl_score: 0.2
            url_patterns: 0.15
            threat_intel: 0.35
        """
        risk_factors = []
        risk_scores = {}
        
        # Domain age analysis (weight: 0.3)
        domain_age = security_checks.get('domain_age', {}).get('age_days', 0)
        if domain_age < 30:
            risk_factors.append(f'Domain is {domain_age} days old (less than 30 days)')
            risk_scores['domain_age'] = min(100, (30 - domain_age) * 3.33)
        elif domain_age < 90:
            risk_factors.append(f'Domain is relatively new ({domain_age} days old)')
            risk_scores['domain_age'] = min(100, (90 - domain_age) * 1.11)
        else:
            risk_scores['domain_age'] = 0

        # SSL analysis (weight: 0.2)
        ssl_info = security_checks.get('ssl_info', {})
        if not ssl_info.get('has_ssl'):
            risk_factors.append('No SSL/TLS security')
            risk_scores['ssl_score'] = 100
        elif not ssl_info.get('is_valid', True):
            risk_factors.append('Invalid SSL certificate')
            risk_scores['ssl_score'] = 80
        elif ssl_info.get('days_until_expiry', 30) < 7:
            risk_factors.append('SSL certificate near expiration')
            risk_scores['ssl_score'] = 50
        else:
            risk_scores['ssl_score'] = 0

        # URL Pattern analysis (weight: 0.15)
        pattern_matches = 0
        for pattern in self.suspicious_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                pattern_matches += 1
                risk_factors.append(f'Suspicious pattern detected: {pattern}')
        
        keyword_matches = 0
        url_lower = url.lower()
        for keyword in self.suspicious_keywords:
            if keyword in url_lower:
                keyword_matches += 1
                risk_factors.append(f'Suspicious keyword detected: {keyword}')
        
        # Calculate URL pattern score
        risk_scores['url_patterns'] = min(100, (pattern_matches * 20) + (keyword_matches * 15))

        return {
            'risk_scores': risk_scores,
            'risk_factors': risk_factors
        }
