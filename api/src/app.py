from flask import Flask, request, jsonify
from datetime import datetime
import validators
import tldextract
import requests
import re
from urllib.parse import urlparse

app = Flask(__name__)

class URLAnalyzer:
    def __init__(self):
        self.suspicious_patterns = [
            r'paypal.*\.com',  # Suspicious PayPal domains
            r'.*\.tk$',        # .tk domains (often used in phishing)
            r'.*\d+.*\.com',   # Domains with numbers
            r'.*-.*\.com'      # Domains with hyphens
        ]
        
    def analyze_url(self, url):
        analysis_result = {
            'url': url,
            'is_valid_url': False,
            'domain_info': {},
            'risk_factors': [],
            'risk_score': 0
        }
        
        # Check if URL is valid
        if not validators.url(url):
            analysis_result['risk_factors'].append('Invalid URL format')
            return analysis_result
            
        analysis_result['is_valid_url'] = True
        
        # Extract domain information
        extracted = tldextract.extract(url)
        domain_info = {
            'subdomain': extracted.subdomain,
            'domain': extracted.domain,
            'suffix': extracted.suffix,
            'full_domain': extracted.fqdn
        }
        analysis_result['domain_info'] = domain_info
        
        # Check URL length
        if len(url) > 100:
            analysis_result['risk_factors'].append('Unusually long URL')
            analysis_result['risk_score'] += 20
            
        # Check for suspicious patterns
        for pattern in self.suspicious_patterns:
            if re.match(pattern, extracted.fqdn):
                analysis_result['risk_factors'].append(f'Suspicious pattern detected: {pattern}')
                analysis_result['risk_score'] += 25
                
        # Check for SSL/TLS
        parsed_url = urlparse(url)
        if parsed_url.scheme != 'https':
            analysis_result['risk_factors'].append('No SSL/TLS security')
            analysis_result['risk_score'] += 30
            
        # Check for special characters
        special_chars = re.findall(r'[^a-zA-Z0-9-.]', extracted.fqdn)
        if special_chars:
            analysis_result['risk_factors'].append('Contains special characters in domain')
            analysis_result['risk_score'] += 15
            
        return analysis_result

analyzer = URLAnalyzer()

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    
    if not data or 'url' not in data:
        return jsonify({'error': 'No URL provided'}), 400
        
    url = data['url']
    result = analyzer.analyze_url(url)
    
    return jsonify(result)

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy', 'timestamp': datetime.now().isoformat()})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True)