from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime, timedelta
import validators
import tldextract
import requests
import re
from urllib.parse import urlparse
import whois
import dns.resolver
import socket
import ssl
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
import hashlib
import urllib.request
import redis
import json
from functools import wraps
import time
import os
from datetime import datetime, date, timedelta


app = Flask(__name__)
CORS(app)
# Get Redis configuration from environment variables
REDIS_HOST = os.getenv('REDIS_HOST', 'redis')  # Default to 'redis' service name
REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))
REDIS_DB = int(os.getenv('REDIS_DB', 0))
CACHE_EXPIRATION = int(os.getenv('CACHE_EXPIRATION', 3600))

def get_redis_client(max_retries=5, retry_delay=2):
    for attempt in range(max_retries):
        try:
            client = redis.Redis(
                host=REDIS_HOST,
                port=REDIS_PORT,
                db=REDIS_DB,
                decode_responses=True,
                socket_timeout=5,
                socket_connect_timeout=5
            )
            client.ping()  # Test connection
            return client
        except redis.ConnectionError as e:
            if attempt == max_retries - 1:
                app.logger.error(f"Failed to connect to Redis after {max_retries} attempts: {str(e)}")
                raise
            app.logger.warning(f"Redis connection attempt {attempt + 1} failed, retrying in {retry_delay} seconds...")
            time.sleep(retry_delay)

try:
    redis_client = get_redis_client()
except redis.ConnectionError:
    app.logger.error("Unable to establish Redis connection. Running without cache.")
    redis_client = None

class URLCache:
    def __init__(self, redis_client):
        self.redis = redis_client
        self.default_expiration = CACHE_EXPIRATION

    def delete(self, url: str) -> None:

        """Delete cached analysis results for a URL"""

        cache_key = self.generate_cache_key(url)

        self.redis.delete(cache_key)

    def generate_cache_key(self, url: str) -> str:
        """Generate a unique cache key for a URL"""
        normalized_url = url.lower().strip()
        return f"url_analysis:{hashlib.md5(normalized_url.encode()).hexdigest()}"

    def get(self, url: str) -> Optional[Dict]:
        """Retrieve cached analysis results for a URL"""
        cache_key = self.generate_cache_key(url)
        cached_data = self.redis.get(cache_key)
        
        if cached_data:
            try:
                return json.loads(cached_data)
            except json.JSONDecodeError:
                return None
        return None

    def datetime_handler(self, obj):
        """Handler for datetime objects during JSON serialization"""
        if isinstance(obj, (datetime, date)):  # Now date is properly imported
            return obj.isoformat()
        raise TypeError(f"Object of type {type(obj)} is not JSON serializable")

    def set(self, url: str, analysis_result: Dict, expiration: int = None) -> None:
        """Cache analysis results for a URL with proper datetime handling"""
        cache_key = self.generate_cache_key(url)
        expiration = expiration or self.default_expiration
        
        try:
            # Convert all datetime objects in the analysis result
            current_time = datetime.now()
            expire_time = current_time + timedelta(seconds=expiration)
            
            # Deep copy the analysis result to avoid modifying the original
            result_to_cache = analysis_result.copy()
            
            # Add timestamp information
            result_to_cache['cached_at'] = current_time.isoformat()
            result_to_cache['cache_expiration'] = expire_time.isoformat()
            
            # Handle datetime objects in security features
            if 'security_features' in result_to_cache:
                domain_age = result_to_cache['security_features'].get('domain_age', {})
                if domain_age:
                    if 'creation_date' in domain_age:
                        creation_date = domain_age['creation_date']
                        if creation_date:
                            domain_age['creation_date'] = (
                                creation_date.isoformat() if isinstance(creation_date, (datetime, date))
                                else creation_date
                            )
                    if 'expiration_date' in domain_age:
                        expiration_date = domain_age['expiration_date']
                        if expiration_date:
                            domain_age['expiration_date'] = (
                                expiration_date.isoformat() if isinstance(expiration_date, (datetime, date))
                                else expiration_date
                            )
            
            # Serialize with custom handler for any remaining datetime objects
            cached_data = json.dumps(result_to_cache, default=self.datetime_handler)
            
            self.redis.setex(
                cache_key,
                expiration,
                cached_data
            )
        except Exception as e:
            app.logger.error(f"Cache setting error: {str(e)}")


class CacheStats:
    def __init__(self, redis_client):
        self.redis = redis_client
        self.stats_key = "url_analysis:stats"
        
    def increment_hit(self):
        """Increment cache hit counter"""
        self.redis.hincrby(self.stats_key, "hits", 1)
        
    def increment_miss(self):
        """Increment cache miss counter"""
        self.redis.hincrby(self.stats_key, "misses", 1)
        
    def get_stats(self) -> Dict:
        """Get cache statistics"""
        stats = self.redis.hgetall(self.stats_key)
        return {
            "hits": int(stats.get("hits", 0)),
            "misses": int(stats.get("misses", 0)),
            "total_requests": int(stats.get("hits", 0)) + int(stats.get("misses", 0))
        }

# Initialize cache and stats
url_cache = URLCache(redis_client)
cache_stats = CacheStats(redis_client)

def cache_decorator(expiration=None):
    """Decorator for caching function results"""
    def decorator(func):
        @wraps(func)
        def wrapper(self, url: str, *args, **kwargs):
            # Check cache first
            cached_result = url_cache.get(url)
            
            if cached_result:
                cache_stats.increment_hit()
                cached_result['cache_hit'] = True
                return cached_result
            
            # If not in cache, execute function and cache result
            cache_stats.increment_miss()
            result = func(self, url, *args, **kwargs)
            url_cache.set(url, result, expiration)
            result['cache_hit'] = False
            
            return result
        return wrapper
    return decorator

@dataclass
class SecurityFeatures:
    ssl_info: Dict
    domain_age: int
    dns_records: Dict
    registration_details: Dict

class URLAnalyzer:
    def __init__(self):
 
        self.suspicious_patterns = [
            r'paypal.*\.com',
            r'.*\.tk$',
            r'\d{4,}',
            r'.*-.*\.com',
            r'.*\.temp\..+',
            r'.*\.xyz$',
            r'.*\.(work|click|loan|top|gq|ml|ga|cf)$',
            r'.*\.(zip|review|country|kim|cricket|science|party)$',
            r'.*\.(bank|secure|account|login|signin|security).*'
        ]
        
        self.suspicious_keywords = [
            'login', 'signin', 'security', 'update', 'verify',
            'authenticate', 'account', 'banking', 'password',
            'credential', 'confirm', 'verification'
        ]

        self.legitimate_tlds = {
            'com', 'org', 'net', 'edu', 'gov', 'mil',
            'int', 'eu', 'uk', 'us', 'ca', 'au'
        }

    def get_ssl_info(self, domain: str) -> Dict:
        """Check SSL certificate information"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Extract common name from subject
                    subject_cn = ''
                    if cert.get('subject'):
                        for field in cert['subject']:
                            if field[0][0] == 'commonName':
                                subject_cn = field[0][1]
                                break
                    
                    # Extract issuer information
                    issuer_cn = ''
                    issuer_org = ''
                    if cert.get('issuer'):
                        for field in cert['issuer']:
                            for item in field:
                                if item[0] == 'commonName':
                                    issuer_cn = item[1]
                                elif item[0] == 'organizationName':
                                    issuer_org = item[1]
                    
                    # Format expiry date
                    expiry_date = datetime.strptime(
                        cert['notAfter'],
                        '%b %d %H:%M:%S %Y GMT'
                    ) if cert.get('notAfter') else None
                    
                    # Get alternative names
                    alt_names = []
                    if cert.get('subjectAltName'):
                        alt_names = [name[1] for name in cert['subjectAltName'] if name[0] == 'DNS']
                    
                    return {
                        'issued_to': subject_cn,
                        'issuer': {
                            'common_name': issuer_cn,
                            'organization': issuer_org
                        },
                        'version': cert.get('version', ''),
                        'has_ssl': True,
                        'expiry_date': expiry_date.isoformat() if expiry_date else '',
                        'serial_number': cert.get('serialNumber', ''),
                        'alt_names': alt_names,
                        'ocsp_servers': cert.get('OCSP', []),
                        'ca_issuers': cert.get('caIssuers', [])
                    }
        except Exception as e:
            return {
                'has_ssl': False,
                'error': str(e)
            }
    
    def get_domain_age(self, domain: str) -> Dict:
        """Get domain registration age and details"""
        try:
            w = whois.whois(domain)
            creation_date = w.creation_date
            expiration_date = w.expiration_date
            
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            age = (datetime.now() - creation_date).days if creation_date else 0
            
            return {
                'age_days': age,
                'registrar': w.registrar,
                'creation_date': creation_date,
                'expiration_date': expiration_date,
            }
        except Exception:
            return {'age_days': 0, 'error': 'Unable to fetch domain age'}

    def check_dns_records(self, domain: str) -> Dict:
        """Check various DNS records"""
        records = {}
        try:
            # A Record
            a_records = dns.resolver.resolve(domain, 'A')
            records['A'] = [str(r) for r in a_records]
            
            # MX Record
            try:
                mx_records = dns.resolver.resolve(domain, 'MX')
                records['MX'] = [str(r) for r in mx_records]
            except:
                records['MX'] = []
            
            # TXT Record
            try:
                txt_records = dns.resolver.resolve(domain, 'TXT')
                records['TXT'] = [str(r) for r in txt_records]
            except:
                records['TXT'] = []
                
            return records
        except Exception as e:
            return {'error': str(e)}

    def check_redirect_chain(self, url: str, max_redirects: int = 5) -> List[str]:
        """Check URL redirect chain"""
        redirect_chain = []
        try:
            opener = urllib.request.build_opener(urllib.request.HTTPRedirectHandler())
            opener.addheaders = [('User-Agent', 'Mozilla/5.0')]
            response = opener.open(url)
            redirect_chain = [response.geturl()]
        except Exception as e:
            pass
        return redirect_chain

    @cache_decorator(expiration=CACHE_EXPIRATION)
    def analyze_url(self, url: str) -> Dict[str, Any]:
        """Main URL analysis method with caching"""
        analysis_result = {
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'is_valid_url': False,
            'domain_info': {},
            'security_features': {},
            'risk_factors': [],
            'risk_score': 0,
            'redirect_chain': [],
            'recommendations': []
        }

        if not validators.url(url):
            analysis_result['risk_factors'].append('Invalid URL format')
            analysis_result['risk_score'] = 100
            return analysis_result

        analysis_result['is_valid_url'] = True
        
        # Extract domain information
        extracted = tldextract.extract(url)
        parsed_url = urlparse(url)
        
        # Basic domain info
        domain_info = {
            'subdomain': extracted.subdomain,
            'domain': extracted.domain,
            'suffix': extracted.suffix,
            'full_domain': extracted.fqdn,
            'path': parsed_url.path,
            'query': parsed_url.query
        }
        analysis_result['domain_info'] = domain_info

        # Security checks
        security_features = {
            'ssl_info': self.get_ssl_info(extracted.fqdn),
            'domain_age': self.get_domain_age(extracted.fqdn),
            'dns_records': self.check_dns_records(extracted.fqdn)
        }
        analysis_result['security_features'] = security_features

        # Risk scoring
        risk_score = 0
        
        # 1. URL Structure Analysis
        if len(url) > 100:
            analysis_result['risk_factors'].append('Unusually long URL')
            risk_score += 15
            analysis_result['recommendations'].append('Consider using a shorter URL')

        # 2. Domain Age Analysis
        domain_age = security_features['domain_age'].get('age_days', 0)
        if domain_age < 30:
            analysis_result['risk_factors'].append('Domain is less than 30 days old')
            risk_score += 25
            analysis_result['recommendations'].append('Exercise caution with newly registered domains')

        # 3. SSL/TLS Analysis
        if not security_features['ssl_info'].get('has_ssl', False):
            analysis_result['risk_factors'].append('No SSL/TLS security')
            risk_score += 30
            analysis_result['recommendations'].append('Implement SSL/TLS security')

        # 4. Suspicious Pattern Analysis
        for pattern in self.suspicious_patterns:
            if re.search(pattern, extracted.fqdn, re.IGNORECASE):
                analysis_result['risk_factors'].append(f'Suspicious pattern detected: {pattern}')
                risk_score += 20

        # 5. Special Character Analysis
        special_chars = re.findall(r'[^a-zA-Z0-9-.]', extracted.fqdn)
        if special_chars:
            analysis_result['risk_factors'].append('Contains special characters in domain')
            risk_score += 15
            analysis_result['recommendations'].append('Avoid special characters in domain name')

        # 6. TLD Analysis
        if extracted.suffix not in self.legitimate_tlds:
            analysis_result['risk_factors'].append('Suspicious TLD')
            risk_score += 20
            analysis_result['recommendations'].append('Consider using more established TLDs')

        # 7. Keyword Analysis
        domain_text = f"{extracted.domain}.{extracted.suffix}".lower()
        suspicious_keywords_found = [k for k in self.suspicious_keywords if k in domain_text]
        if suspicious_keywords_found:
            analysis_result['risk_factors'].append(f'Suspicious keywords found: {suspicious_keywords_found}')
            risk_score += 15

        # 8. DNS Record Analysis
        if not security_features['dns_records'].get('MX', []):
            analysis_result['risk_factors'].append('No MX records found')
            risk_score += 10

        # Check redirect chain
        redirect_chain = self.check_redirect_chain(url)
        if len(redirect_chain) > 1:
            analysis_result['risk_factors'].append('Multiple redirects detected')
            risk_score += 15
            analysis_result['redirect_chain'] = redirect_chain

        # Normalize risk score to 0-100
        analysis_result['risk_score'] = min(100, risk_score)

        # Add risk level classification
        if analysis_result['risk_score'] >= 80:
            analysis_result['risk_level'] = 'Critical'
        elif analysis_result['risk_score'] >= 60:
            analysis_result['risk_level'] = 'High'
        elif analysis_result['risk_score'] >= 40:
            analysis_result['risk_level'] = 'Medium'
        else:
            analysis_result['risk_level'] = 'Low'
        
        return analysis_result

analyzer = URLAnalyzer()

@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        data = request.get_json()
        
        if not data or 'url' not in data:
            return jsonify({
                'error': 'No URL provided',
                'status': 'error'
            }), 400

        url = data['url']
        force_refresh = data.get('force_refresh', False)
        
        if force_refresh:
            # Delete existing cache entry if force refresh is requested
            url_cache.delete(url)
        
        result = analyzer.analyze_url(url)
        
        return jsonify({
            'status': 'success',
            'data': result
        })

    except Exception as e:
        return jsonify({
            'error': str(e),
            'status': 'error'
        }), 500

@app.route('/cache/stats', methods=['GET'])
def get_cache_stats():
    """Endpoint to get cache statistics"""
    stats = cache_stats.get_stats()
    return jsonify({
        'status': 'success',
        'data': stats
    })

@app.route('/cache/clear', methods=['POST'])
def clear_cache():
    """Endpoint to clear the entire cache"""
    try:
        redis_client.flushdb()
        return jsonify({
            'status': 'success',
            'message': 'Cache cleared successfully'
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Enhanced health check endpoint with cache status"""
    redis_status = "healthy"
    try:
        redis_client.ping()
    except redis.ConnectionError:
        redis_status = "unhealthy"

    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '2.0.0',
        'cache_status': redis_status
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True)