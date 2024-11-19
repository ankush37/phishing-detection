from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime, timedelta
import validators
import tldextract
from urllib.parse import urlparse
import urllib.request
from typing import Dict, List, Any, Optional
import os

# Import modularized components
from analyze.risk_analyzer import RiskAnalyzer
from analyze.security_checks import SecurityChecker
from utils.redis_client import get_redis_client
from utils.logger import setup_logger
from threat_intel.feed_manager import FeedManager
from config.default import Config

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Setup logging
logger = setup_logger('app')

# Initialize components
try:
    redis_client = get_redis_client()
    # Initialize FeedManager
    feed_manager = FeedManager(redis_client)
    # Start feed updates in background
    feed_manager.start_feed_updates()
except Exception as e:
    logger.error(f"Initialization failed: {str(e)}")
    redis_client = None
    feed_manager = None

security_checker = SecurityChecker()
risk_analyzer = RiskAnalyzer()

class URLCache:
    def __init__(self, redis_client):
        self.redis = redis_client
        self.default_expiration = Config.CACHE_EXPIRATION

    def generate_cache_key(self, url: str) -> str:
        """Generate a unique cache key for a URL"""
        from hashlib import md5
        normalized_url = url.lower().strip()
        return f"url_analysis:{md5(normalized_url.encode()).hexdigest()}"

    def get(self, url: str) -> Optional[Dict]:
        """Retrieve cached analysis results"""
        if not self.redis:
            return None
            
        cache_key = self.generate_cache_key(url)
        cached_data = self.redis.get(cache_key)
        
        if cached_data:
            try:
                return eval(cached_data)
            except:
                return None
        return None

    def set(self, url: str, analysis_result: Dict, expiration: int = None) -> None:
        """Cache analysis results"""
        if not self.redis:
            return
            
        cache_key = self.generate_cache_key(url)
        expiration = expiration or self.default_expiration
        
        try:
            self.redis.setex(cache_key, expiration, str(analysis_result))
        except Exception as e:
            logger.error(f"Cache setting error: {str(e)}")

    def delete(self, url: str) -> None:
        """Delete cached analysis results"""
        if not self.redis:
            return
            
        cache_key = self.generate_cache_key(url)
        self.redis.delete(cache_key)

class URLAnalyzer:
    def __init__(self):
        self.security_checker = SecurityChecker()
        self.risk_analyzer = RiskAnalyzer()

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


    def determine_risk_level(self, total_score: float) -> str:
        """Determine risk level based on total weighted score"""
        if total_score >= 80:
            return 'Critical'
        elif total_score >= 60:
            return 'High'
        elif total_score >= 40:
            return 'Medium'
        elif total_score >= 20:
            return 'Low'
        return 'Minimal'

    def calculate_threat_score(self, threat_intel: Dict) -> tuple[float, List[str]]:
        """Calculate threat intelligence score (weight: 0.35)"""
        threat_factors = []
        
        if not threat_intel.get('is_malicious'):
            return 0, threat_factors

        sources = threat_intel.get('sources', [])
        source_names = [source['feed'] for source in sources]
        threat_factors.append(f"URL found in threat feeds: {', '.join(source_names)}")
        
        # Calculate threat score based on sources
        threat_score = 100 if sources else 0
        
        return threat_score, threat_factors

    def analyze_url(self, url: str) -> Dict[str, Any]:
        """Main URL analysis method"""
        analysis_result = {
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'is_valid_url': False,
            'domain_info': {},
            'security_features': {},
            'risk_assessment': {},
            'redirect_chain': [],
            'recommendations': [],
            'threat_intel': {}
        }

        # Handle invalid URLs
        if not validators.url(url):
            analysis_result['risk_assessment'] = {
                'risk_factors': ['Invalid URL format'],
                'risk_score': 100,
                'risk_level': 'Critical',
                'category_scores': {
                    'domain_age': 100,
                    'ssl_score': 100,
                    'url_patterns': 100,
                    'threat_intel': 100
                }
            }
            return analysis_result

        analysis_result['is_valid_url'] = True
        
        # Extract and set domain information
        extracted = tldextract.extract(url)
        parsed_url = urlparse(url)
        analysis_result['domain_info'] = {
            'subdomain': extracted.subdomain,
            'domain': extracted.domain,
            'suffix': extracted.suffix,
            'full_domain': extracted.fqdn,
            'path': parsed_url.path,
            'query': parsed_url.query
        }

        # Get security features
        security_features = {
            'ssl_info': self.security_checker.get_ssl_info(extracted.fqdn),
            'domain_age': self.security_checker.get_domain_age(extracted.fqdn),
            'dns_records': self.security_checker.check_dns_records(extracted.fqdn)
        }
        analysis_result['security_features'] = security_features

        # Get base risk analysis
        risk_analysis = self.risk_analyzer.analyze_risk(
            url,
            analysis_result['domain_info'],
            security_features
        )
        
        # Get threat intelligence score
        threat_intel = feed_manager.check_url(url) if feed_manager else {'is_malicious': False, 'sources': []}
        analysis_result['threat_intel'] = threat_intel
        threat_score, threat_factors = self.calculate_threat_score(threat_intel)
        
        # Combine all scores using Config weights
        risk_scores = risk_analysis['risk_scores']
        risk_scores['threat_intel'] = threat_score
        
        # Calculate final score using Config.RISK_WEIGHTS
        final_score = sum(
            score * Config.RISK_WEIGHTS[category]
            for category, score in risk_scores.items()
        )

        # Apply whitelist reduction if applicable
        if self._is_whitelisted(analysis_result['domain_info']):
            final_score *= Config.WHITELIST_REDUCTION_FACTOR
            risk_analysis['risk_factors'].append('Score reduced due to whitelisted domain')

        # Set final risk assessment
        analysis_result['risk_assessment'] = {
            'risk_score': min(100, round(final_score, 2)),
            'risk_factors': risk_analysis['risk_factors'] + threat_factors,
            'risk_level': self.determine_risk_level(final_score),
            'category_scores': risk_scores
        }

        # Add redirect chain analysis
        redirect_chain = self.check_redirect_chain(url)
        if len(redirect_chain) > 1:
            analysis_result['redirect_chain'] = redirect_chain
            analysis_result['risk_assessment']['risk_factors'].append(
                f'Multiple redirects detected: {len(redirect_chain)} redirects'
            )

        # Generate recommendations
        self._generate_recommendations(analysis_result)
        
        return analysis_result
    
    def _is_whitelisted(self, domain_info: Dict) -> bool:
        """Check if domain is whitelisted"""
        trusted_tlds = {'gov', 'edu', 'mil'}
        return domain_info.get('suffix', '').lower() in trusted_tlds

    def _generate_recommendations(self, analysis_result: Dict) -> None:
        """Generate recommendations based on risk assessment"""
        recommendations = []
        risk_factors = analysis_result['risk_assessment'].get('risk_factors', [])
        
        for factor in risk_factors:
            if 'SSL' in factor:
                recommendations.append('Implement SSL/TLS security')
            elif 'domain age' in factor.lower():
                recommendations.append('Exercise caution with newly registered domains')
            elif 'redirect' in factor.lower():
                recommendations.append('Investigate redirect chain for potential security risks')
                
        analysis_result['recommendations'] = recommendations
    

# Initialize components
url_cache = URLCache(redis_client)
url_analyzer = URLAnalyzer()

@app.route('/api/analyze', methods=['POST'])
def analyze_url():
    """Endpoint for URL analysis"""
    try:
        data = request.get_json()
        
        if not data or 'url' not in data:
            return jsonify({
                'status': 'error',
                'error': 'No URL provided'
            }), 400

        url = data['url']
        force_refresh = data.get('force_refresh', False)
        
        if force_refresh:
            url_cache.delete(url)
            
        # Check cache first
        cached_result = url_cache.get(url)
        if cached_result and not force_refresh:
            cached_result['cache_hit'] = True
            return jsonify({
                'status': 'success',
                'data': cached_result
            })

        # Perform analysis
        result = url_analyzer.analyze_url(url)
        result['cache_hit'] = False
        
        # Cache the result
        url_cache.set(url, result)
        
        return jsonify({
            'status': 'success',
            'data': result
        })

    except Exception as e:
        logger.error(f"Analysis error: {str(e)}")
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    redis_status = "healthy" if redis_client else "unhealthy"
    feed_status = "healthy" if feed_manager else "unhealthy"
    
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'components': {
            'redis': redis_status,
            'security_checker': 'healthy',
            'risk_analyzer': 'healthy',
            'feed_manager': feed_status
        },
        'version': '3.1.0'
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True)