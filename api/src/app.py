from flask import Flask, request, jsonify
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

app = Flask(__name__)

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

    def generate_cache_key(self, url: str) -> str:
        """Generate a unique cache key for a URL"""
        # Normalize URL to ensure consistent caching
        normalized_url = url.lower().strip()
        # Create hash to handle long URLs and special characters
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

    def set(self, url: str, analysis_result: Dict, expiration: int = None) -> None:
        """Cache analysis results for a URL"""
        cache_key = self.generate_cache_key(url)
        expiration = expiration or self.default_expiration
        
        try:
            # Add timestamp to cached data
            analysis_result['cached_at'] = datetime.now().isoformat()
            analysis_result['cache_expiration'] = (
                datetime.now() + timedelta(seconds=expiration)
            ).isoformat()
            
            self.redis.setex(
                cache_key,
                expiration,
                json.dumps(analysis_result)
            )
        except Exception as e:
            app.logger.error(f"Cache setting error: {str(e)}")

    def delete(self, url: str) -> None:
        """Delete cached analysis results for a URL"""
        cache_key = self.generate_cache_key(url)
        self.redis.delete(cache_key)

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

    @cache_decorator(expiration=CACHE_EXPIRATION)
    def analyze_url(self, url: str) -> Dict[str, Any]:
        """Main URL analysis method with caching"""
        # Previous analysis code remains the same
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