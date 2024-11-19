from datetime import timedelta
import os

class Config:
    # Redis Configuration
    REDIS_HOST = os.getenv('REDIS_HOST', 'redis')
    REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))
    REDIS_DB = int(os.getenv('REDIS_DB', 0))
    
    # Cache Configuration
    CACHE_EXPIRATION = int(os.getenv('CACHE_EXPIRATION', 3600))
    
    # Threat Intelligence Configuration
    FEED_UPDATE_INTERVAL = int(os.getenv('FEED_UPDATE_INTERVAL', 21600))  # 6 hours in seconds
    FEED_CACHE_DURATION = int(os.getenv('FEED_CACHE_DURATION', 86400))    # 24 hours in seconds
    
    # Feed URLs
    PHISHTANK_URL = os.getenv('PHISHTANK_URL', 'https://data.phishtank.com/data/online-valid.json')
    OPENPHISH_URL = os.getenv('OPENPHISH_URL', 'https://openphish.com/feed.txt')
    URLHAUS_URL = os.getenv('URLHAUS_URL', 'https://urlhaus.abuse.ch/downloads/text_recent/')
    
    # Logging Configuration
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    
    # Risk Scoring Configuration
    RISK_WEIGHTS = {
        'domain_age': float(os.getenv('WEIGHT_DOMAIN_AGE', '0.3')),
        'ssl_score': float(os.getenv('WEIGHT_SSL', '0.2')),
        'url_patterns': float(os.getenv('WEIGHT_URL_PATTERNS', '0.15')),
    }
    
    # Whitelist Configuration
    WHITELIST_REDUCTION_FACTOR = float(os.getenv('WHITELIST_REDUCTION_FACTOR', '0.5'))
