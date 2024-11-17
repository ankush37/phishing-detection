import pytest
from src.app import URLAnalyzer

def test_valid_url():
    analyzer = URLAnalyzer()
    result = analyzer.analyze_url('https://www.example.com')
    assert result['is_valid_url'] == True
    assert result['domain_info']['domain'] == 'example'

def test_invalid_url():
    analyzer = URLAnalyzer()
    result = analyzer.analyze_url('not-a-url')
    assert result['is_valid_url'] == False

def test_suspicious_url():
    analyzer = URLAnalyzer()
    result = analyzer.analyze_url('http://paypal-secure123.tk')
    assert len(result['risk_factors']) > 0
    assert result['risk_score'] > 50