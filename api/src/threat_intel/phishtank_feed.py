from threat_intel.base_feed import BaseFeed
import json
from config.default import Config
from typing import List

class PhishTankFeed(BaseFeed):
    def __init__(self):
        super().__init__(
            name='phishtank',
            url=Config.PHISHTANK_URL,
            feed_type='phishing'
        )

    def parse_feed(self, data: str) -> List[str]:
        try:
            entries = json.loads(data)
            return [entry['url'] for entry in entries]
        except Exception as e:
            self.logger.error(f"Error parsing PhishTank data: {str(e)}")
            return []