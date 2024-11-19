from threat_intel.base_feed import BaseFeed
from typing import List
from config.default import Config

class OpenPhishFeed(BaseFeed):
    def __init__(self):
        super().__init__(
            name='openphish',
            url=Config.OPENPHISH_URL,
            feed_type='phishing'
        )

    def parse_feed(self, data: str) -> List[str]:
        return [line.strip() for line in data.split('\n') if line.strip()]