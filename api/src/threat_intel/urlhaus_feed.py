from threat_intel.base_feed import BaseFeed
from config.default import Config
from typing import List

class URLHausFeed(BaseFeed):
    def __init__(self):
        super().__init__(
            name='urlhaus',
            url=Config.URLHAUS_URL,
            feed_type='malware'
        )

    def parse_feed(self, data: str) -> List[str]:
        return [
            line.strip() for line in data.split('\n')
            if line.strip() and not line.startswith('#')
        ]