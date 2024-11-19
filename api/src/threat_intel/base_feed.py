from abc import ABC, abstractmethod
from typing import List, Dict
import requests
from utils.logger import setup_logger

class BaseFeed(ABC):
    def __init__(self, name: str, url: str, feed_type: str):
        self.name = name
        self.url = url
        self.feed_type = feed_type
        self.logger = setup_logger(f'feed.{name}')

    @abstractmethod
    def parse_feed(self, data: str) -> List[str]:
        pass

    def fetch_feed(self) -> List[str]:
        try:
            response = requests.get(self.url, timeout=30)
            response.raise_for_status()
            return self.parse_feed(response.text)
        except Exception as e:
            self.logger.error(f"Error fetching {self.name} feed: {str(e)}")
            return []