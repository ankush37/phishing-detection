import schedule
import threading
import time
from typing import Dict, List
from config.default import Config
from utils.logger import setup_logger
from threat_intel.phishtank_feed import PhishTankFeed
from threat_intel.openphish_feed import OpenPhishFeed
from threat_intel.urlhaus_feed import URLHausFeed

class FeedManager:
    def __init__(self, redis_client):
        self.redis_client = redis_client
        self.logger = setup_logger('feed_manager')
        self.feeds = {
            'phishtank': PhishTankFeed(),
            'openphish': OpenPhishFeed(),
            'urlhaus': URLHausFeed()
        }

    def update_feed(self, feed_name: str) -> None:
        feed = self.feeds.get(feed_name)
        if not feed:
            return

        urls = feed.fetch_feed()
        feed_key = f"threat_feed:{feed_name}"
        
        pipeline = self.redis_client.pipeline()
        pipeline.delete(feed_key)
        if urls:
            pipeline.sadd(feed_key, *urls)
            pipeline.expire(feed_key, Config.FEED_CACHE_DURATION)
            pipeline.set(
                f"{feed_key}:last_update",
                time.strftime('%Y-%m-%d %H:%M:%S')
            )
        pipeline.execute()
        
        self.logger.info(f"Updated {feed_name} feed with {len(urls)} entries")

    def update_all_feeds(self) -> None:
        for feed_name in self.feeds:
            self.update_feed(feed_name)

    def start_feed_updates(self) -> None:
        def run_schedule():
            while True:
                schedule.run_pending()
                time.sleep(60)

        schedule.every(Config.FEED_UPDATE_INTERVAL).seconds.do(
            self.update_all_feeds
        )
        
        self.update_all_feeds()  # Initial update
        
        thread = threading.Thread(target=run_schedule, daemon=True)
        thread.start()

    def check_url(self, url: str) -> Dict:
        results = {
            'is_malicious': False,
            'sources': []
        }

        for feed_name, feed in self.feeds.items():
            feed_key = f"threat_feed:{feed_name}"
            if self.redis_client.sismember(feed_key, url):
                results['is_malicious'] = True
                results['sources'].append({
                    'feed': feed_name,
                    'type': feed.feed_type
                })

        return results