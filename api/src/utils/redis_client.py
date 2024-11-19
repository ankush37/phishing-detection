import redis
from config.default import Config
import time
from utils.logger import setup_logger

logger = setup_logger('redis_client')

def get_redis_client(max_retries=5, retry_delay=2):
    for attempt in range(max_retries):
        try:
            client = redis.Redis(
                host=Config.REDIS_HOST,
                port=Config.REDIS_PORT,
                db=Config.REDIS_DB,
                decode_responses=True,
                socket_timeout=5,
                socket_connect_timeout=5
            )
            client.ping()
            return client
        except redis.ConnectionError as e:
            if attempt == max_retries - 1:
                logger.error(f"Failed to connect to Redis after {max_retries} attempts: {str(e)}")
                raise
            logger.warning(f"Redis connection attempt {attempt + 1} failed, retrying in {retry_delay} seconds...")
            time.sleep(retry_delay)