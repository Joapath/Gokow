"""OPSEC utilities for Gokow."""

import asyncio
import random
import time
from typing import Dict, Any, List
from urllib.parse import urlparse


class OPSECManager:
    """Manages OPSEC measures to avoid detection."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.user_agents = self._load_user_agents()
        self.delays = config.get('delays', {'min': 1, 'max': 5})
        self.stealth_mode = config.get('stealth', False)

    def _load_user_agents(self) -> List[str]:
        """Load realistic user agents."""
        return [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
        ]

    def get_random_user_agent(self) -> str:
        """Get a random user agent."""
        return random.choice(self.user_agents)

    def apply_delay_sync(self) -> None:
        """
        Apply random delay synchronously.
        
        Use sparingly - prefer async version in scanners.
        """
        if self.stealth_mode:
            delay = random.uniform(self.delays['min'], self.delays['max'])
            time.sleep(delay)

    async def apply_delay(self) -> None:
        """
        Apply random delay asynchronously.
        
        Non-blocking version for async scanners.
        """
        if self.stealth_mode:
            delay = random.uniform(self.delays['min'], self.delays['max'])
            await asyncio.sleep(delay)

    def apply_to_request(self, request_kwargs: Dict[str, Any]) -> Dict[str, Any]:
        """Apply OPSEC measures to HTTP request."""
        headers = request_kwargs.get('headers', {})

        # Add random user agent
        if 'User-Agent' not in headers:
            headers['User-Agent'] = self.get_random_user_agent()

        # Add other stealth headers
        if self.stealth_mode:
            headers.update({
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
            })

        request_kwargs['headers'] = headers
        return request_kwargs

    def randomize_query_params(self, url: str) -> str:
        """Add random query parameters to URL for fingerprint evasion."""
        if not self.stealth_mode:
            return url

        parsed = urlparse(url)
        if parsed.query:
            return url  # Don't modify if already has query

        # Add random cache-busting param
        random_param = f"cache={random.randint(100000, 999999)}"
        return f"{url}?{random_param}"