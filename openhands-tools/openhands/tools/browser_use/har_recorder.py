"""
HAR Recorder - Records network traffic to HAR file via Playwright.

This module provides a simple wrapper that connects to an existing browser
(via CDP URL) and records network traffic using Playwright's HAR recording.
"""

import asyncio
from pathlib import Path
from typing import Optional

from playwright.async_api import async_playwright, Browser, BrowserContext, Page, Playwright


class HarRecorder:
    """Records network traffic to HAR file via Playwright context."""
    
    def __init__(self, har_path: str | Path):
        """Initialize HAR recorder.
        
        Args:
            har_path: Path where HAR file will be saved
        """
        self.har_path = Path(har_path)
        self.har_path.parent.mkdir(parents=True, exist_ok=True)
        
        self._playwright: Optional[Playwright] = None
        self._browser: Optional[Browser] = None
        self._context: Optional[BrowserContext] = None
        self._page: Optional[Page] = None
        self._started = False
    
    async def start(self, cdp_url: str) -> None:
        """Connect to browser and start HAR recording.
        
        Args:
            cdp_url: CDP WebSocket URL of the browser to connect to
        """
        if self._started:
            return
        
        # Start Playwright
        self._playwright = await async_playwright().start()
        
        # Connect to existing browser via CDP
        self._browser = await self._playwright.chromium.connect_over_cdp(cdp_url)
        
        # Create new context with HAR recording
        self._context = await self._browser.new_context(
            record_har_path=str(self.har_path),
            record_har_content="embed",  # Embed content in HAR
        )
        
        # Create a page in the context (required for HAR to capture traffic)
        self._page = await self._context.new_page()
        
        self._started = True
    
    async def navigate(self, url: str) -> None:
        """Navigate the recording page to URL.
        
        This mirrors navigation from the main browser to capture traffic.
        
        Args:
            url: URL to navigate to
        """
        if self._page and self._started:
            try:
                await self._page.goto(url, wait_until="domcontentloaded", timeout=30000)
            except Exception:
                pass  # Ignore navigation errors - HAR still captures the attempt
    
    async def stop(self) -> Path:
        """Stop recording and save HAR file.
        
        Returns:
            Path to the saved HAR file
        """
        if not self._started:
            return self.har_path
        
        try:
            # Close context - this triggers HAR save
            if self._context:
                await self._context.close()
                self._context = None
            
            # Disconnect from browser (don't close it - browser-use owns it)
            if self._browser:
                self._browser = None
            
            # Stop Playwright
            if self._playwright:
                await self._playwright.stop()
                self._playwright = None
                
        except Exception as e:
            # Import logger to avoid circular dependency issues at top level
            from openhands.sdk import get_logger
            logger = get_logger(__name__)
            logger.error(f"Error stopping HAR recorder: {e}")
            pass  # Best effort cleanup
        
        self._started = False
        return self.har_path
    
    @property
    def is_recording(self) -> bool:
        """Check if currently recording."""
        return self._started
