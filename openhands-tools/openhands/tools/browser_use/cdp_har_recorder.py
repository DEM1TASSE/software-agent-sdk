"""
CDP-based HAR Recorder - Records network traffic to HAR file via CDP Network domain.

This module uses Chrome DevTools Protocol to capture ALL network traffic from
the browser-use session, including POST requests from form submissions.

Unlike the previous Playwright-based HarRecorder which created a separate context,
this approach listens to network events on the ACTUAL browser context where
the agent operates.
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


logger = logging.getLogger(__name__)


class CdpHarRecorder:
    """Records network traffic to HAR file via CDP Network domain events."""
    
    def __init__(self, har_path: str | Path):
        """Initialize CDP HAR recorder.
        
        Args:
            har_path: Path where HAR file will be saved
        """
        self.har_path = Path(har_path)
        self.har_path.parent.mkdir(parents=True, exist_ok=True)
        
        self._cdp_client = None
        self._session_id: Optional[str] = None
        self._started = False
        self._callback_registered = False
        
        # HAR data structures
        self._entries: list[dict[str, Any]] = []
        self._pending_requests: dict[str, dict[str, Any]] = {}
    
    async def start(self, cdp_client: Any, browser_session: Any = None, session_id: Optional[str] = None) -> None:
        """Start recording network traffic via CDP.
        
        Args:
            cdp_client: CDPClient instance from browser-use/cdp_use
            browser_session: BrowserSession instance to access existing CDP sessions
            session_id: Optional CDP session ID for target-specific recording
        """
        if self._started:
            return
        
        self._cdp_client = cdp_client
        self._browser_session = browser_session
        self._session_id = session_id
        
        # Track sessions we've enabled Network for
        self._enabled_sessions: set[str] = set()
        
        # Register event callbacks (global, once)
        if not self._callback_registered:
            # Note: cdp_use callbacks receive (event, session_id) as arguments
            cdp_client.register.Network.requestWillBeSent(self._on_request_will_be_sent)
            cdp_client.register.Network.responseReceived(self._on_response_received)
            cdp_client.register.Network.loadingFinished(self._on_loading_finished)
            cdp_client.register.Network.loadingFailed(self._on_loading_failed)
            
            # Subscribe to Target.attachedToTarget to enable Network for future sessions
            cdp_client.register.Target.attachedToTarget(self._on_target_attached)
            
            self._callback_registered = True
            logger.info("[CdpHarRecorder] Registered network and target event callbacks")
        
        # Enable Network for existing sessions from browser_session
        if browser_session and hasattr(browser_session, 'session_manager') and browser_session.session_manager:
            session_manager = browser_session.session_manager
            # SessionManager uses _sessions as internal dict
            if hasattr(session_manager, '_sessions') and session_manager._sessions:
                for sid, cdp_session in session_manager._sessions.items():
                    if sid not in self._enabled_sessions:
                        try:
                            await cdp_client.send.Network.enable(session_id=sid)
                            self._enabled_sessions.add(sid)
                            logger.info(f"[CdpHarRecorder] Network enabled for existing session {sid[:8]}...")
                        except Exception as e:
                            logger.debug(f"[CdpHarRecorder] Failed to enable Network for session {sid[:8]}...: {e}")
        
        # Also try root level (may fail, that's OK)
        try:
            await cdp_client.send.Network.enable(session_id=session_id)
            logger.debug(f"[CdpHarRecorder] Network domain enabled on root")
        except Exception as e:
            logger.debug(f"[CdpHarRecorder] Network.enable on root skipped: {e}")
        
        self._started = True
        logger.info(f"[CdpHarRecorder] Recording started, will save to: {self.har_path}")
    
    def _on_target_attached(self, event: dict[str, Any], session_id: Optional[str] = None) -> None:
        """Handle Target.attachedToTarget event - enable Network domain for new sessions."""
        try:
            new_session_id = event.get("sessionId")
            target_info = event.get("targetInfo", {})
            target_type = target_info.get("type", "")
            
            # Only enable for page targets (not service workers, etc.)
            if target_type == "page" and new_session_id and new_session_id not in self._enabled_sessions:
                self._enabled_sessions.add(new_session_id)
                # Schedule async enable (we're in sync callback)
                import asyncio
                asyncio.create_task(self._enable_network_for_session(new_session_id))
                logger.debug(f"[CdpHarRecorder] Scheduled Network.enable for session {new_session_id[:8]}...")
        except Exception as e:
            logger.warning(f"[CdpHarRecorder] Error handling target attached: {e}")
    
    async def _enable_network_for_session(self, session_id: str) -> None:
        """Enable Network domain for a specific session."""
        try:
            if self._cdp_client:
                await self._cdp_client.send.Network.enable(session_id=session_id)
                logger.info(f"[CdpHarRecorder] Network enabled for session {session_id[:8]}...")
        except Exception as e:
            logger.debug(f"[CdpHarRecorder] Failed to enable Network for session {session_id[:8]}...: {e}")
    
    def _on_request_will_be_sent(self, event: dict[str, Any], session_id: Optional[str] = None) -> None:
        """Handle Network.requestWillBeSent event."""
        try:
            request_id = event.get("requestId")
            request = event.get("request", {})
            
            if not request_id:
                return
            
            # Get timestamp
            wall_time = event.get("wallTime")
            if wall_time:
                started_dt = datetime.fromtimestamp(wall_time, tz=timezone.utc)
            else:
                started_dt = datetime.now(timezone.utc)
            
            # Handle redirect response
            # If redirectResponse is present, the previous request with the same ID is finished/redirected
            redirect_response = event.get("redirectResponse")
            if redirect_response and request_id in self._pending_requests:
                redirect_entry = self._pending_requests[request_id]
                
                # Update redirect entry with response info
                redirect_entry["response"]["status"] = redirect_response.get("status", 0)
                redirect_entry["response"]["statusText"] = redirect_response.get("statusText", "")
                redirect_entry["response"]["headers"] = self._format_headers(redirect_response.get("headers", {}))
                redirect_entry["response"]["content"]["mimeType"] = redirect_response.get("mimeType", "")
                redirect_entry["response"]["redirectURL"] = request.get("url", "") # The new URL is the redirect target
                
                # Calculate timing
                timing = redirect_response.get("timing")
                if timing:
                    redirect_entry["timings"]["wait"] = timing.get("receiveHeadersEnd", 0) - timing.get("sendEnd", 0)
                    
                self._entries.append(redirect_entry)
                
                method = redirect_entry["request"]["method"]
                if method != "GET":
                    logger.info(f"[CdpHarRecorder] Redirected {method} [{request_id}] (saved to entries): {redirect_entry['request']['url'][:100]} -> {request.get('url', '')[:100]}")
                else:
                    logger.debug(f"[CdpHarRecorder] Redirected [{request_id}]: {redirect_entry['request']['url'][:80]} -> {request.get('url', '')[:80]}")
            
            # Build request entry
            entry = {
                "startedDateTime": started_dt.isoformat(),
                "time": 0,  # Will be updated on response
                "request": {
                    "method": request.get("method", "GET"),
                    "url": request.get("url", ""),
                    "httpVersion": "HTTP/1.1",
                    "headers": self._format_headers(request.get("headers", {})),
                    "queryString": [],
                    "cookies": [],
                    "headersSize": -1,
                    "bodySize": -1,
                },
                "response": {
                    "status": 0,
                    "statusText": "",
                    "httpVersion": "HTTP/1.1",
                    "headers": [],
                    "cookies": [],
                    "content": {
                        "size": 0,
                        "mimeType": "",
                    },
                    "redirectURL": "",
                    "headersSize": -1,
                    "bodySize": -1,
                },
                "cache": {},
                "timings": {
                    "send": 0,
                    "wait": 0,
                    "receive": 0,
                },
                "_requestId": request_id,
            }
            
            # Add POST data if present
            post_data = request.get("postData")
            if post_data:
                entry["request"]["postData"] = {
                    "mimeType": request.get("headers", {}).get("Content-Type", "application/x-www-form-urlencoded"),
                    "text": post_data,
                }
            
            self._pending_requests[request_id] = entry
            
        except Exception as e:
            logger.warning(f"[CdpHarRecorder] Error handling request: {e}")

# ... (omitted parts)

    async def stop(self) -> Path:
        """Stop recording and save HAR file.
        
        Returns:
            Path to the saved HAR file
        """
        if not self._started:
            return self.har_path
        
        try:
            # Disable Network domain
            if self._cdp_client:
                try:
                    await self._cdp_client.send.Network.disable(session_id=self._session_id)
                except Exception:
                    pass  # Best effort
            
            # Move any remaining pending requests to entries
            for entry in self._pending_requests.values():
                self._entries.append(entry)
            self._pending_requests.clear()
            
            # Build HAR structure
            har = {
                "log": {
                    "version": "1.2",
                    "creator": {"name": "BrowserUse CDP HarRecorder", "version": "0.1"},
                    "entries": self._entries,
                }
            }
            
            # Ensure directory exists
            self.har_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Save to file
            with self.har_path.open("w", encoding="utf-8") as f:
                json.dump(har, f, indent=2, ensure_ascii=False)
            
            logger.info(f"[CdpHarRecorder] Saved {len(self._entries)} entries to {self.har_path}")
            
        except Exception as e:
            logger.error(f"[CdpHarRecorder] Error saving HAR: {e}")
        
        return self.har_path
    
    def _on_response_received(self, event: dict[str, Any], session_id: Optional[str] = None) -> None:
        """Handle Network.responseReceived event."""
        try:
            request_id = event.get("requestId")
            response = event.get("response", {})
            
            if not request_id or request_id not in self._pending_requests:
                return
            
            entry = self._pending_requests[request_id]
            
            # Update response info
            entry["response"]["status"] = response.get("status", 0)
            entry["response"]["statusText"] = response.get("statusText", "")
            entry["response"]["headers"] = self._format_headers(response.get("headers", {}))
            entry["response"]["content"]["mimeType"] = response.get("mimeType", "")
            
            # Calculate timing if available
            timing = response.get("timing")
            if timing:
                entry["timings"]["wait"] = timing.get("receiveHeadersEnd", 0) - timing.get("sendEnd", 0)
            
        except Exception as e:
            logger.warning(f"[CdpHarRecorder] Error handling response: {e}")
    
    def _on_loading_finished(self, event: dict[str, Any], session_id: Optional[str] = None) -> None:
        """Handle Network.loadingFinished event."""
        try:
            request_id = event.get("requestId")
            
            if not request_id or request_id not in self._pending_requests:
                return
            
            entry = self._pending_requests.pop(request_id)
            
            # Update content size
            encoded_length = event.get("encodedDataLength", 0)
            entry["response"]["content"]["size"] = encoded_length
            entry["response"]["bodySize"] = encoded_length
            
            # Calculate total time
            # timestamp is relative to page load, not absolute
            pass
            
            self._entries.append(entry)
            
        except Exception as e:
            logger.warning(f"[CdpHarRecorder] Error handling loadingFinished: {e}")
    
    def _on_loading_failed(self, event: dict[str, Any], session_id: Optional[str] = None) -> None:
        """Handle Network.loadingFailed event."""
        try:
            request_id = event.get("requestId")
            
            if not request_id or request_id not in self._pending_requests:
                return
            
            entry = self._pending_requests.pop(request_id)
            
            # Mark as failed
            entry["response"]["status"] = 0
            entry["response"]["statusText"] = event.get("errorText", "Failed")
            
            self._entries.append(entry)
            
        except Exception as e:
            logger.warning(f"[CdpHarRecorder] Error handling loadingFailed: {e}")
            
        except Exception as e:
            logger.warning(f"[CdpHarRecorder] Error handling loadingFailed: {e}")
    
    def _format_headers(self, headers: dict[str, str]) -> list[dict[str, str]]:
        """Convert headers dict to HAR format list."""
        return [{"name": k, "value": v} for k, v in headers.items()]
    
    async def stop(self) -> Path:
        """Stop recording and save HAR file.
        
        Returns:
            Path to the saved HAR file
        """
        if not self._started:
            return self.har_path
        
        try:
            # Disable Network domain
            if self._cdp_client:
                try:
                    await self._cdp_client.send.Network.disable(session_id=self._session_id)
                except Exception:
                    pass  # Best effort
            
            # Move any remaining pending requests to entries
            pending_count = len(self._pending_requests)
            if pending_count > 0:
                pending_methods = {}
                for entry in self._pending_requests.values():
                    m = entry.get("request", {}).get("method", "UNKNOWN")
                    pending_methods[m] = pending_methods.get(m, 0) + 1
                logger.info(f"[CdpHarRecorder] Moving {pending_count} pending requests to entries: {pending_methods}")
            for entry in self._pending_requests.values():
                self._entries.append(entry)
            self._pending_requests.clear()
            
            # Build HAR structure
            har = {
                "log": {
                    "version": "1.2",
                    "creator": {
                        "name": "CdpHarRecorder",
                        "version": "1.0",
                    },
                    "entries": self._entries,
                }
            }
            
            # Save to file
            with self.har_path.open("w", encoding="utf-8") as f:
                json.dump(har, f, indent=2, ensure_ascii=False)
            
            # Log method distribution for debugging
            methods = {}
            for entry in self._entries:
                m = entry.get("request", {}).get("method", "UNKNOWN")
                methods[m] = methods.get(m, 0) + 1
            logger.info(f"[CdpHarRecorder] Saved {len(self._entries)} entries to {self.har_path}")
            logger.info(f"[CdpHarRecorder] Methods: {methods}")
            
        except Exception as e:
            logger.error(f"[CdpHarRecorder] Error saving HAR: {e}")
        
        self._started = False
        return self.har_path
    
    @property
    def is_recording(self) -> bool:
        """Check if currently recording."""
        return self._started
    
    @property
    def entry_count(self) -> int:
        """Get current number of recorded entries."""
        return len(self._entries) + len(self._pending_requests)


# Test code
if __name__ == "__main__":
    print("CdpHarRecorder module loaded successfully")
    print("This module requires integration with browser-use's CDPClient")
