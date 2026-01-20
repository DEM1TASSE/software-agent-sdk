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
        # Cache for extraInfo that arrives before requestWillBeSent
        self._pending_extra_info: dict[str, dict[str, Any]] = {}
    
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
            cdp_client.register.Network.requestWillBeSentExtraInfo(self._on_request_will_be_sent_extra_info)
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
            
            # Check if we have cached extraInfo that arrived early
            if request_id in self._pending_extra_info:
                cached = self._pending_extra_info.pop(request_id)
                extra_headers = cached.get("headers", {})
                if extra_headers:
                    logger.info(f"[CdpHarRecorder] Applying {len(extra_headers)} cached extra headers for {request.get('url', '')[:80]}")
                    existing_headers = {h["name"]: h["value"] for h in entry["request"]["headers"]}
                    added_count = 0
                    for name, value in extra_headers.items():
                        if name not in existing_headers:
                            entry["request"]["headers"].append({"name": name, "value": value})
                            added_count += 1
                    logger.info(f"[CdpHarRecorder] Applied {added_count} cached headers")
            
            # Log POST requests at INFO level for debugging
            method = request.get('method', 'GET')
            entry_method = entry["request"]["method"]
            if method != 'GET':
                logger.info(f"[CdpHarRecorder] Non-GET request: {method} (entry_method={entry_method}) {request.get('url', '')[:100]}")
            else:
                logger.debug(f"[CdpHarRecorder] Request: {method} {request.get('url', '')[:80]}")
            
        except Exception as e:
            logger.warning(f"[CdpHarRecorder] Error handling request: {e}")

    def _on_request_will_be_sent_extra_info(self, event: dict[str, Any], session_id: Optional[str] = None) -> None:
        """Handle Network.requestWillBeSentExtraInfo event.
        
        This event contains the complete headers including browser-added headers
        like Accept, Sec-Fetch-Dest, Sec-Fetch-Mode, Sec-Fetch-User, etc.
        These headers are needed for proper navigation event detection.
        
        NOTE: This event may arrive BEFORE or AFTER requestWillBeSent for the same request.
        We cache it if it arrives early.
        """
        try:
            request_id = event.get("requestId")
            extra_headers = event.get("headers", {})
            
            logger.info(f"[CdpHarRecorder] requestWillBeSentExtraInfo: requestId={request_id}, headers={len(extra_headers)}")
            
            if not request_id:
                return
            
            # Check if the main request has already been registered
            if request_id in self._pending_requests:
                # Request already exists, merge headers now
                entry = self._pending_requests[request_id]
                if extra_headers:
                    logger.info(f"[CdpHarRecorder] Merging {len(extra_headers)} extra headers for {entry['request']['url'][:80]}")
                    existing_headers = {h["name"]: h["value"] for h in entry["request"]["headers"]}
                    
                    added_count = 0
                    for name, value in extra_headers.items():
                        if name not in existing_headers:
                            entry["request"]["headers"].append({"name": name, "value": value})
                            added_count += 1
                    logger.info(f"[CdpHarRecorder] Added {added_count} new headers")
            else:
                # Request hasn't arrived yet, cache the extra info
                logger.info(f"[CdpHarRecorder] Caching extraInfo for future request {request_id}")
                self._pending_extra_info[request_id] = {"headers": extra_headers}
                        
        except Exception as e:
            logger.warning(f"[CdpHarRecorder] Error handling requestWillBeSentExtraInfo: {e}")
    
    def _on_response_received(self, event: dict[str, Any], session_id: Optional[str] = None) -> None:
        """Handle Network.responseReceived event."""
        try:
            request_id = event.get("requestId")
            response = event.get("response", {})
            
            if not request_id or request_id not in self._pending_requests:
                return
            
            entry = self._pending_requests[request_id]
            method = entry["request"]["method"]
            
            # Update response info
            entry["response"]["status"] = response.get("status", 0)
            entry["response"]["statusText"] = response.get("statusText", "")
            entry["response"]["headers"] = self._format_headers(response.get("headers", {}))
            entry["response"]["content"]["mimeType"] = response.get("mimeType", "")
            
            # Calculate timing if available
            timing = response.get("timing")
            if timing:
                entry["timings"]["wait"] = timing.get("receiveHeadersEnd", 0) - timing.get("sendEnd", 0)
            
            if method != "GET":
                logger.info(f"[CdpHarRecorder] Response for {method}: {response.get('status')} {entry['request']['url'][:100]}")
            else:
                logger.debug(f"[CdpHarRecorder] Response: {response.get('status')} for {entry['request']['url'][:80]}")
            
        except Exception as e:
            logger.warning(f"[CdpHarRecorder] Error handling response: {e}")
    
    def _on_loading_finished(self, event: dict[str, Any], session_id: Optional[str] = None) -> None:
        """Handle Network.loadingFinished event."""
        try:
            request_id = event.get("requestId")
            
            if not request_id or request_id not in self._pending_requests:
                return
            
            entry = self._pending_requests.pop(request_id)
            method = entry["request"]["method"]
            
            # Update content size
            encoded_length = event.get("encodedDataLength", 0)
            entry["response"]["content"]["size"] = encoded_length
            entry["response"]["bodySize"] = encoded_length
            
            entry["response"]["content"] = entry["response"].get("content", {})
            entry["response"]["content"]["text"] = "" # Placeholder, we don't capture body yet
            
            # Calculate total time
            # timestamp is relative to page load, not absolute
            pass
            
            self._entries.append(entry)
            
            if method != "GET":
                logger.info(f"[CdpHarRecorder] Finished {method} (saved to entries, total now {len(self._entries)}): {entry['request']['url'][:100]}")
            else:
                logger.debug(f"[CdpHarRecorder] Completed: {entry['request']['url'][:80]}")
            
        except Exception as e:
            logger.warning(f"[CdpHarRecorder] Error handling loadingFinished: {e}")
    
    def _on_loading_failed(self, event: dict[str, Any], session_id: Optional[str] = None) -> None:
        """Handle Network.loadingFailed event."""
        try:
            request_id = event.get("requestId")
            
            if not request_id or request_id not in self._pending_requests:
                return
            
            entry = self._pending_requests.pop(request_id)
            method = entry["request"]["method"]
            
            # Mark as failed
            entry["response"]["status"] = 0
            entry["response"]["statusText"] = event.get("errorText", "Failed")
            
            self._entries.append(entry)
            
            if method != "GET":
                logger.info(f"[CdpHarRecorder] Failed {method}: {event.get('errorText')} {entry['request']['url'][:100]}")
            else:
                logger.debug(f"[CdpHarRecorder] Failed: {entry['request']['url'][:80]}")
            
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
