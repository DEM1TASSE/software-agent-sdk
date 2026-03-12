"""Tests for CdpHarRecorder — specifically the navigation POST body fix.

Tests verify that:
1. Navigation POST (postData absent in event) → triggers getRequestPostData
2. AJAX POST (postData present in event) → does NOT trigger extra call
3. getRequestPostData failure (race condition / 302) → graceful fallback
4. postData correctly written back to pending entry
5. Real task scenarios (399, 409, 650, 731, 732, 733)
"""

import asyncio
import json
import pytest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from openhands.tools.browser_use.cdp_har_recorder import CdpHarRecorder


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_har_path(tmp_path):
    return tmp_path / "test.har"


@pytest.fixture
def mock_cdp_client():
    """Mock CDP client with chain-style send API."""
    client = MagicMock()

    # Mock send.Network.enable
    client.send.Network.enable = AsyncMock(return_value={})
    # Mock send.Network.disable
    client.send.Network.disable = AsyncMock(return_value={})
    # Mock send.Network.getRequestPostData
    client.send.Network.getRequestPostData = AsyncMock(return_value={
        "postData": "biography=I+am+a+robot"
    })

    # Mock register.Network.* (sync callbacks)
    client.register.Network.requestWillBeSent = MagicMock()
    client.register.Network.requestWillBeSentExtraInfo = MagicMock()
    client.register.Network.responseReceived = MagicMock()
    client.register.Network.loadingFinished = MagicMock()
    client.register.Network.loadingFailed = MagicMock()
    client.register.Target.attachedToTarget = MagicMock()

    return client


@pytest.fixture
def recorder(tmp_har_path):
    return CdpHarRecorder(har_path=tmp_har_path)


@pytest.fixture
async def started_recorder(recorder, mock_cdp_client):
    """Recorder that has been started with mock CDP client."""
    await recorder.start(mock_cdp_client)
    return recorder


# ---------------------------------------------------------------------------
# Helper: build CDP events
# ---------------------------------------------------------------------------

def make_request_event(
    request_id: str,
    method: str,
    url: str,
    post_data: str | None = None,
    headers: dict | None = None,
) -> dict:
    """Build a Network.requestWillBeSent event."""
    request = {
        "method": method,
        "url": url,
        "headers": headers or {"Content-Type": "application/x-www-form-urlencoded"},
    }
    if post_data is not None:
        request["postData"] = post_data
    return {
        "requestId": request_id,
        "request": request,
        "wallTime": 1710000000.0,
        "type": "Document" if method == "POST" and post_data is None else "XHR",
    }


def make_response_event(request_id: str, status: int = 200) -> dict:
    return {
        "requestId": request_id,
        "response": {
            "status": status,
            "statusText": "OK" if status == 200 else "Found",
            "headers": {},
            "mimeType": "text/html",
        },
    }


def make_loading_finished_event(request_id: str) -> dict:
    return {
        "requestId": request_id,
        "encodedDataLength": 1234,
    }


# ---------------------------------------------------------------------------
# Test: Navigation POST triggers getRequestPostData
# ---------------------------------------------------------------------------

class TestNavigationPostFetch:
    """Tests for the core fix: fetching postData for navigation POSTs."""

    @pytest.mark.asyncio
    async def test_navigation_post_triggers_fetch(self, started_recorder, mock_cdp_client):
        """When POST event has no postData, should call getRequestPostData."""
        recorder = started_recorder
        session_id = "test-session-123"

        # Navigation POST: no postData in the event (Chrome omits it)
        event = make_request_event(
            request_id="req-399",
            method="POST",
            url="http://reddit.test/user/MarvelsGrantMan136/edit_biography",
            post_data=None,  # This is the bug scenario
        )

        recorder._on_request_will_be_sent(event, session_id=session_id)

        # Let the event loop process the create_task
        await asyncio.sleep(0.05)

        # Should have called getRequestPostData
        mock_cdp_client.send.Network.getRequestPostData.assert_called_once()
        call_args = mock_cdp_client.send.Network.getRequestPostData.call_args
        assert call_args.kwargs.get("session_id") == session_id or \
               call_args[1].get("session_id") == session_id

    @pytest.mark.asyncio
    async def test_navigation_post_writes_back_postdata(self, started_recorder, mock_cdp_client):
        """Fetched postData should be written back to the pending entry."""
        recorder = started_recorder

        mock_cdp_client.send.Network.getRequestPostData = AsyncMock(return_value={
            "postData": "biography=I+am+a+robot"
        })

        event = make_request_event(
            request_id="req-399",
            method="POST",
            url="http://reddit.test/user/MarvelsGrantMan136/edit_biography",
            post_data=None,
        )

        recorder._on_request_will_be_sent(event, session_id="sess-1")
        await asyncio.sleep(0.05)

        # Check the pending entry has postData filled in
        entry = recorder._pending_requests.get("req-399")
        assert entry is not None
        assert "postData" in entry["request"]
        assert entry["request"]["postData"]["text"] == "biography=I+am+a+robot"

    @pytest.mark.asyncio
    async def test_ajax_post_does_not_trigger_fetch(self, started_recorder, mock_cdp_client):
        """When POST event already has postData, should NOT call getRequestPostData."""
        recorder = started_recorder

        # AJAX POST: postData is present (normal case, tasks 404/406/714/716)
        event = make_request_event(
            request_id="req-404",
            method="POST",
            url="http://reddit.test/api/vote",
            post_data="id=t3_1234&dir=1",  # postData present
        )

        recorder._on_request_will_be_sent(event, session_id="sess-1")
        await asyncio.sleep(0.05)

        # Should NOT have called getRequestPostData
        mock_cdp_client.send.Network.getRequestPostData.assert_not_called()

        # But postData should still be in the entry
        entry = recorder._pending_requests.get("req-404")
        assert entry is not None
        assert entry["request"]["postData"]["text"] == "id=t3_1234&dir=1"

    @pytest.mark.asyncio
    async def test_get_request_does_not_trigger_fetch(self, started_recorder, mock_cdp_client):
        """GET requests should never trigger getRequestPostData."""
        recorder = started_recorder

        event = make_request_event(
            request_id="req-get-1",
            method="GET",
            url="http://reddit.test/",
        )

        recorder._on_request_will_be_sent(event, session_id="sess-1")
        await asyncio.sleep(0.05)

        mock_cdp_client.send.Network.getRequestPostData.assert_not_called()


# ---------------------------------------------------------------------------
# Test: Race condition handling
# ---------------------------------------------------------------------------

class TestRaceCondition:
    """Tests for graceful handling when getRequestPostData fails."""

    @pytest.mark.asyncio
    async def test_fetch_failure_silent(self, started_recorder, mock_cdp_client):
        """If getRequestPostData fails (302 already resolved), entry has no postData but no crash."""
        recorder = started_recorder

        # Simulate Chrome rejecting the call (request already gone)
        mock_cdp_client.send.Network.getRequestPostData = AsyncMock(
            side_effect=Exception("No data found for resource with given identifier")
        )

        event = make_request_event(
            request_id="req-731",
            method="POST",
            url="http://reddit.test/f/MachineLearning/1/-/edit",
            post_data=None,
        )

        recorder._on_request_will_be_sent(event, session_id="sess-1")
        await asyncio.sleep(0.05)

        # Entry should exist but without postData (same as current behavior)
        entry = recorder._pending_requests.get("req-731")
        assert entry is not None
        assert "postData" not in entry["request"]

    @pytest.mark.asyncio
    async def test_fetch_after_entry_moved_to_entries(self, started_recorder, mock_cdp_client):
        """If entry already moved from pending to entries before fetch completes, no crash."""
        recorder = started_recorder

        # Make getRequestPostData slow
        async def slow_fetch(**kwargs):
            await asyncio.sleep(0.1)
            return {"postData": "too_late=yes"}

        mock_cdp_client.send.Network.getRequestPostData = AsyncMock(side_effect=slow_fetch)

        event = make_request_event(
            request_id="req-fast-302",
            method="POST",
            url="http://reddit.test/f/books/59421/-/comment",
            post_data=None,
        )

        recorder._on_request_will_be_sent(event, session_id="sess-1")

        # Immediately complete the request (simulating fast 302)
        recorder._on_response_received(
            make_response_event("req-fast-302", status=302), session_id="sess-1"
        )
        recorder._on_loading_finished(
            make_loading_finished_event("req-fast-302"), session_id="sess-1"
        )

        # Entry should be in _entries now, not _pending_requests
        assert "req-fast-302" not in recorder._pending_requests
        assert any(e["_requestId"] == "req-fast-302" for e in recorder._entries)

        # Wait for the slow fetch to complete — should not crash
        await asyncio.sleep(0.15)

        # No exception raised = success


# ---------------------------------------------------------------------------
# Test: Real task scenarios
# ---------------------------------------------------------------------------

# Task data from webarena-verified dataset
AFFECTED_TASKS = [
    {
        "task_id": 399,
        "url": "http://reddit.test/user/MarvelsGrantMan136/edit_biography",
        "post_data": "biography=I+am+a+robot",
        "description": "Change bio to 'I am a robot'",
    },
    {
        "task_id": 409,
        "url": "http://reddit.test/f/books/59421/-/comment/1235250",
        "post_data": "body=Great+recommendation",
        "description": "Reply to comment",
    },
    {
        "task_id": 650,
        "url": "http://reddit.test/f/books/59421/-/comment",
        "post_data": "body=Thanks+for+the+post",
        "description": "Reply to post",
    },
    {
        "task_id": 731,
        "url": "http://reddit.test/f/MachineLearning/1/-/edit",
        "post_data": "title=Nvidia+update&body=edited",
        "description": "Edit post (Nvidia)",
    },
    {
        "task_id": 732,
        "url": "http://reddit.test/f/television/134868/-/edit",
        "post_data": "title=Night+Agent&body=edited",
        "description": "Edit post (Night Agent)",
    },
    {
        "task_id": 733,
        "url": "http://reddit.test/f/television/135201/-/edit",
        "post_data": "title=Star+Trek&body=edited",
        "description": "Edit post (Star Trek)",
    },
]


class TestAffectedTasks:
    """End-to-end test for each affected task: navigation POST → fetch → HAR output."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("task", AFFECTED_TASKS, ids=[f"task-{t['task_id']}" for t in AFFECTED_TASKS])
    async def test_affected_task_postdata_captured(self, tmp_har_path, mock_cdp_client, task):
        """Each affected task's POST body should appear in the final HAR."""
        recorder = CdpHarRecorder(har_path=tmp_har_path)
        await recorder.start(mock_cdp_client)

        # Configure mock to return this task's post data
        mock_cdp_client.send.Network.getRequestPostData = AsyncMock(return_value={
            "postData": task["post_data"]
        })

        request_id = f"req-{task['task_id']}"

        # 1. Navigation POST event (no postData from Chrome)
        recorder._on_request_will_be_sent(
            make_request_event(request_id, "POST", task["url"], post_data=None),
            session_id="sess-task",
        )
        await asyncio.sleep(0.05)

        # 2. Response (302 redirect)
        recorder._on_response_received(
            make_response_event(request_id, status=302),
            session_id="sess-task",
        )

        # 3. Loading finished
        recorder._on_loading_finished(
            make_loading_finished_event(request_id),
            session_id="sess-task",
        )

        # 4. Stop and save HAR
        await recorder.stop()

        # 5. Verify HAR file
        assert tmp_har_path.exists()
        har = json.loads(tmp_har_path.read_text())
        entries = har["log"]["entries"]

        post_entries = [e for e in entries if e["request"]["method"] == "POST"]
        assert len(post_entries) == 1, f"Task {task['task_id']}: expected 1 POST entry"

        post_entry = post_entries[0]
        assert post_entry["request"]["url"] == task["url"]
        assert "postData" in post_entry["request"], \
            f"Task {task['task_id']}: postData missing from HAR"
        assert post_entry["request"]["postData"]["text"] == task["post_data"]


# ---------------------------------------------------------------------------
# Test: Regression — AJAX POSTs still work
# ---------------------------------------------------------------------------

class TestAjaxPostRegression:
    """Verify that AJAX POSTs (which already work) are not broken by the fix."""

    @pytest.mark.asyncio
    async def test_ajax_post_preserved_in_har(self, tmp_har_path, mock_cdp_client):
        """AJAX POST with postData in event should appear in HAR without extra fetch."""
        recorder = CdpHarRecorder(har_path=tmp_har_path)
        await recorder.start(mock_cdp_client)

        # AJAX POST — postData is present (vote action)
        recorder._on_request_will_be_sent(
            make_request_event("req-vote", "POST", "http://reddit.test/api/vote",
                             post_data="id=t3_1234&dir=1"),
            session_id="sess-ajax",
        )

        recorder._on_response_received(
            make_response_event("req-vote", status=200),
            session_id="sess-ajax",
        )
        recorder._on_loading_finished(
            make_loading_finished_event("req-vote"),
            session_id="sess-ajax",
        )

        await recorder.stop()

        har = json.loads(tmp_har_path.read_text())
        post_entries = [e for e in har["log"]["entries"] if e["request"]["method"] == "POST"]
        assert len(post_entries) == 1
        assert post_entries[0]["request"]["postData"]["text"] == "id=t3_1234&dir=1"

        # Should NOT have called getRequestPostData
        mock_cdp_client.send.Network.getRequestPostData.assert_not_called()
