"""Tests for CdpHarRecorder — redirect POST body preservation fix.

Root cause: Chrome reuses requestId for redirects. For POST → 302:
  Event 1: requestWillBeSent(POST /submit, postData=...)
  Event 2: requestWillBeSent(GET /redirect_target, redirectResponse={status:302})
Without redirect handling, event 2 overwrites event 1 in _pending_requests,
losing the POST's postData.

Fix: when redirectResponse is present, save the existing entry first.
"""

import asyncio
import json
import pytest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

from openhands.tools.browser_use.cdp_har_recorder import CdpHarRecorder


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_har_path(tmp_path):
    return tmp_path / "test.har"


@pytest.fixture
def mock_cdp_client():
    client = MagicMock()
    client.send.Network.enable = AsyncMock(return_value={})
    client.send.Network.disable = AsyncMock(return_value={})
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
    await recorder.start(mock_cdp_client)
    return recorder


# ---------------------------------------------------------------------------
# Helpers: build CDP events matching real Chrome behavior
# ---------------------------------------------------------------------------

def make_request_will_be_sent(
    request_id: str,
    method: str,
    url: str,
    post_data: str | None = None,
    redirect_response: dict | None = None,
) -> dict:
    """Build a Network.requestWillBeSent event."""
    request = {
        "method": method,
        "url": url,
        "headers": {"Content-Type": "application/x-www-form-urlencoded"},
    }
    if post_data is not None:
        request["postData"] = post_data
        request["hasPostData"] = True

    event = {
        "requestId": request_id,
        "request": request,
        "wallTime": 1710000000.0,
    }
    if redirect_response is not None:
        event["redirectResponse"] = redirect_response
    return event


def make_redirect_response(status: int = 302, location: str = "") -> dict:
    """Build a redirectResponse object (included in event 2 of a redirect chain)."""
    return {
        "status": status,
        "statusText": "Found",
        "headers": {"Location": location},
        "mimeType": "text/html",
    }


def make_response_event(request_id: str, status: int = 200) -> dict:
    return {
        "requestId": request_id,
        "response": {
            "status": status,
            "statusText": "OK",
            "headers": {},
            "mimeType": "text/html",
        },
    }


def make_loading_finished_event(request_id: str) -> dict:
    return {"requestId": request_id, "encodedDataLength": 1234}


# ---------------------------------------------------------------------------
# Core tests: redirect POST body preservation
# ---------------------------------------------------------------------------

class TestRedirectPostPreservation:
    """The core fix: POST → 302 should preserve postData in HAR."""

    @pytest.mark.asyncio
    async def test_post_302_preserves_postdata(self, started_recorder):
        """POST → 302 → GET: original POST entry with postData must be saved."""
        recorder = started_recorder
        rid = "redirect-req-1"

        # Event 1: POST with postData
        recorder._on_request_will_be_sent(
            make_request_will_be_sent(rid, "POST",
                "http://reddit.test/user/MarvelsGrantMan136/edit_biography",
                post_data="user_biography%5Bbiography%5D=I+am+a+robot"),
            session_id="sess-1",
        )
        assert rid in recorder._pending_requests
        assert recorder._pending_requests[rid]["request"]["method"] == "POST"

        # Event 2: GET redirect target (same requestId, has redirectResponse)
        recorder._on_request_will_be_sent(
            make_request_will_be_sent(rid, "GET",
                "http://reddit.test/user/MarvelsGrantMan136",
                redirect_response=make_redirect_response(302)),
            session_id="sess-1",
        )

        # POST entry should be saved to _entries with postData
        post_entries = [e for e in recorder._entries if e["request"]["method"] == "POST"]
        assert len(post_entries) == 1
        assert "postData" in post_entries[0]["request"]
        assert "I+am+a+robot" in post_entries[0]["request"]["postData"]["text"]
        assert post_entries[0]["response"]["status"] == 302

        # GET redirect target should be in _pending_requests
        assert rid in recorder._pending_requests
        assert recorder._pending_requests[rid]["request"]["method"] == "GET"

    @pytest.mark.asyncio
    async def test_post_302_in_final_har(self, tmp_har_path, mock_cdp_client):
        """End-to-end: POST → 302 → GET completes → HAR has both entries."""
        recorder = CdpHarRecorder(har_path=tmp_har_path)
        await recorder.start(mock_cdp_client)
        rid = "e2e-req-1"

        # POST
        recorder._on_request_will_be_sent(
            make_request_will_be_sent(rid, "POST",
                "http://reddit.test/f/MachineLearning/1/-/edit",
                post_data="title=Nvidia+update&body=edited"),
            session_id="sess-1",
        )

        # Redirect → GET
        recorder._on_request_will_be_sent(
            make_request_will_be_sent(rid, "GET",
                "http://reddit.test/f/MachineLearning/1",
                redirect_response=make_redirect_response(302)),
            session_id="sess-1",
        )

        # GET response + finish
        recorder._on_response_received(
            make_response_event(rid, 200), session_id="sess-1")
        recorder._on_loading_finished(
            make_loading_finished_event(rid), session_id="sess-1")

        await recorder.stop()

        har = json.loads(tmp_har_path.read_text())
        entries = har["log"]["entries"]

        post_entries = [e for e in entries if e["request"]["method"] == "POST"]
        get_entries = [e for e in entries if e["request"]["method"] == "GET"]

        assert len(post_entries) == 1, f"Expected 1 POST, got {len(post_entries)}"
        assert len(get_entries) == 1, f"Expected 1 GET, got {len(get_entries)}"
        assert "postData" in post_entries[0]["request"]
        assert post_entries[0]["request"]["postData"]["text"] == "title=Nvidia+update&body=edited"
        assert post_entries[0]["response"]["status"] == 302

    @pytest.mark.asyncio
    async def test_no_redirect_post_still_works(self, started_recorder):
        """AJAX POST (no redirect) should work as before."""
        recorder = started_recorder

        recorder._on_request_will_be_sent(
            make_request_will_be_sent("ajax-1", "POST",
                "http://reddit.test/api/vote",
                post_data="id=t3_1234&dir=1"),
            session_id="sess-1",
        )

        # No redirect event — just response + finish
        recorder._on_response_received(
            make_response_event("ajax-1", 200), session_id="sess-1")
        recorder._on_loading_finished(
            make_loading_finished_event("ajax-1"), session_id="sess-1")

        post_entries = [e for e in recorder._entries if e["request"]["method"] == "POST"]
        assert len(post_entries) == 1
        assert post_entries[0]["request"]["postData"]["text"] == "id=t3_1234&dir=1"

    @pytest.mark.asyncio
    async def test_get_redirect_no_crash(self, started_recorder):
        """GET → 302 → GET should not crash (no postData involved)."""
        recorder = started_recorder

        recorder._on_request_will_be_sent(
            make_request_will_be_sent("get-redir-1", "GET",
                "http://reddit.test/old-path"),
            session_id="sess-1",
        )

        recorder._on_request_will_be_sent(
            make_request_will_be_sent("get-redir-1", "GET",
                "http://reddit.test/new-path",
                redirect_response=make_redirect_response(301)),
            session_id="sess-1",
        )

        # First GET saved to entries with 301 status
        redirect_entries = [e for e in recorder._entries if e["response"]["status"] == 301]
        assert len(redirect_entries) == 1
        assert redirect_entries[0]["request"]["url"] == "http://reddit.test/old-path"


# ---------------------------------------------------------------------------
# Affected task scenarios (parametrized)
# ---------------------------------------------------------------------------

AFFECTED_TASKS = [
    {"task_id": 399, "url": "http://reddit.test/user/MarvelsGrantMan136/edit_biography",
     "redirect_url": "http://reddit.test/user/MarvelsGrantMan136",
     "post_data": "user_biography%5Bbiography%5D=I+am+a+robot"},
    {"task_id": 409, "url": "http://reddit.test/f/books/59421/-/comment/1235250",
     "redirect_url": "http://reddit.test/f/books/59421/-/comment/1235250",
     "post_data": "body=Great+recommendation"},
    {"task_id": 650, "url": "http://reddit.test/f/books/59421/-/comment",
     "redirect_url": "http://reddit.test/f/books/59421",
     "post_data": "body=Thanks+for+the+post"},
    {"task_id": 731, "url": "http://reddit.test/f/MachineLearning/1/-/edit",
     "redirect_url": "http://reddit.test/f/MachineLearning/1",
     "post_data": "title=Nvidia+update&body=edited"},
    {"task_id": 732, "url": "http://reddit.test/f/television/134868/-/edit",
     "redirect_url": "http://reddit.test/f/television/134868",
     "post_data": "title=Night+Agent&body=edited"},
    {"task_id": 733, "url": "http://reddit.test/f/television/135201/-/edit",
     "redirect_url": "http://reddit.test/f/television/135201",
     "post_data": "title=Star+Trek&body=edited"},
]


class TestAffectedTasks:
    """Each affected task: POST → 302 → GET, verify postData in HAR."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("task", AFFECTED_TASKS,
                             ids=[f"task-{t['task_id']}" for t in AFFECTED_TASKS])
    async def test_task_postdata_preserved(self, tmp_har_path, mock_cdp_client, task):
        recorder = CdpHarRecorder(har_path=tmp_har_path)
        await recorder.start(mock_cdp_client)
        rid = f"req-{task['task_id']}"

        # POST with postData
        recorder._on_request_will_be_sent(
            make_request_will_be_sent(rid, "POST", task["url"],
                post_data=task["post_data"]),
            session_id="sess-task",
        )

        # Redirect → GET
        recorder._on_request_will_be_sent(
            make_request_will_be_sent(rid, "GET", task["redirect_url"],
                redirect_response=make_redirect_response(302)),
            session_id="sess-task",
        )

        # GET completes
        recorder._on_response_received(
            make_response_event(rid, 200), session_id="sess-task")
        recorder._on_loading_finished(
            make_loading_finished_event(rid), session_id="sess-task")

        await recorder.stop()

        har = json.loads(tmp_har_path.read_text())
        post_entries = [e for e in har["log"]["entries"] if e["request"]["method"] == "POST"]

        assert len(post_entries) == 1, f"Task {task['task_id']}: expected 1 POST"
        assert "postData" in post_entries[0]["request"], \
            f"Task {task['task_id']}: postData missing"
        assert post_entries[0]["request"]["postData"]["text"] == task["post_data"]
        assert post_entries[0]["response"]["status"] == 302


# ---------------------------------------------------------------------------
# Regression: AJAX POST still works
# ---------------------------------------------------------------------------

class TestAjaxPostRegression:

    @pytest.mark.asyncio
    async def test_ajax_post_in_har(self, tmp_har_path, mock_cdp_client):
        recorder = CdpHarRecorder(har_path=tmp_har_path)
        await recorder.start(mock_cdp_client)

        recorder._on_request_will_be_sent(
            make_request_will_be_sent("req-vote", "POST",
                "http://reddit.test/api/vote",
                post_data="id=t3_1234&dir=1"),
            session_id="sess-ajax",
        )
        recorder._on_response_received(
            make_response_event("req-vote", 200), session_id="sess-ajax")
        recorder._on_loading_finished(
            make_loading_finished_event("req-vote"), session_id="sess-ajax")

        await recorder.stop()

        har = json.loads(tmp_har_path.read_text())
        post_entries = [e for e in har["log"]["entries"] if e["request"]["method"] == "POST"]
        assert len(post_entries) == 1
        assert post_entries[0]["request"]["postData"]["text"] == "id=t3_1234&dir=1"
