"""
Browser use example with HAR recording enabled.
This demonstrates how to record network traffic to a HAR file.

Changes from original 15_browser_use.py:
1. Added record_har_path parameter to BrowserToolSet config
2. Added output directory for HAR file
"""
import os
from pathlib import Path

from pydantic import SecretStr

from openhands.sdk import (
    LLM,
    Agent,
    Conversation,
    Event,
    LLMConvertibleEvent,
    get_logger,
)
from openhands.sdk.tool import Tool
from openhands.tools.browser_use import BrowserToolSet
from openhands.tools.file_editor import FileEditorTool
from openhands.tools.terminal import TerminalTool


logger = get_logger(__name__)

# Configure LLM
api_key = os.getenv("LLM_API_KEY")
assert api_key is not None, "LLM_API_KEY environment variable is not set."
model = os.getenv("LLM_MODEL", "anthropic/claude-sonnet-4-5-20250929")
base_url = os.getenv("LLM_BASE_URL")
llm = LLM(
    usage_id="agent",
    model=model,
    base_url=base_url,
    api_key=SecretStr(api_key),
)

# Output directory for HAR file
output_dir = Path("/tmp/har_test")
output_dir.mkdir(parents=True, exist_ok=True)
har_path = output_dir / "network.har"

print(f"HAR file will be saved to: {har_path}")

# Tools - Added record_har_path config (now integrated into BrowserToolExecutor)
cwd = os.getcwd()
tools = [
    Tool(name=TerminalTool.name),
    Tool(name=FileEditorTool.name),
    Tool(
        name=BrowserToolSet.name,
        params={  # Note: Tool class uses 'params', not 'config'!
            "record_har_path": str(har_path),  # HAR recording integrated!
        },
    ),
]

# Agent
agent = Agent(llm=llm, tools=tools)

llm_messages = []  # collect raw LLM messages


def conversation_callback(event: Event):
    if isinstance(event, LLMConvertibleEvent):
        llm_messages.append(event.to_llm_message())


conversation = Conversation(
    agent=agent, callbacks=[conversation_callback], workspace=cwd
)

# Simple task to test HAR recording
print("Starting conversation...")
try:
    conversation.send_message(
        "Could you go to https://openhands.dev/ blog page and summarize main "
        "points of the latest blog?"
    )
    conversation.run()
except Exception as e:
    print(f"An error occurred during execution: {e}")
    # Print stack trace for better debugging
    import traceback
    traceback.print_exc()
finally:
    print("=" * 100)
    print("Conversation finished (or interrupted).")

    # Explicitly cleanup to ensure HAR file is saved
    print("Cleaning up browser resources...")
    import time
    try:
        if BrowserToolSet._last_executor:
            # Short sleep to allow pending async tasks to settle
            try:
                import asyncio
                # We can't await here easily in sync code, so we rely on the executor.close()
                pass 
            except ImportError:
                pass
                
            BrowserToolSet._last_executor.close()
            print("Browser resources cleaned up.")
            
            # Give a moment for file I/O to complete
            time.sleep(2)
        else:
            print("No browser executor was initialized.")
    except Exception as e:
        print(f"Error during cleanup: {e}")

    print(f"Checking HAR file: {har_path}")
    if har_path.exists():
        size = har_path.stat().st_size
        print(f"✓ HAR file exists! Size: {size} bytes")
        
        # Show first 500 chars of HAR file
        try:
            with open(har_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(500)
                print(f"HAR file preview:\n{content}...")
        except Exception as read_err:
            print(f"Could not read HAR file: {read_err}")
    else:
        print("✗ HAR file not found!")

