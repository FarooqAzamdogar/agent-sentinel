"""Recipe: LangChain tools whose every call goes through agent-sentinel.

    pip install langchain-core            (agent-sentinel itself needs nothing else)

    firewall = Firewall(Policy.from_file("policy.json"), audit_path="audit.jsonl")
    tools = make_tools(firewall, notes_folder="notes")
    # hand `tools` to your agent as usual

`guard` goes UNDER LangChain's @tool. LangChain then reads the original
function's name, docstring and parameters to describe the tool to the model
(guard keeps them), and every call it makes is checked against the policy,
runs, and has its result scanned for prompt injection before the model
reads it. With on_block="return", a blocked call returns a short text the
model may read ("Blocked by agent-sentinel: ... (ref 7f3a9c21)") instead
of raising, so the agent can carry on.

The policy names these tools as written here: "read_note", "search_notes".
read_note joins the name it is given to the notes folder, so the policy
should accept only plain note names, for example:

    "read_note": {"action": "allow", "allow_args": [
        {"arg": "name", "pattern": "[A-Za-z0-9_-]+\\\\.txt"},
        {"arg": "max_chars", "pattern": "[0-9]{1,5}"}]}

(max_chars is always checked: guard fills in a parameter's default when the call leaves it out.)

BEST EFFORT. Tested against a stand-in for langchain_core's @tool, not
against LangChain itself, whose API changes often.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from langchain_core.tools import tool

from agent_sentinel import Firewall
from agent_sentinel.tool_guard import guard


def make_tools(firewall: Firewall, notes_folder: str | Path) -> list[Any]:
    """Two tools over a folder of notes, each guarded by the firewall."""
    folder = Path(notes_folder)

    @tool
    @guard(firewall, on_block="return")
    def read_note(name: str, max_chars: int = 4000) -> str:
        """Read one note from the notes folder and return its text."""
        return (folder / name).read_text(encoding="utf-8")[:max_chars]

    @tool
    @guard(firewall, on_block="return")
    async def search_notes(query: str) -> str:
        """Return the names of the notes whose text contains the query."""
        found = [path.name for path in sorted(folder.glob("*.txt"))
                 if query.lower() in path.read_text(encoding="utf-8").lower()]
        return "\n".join(found) or "no note matches"

    return [read_note, search_notes]
