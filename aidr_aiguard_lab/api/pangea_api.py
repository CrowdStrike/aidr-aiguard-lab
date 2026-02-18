from __future__ import annotations

import getpass
import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, TypedDict

from crowdstrike_aidr import AIGuard, omit
from dotenv import load_dotenv

from aidr_aiguard_lab.defaults import defaults

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from crowdstrike_aidr.models.ai_guard import GuardChatCompletionsResponse


load_dotenv(override=True)


class Message(TypedDict):
    role: str
    content: str


class GuardInput(TypedDict):
    messages: Sequence[Message]


class ExtraInfo(TypedDict, total=False):
    app_name: str | None
    app_group: str | None
    app_version: str | None
    actor_name: str | None
    actor_group: str | None
    source_region: str | None
    sub_tenant: str | None


class GuardChatCompletionsParams(TypedDict, total=False):
    guard_input: GuardInput
    app_id: str | None
    collector_instance_id: str | None
    event_type: None | Literal["input", "output", "tool_input", "tool_output", "tool_listing"]
    extra_info: ExtraInfo | None
    llm_provider: str | None
    model: str | None
    model_version: str | None
    source_ip: str | None
    source_location: str | None
    tenant_id: str | None
    user_id: str | None


# Default AIDR metadata
DEFAULT_AIDR_METADATA: GuardChatCompletionsParams = {
    "event_type": "input",
    "app_id": "AIG-lab",
    "llm_provider": "test",
    "model": "GPT-6-super",
    "model_version": "6s",
    "source_ip": "74.244.51.54",
    "extra_info": ExtraInfo(
        actor_name=getpass.getuser(),  # Gets current username
        app_name=Path(sys.argv[0]).stem if sys.argv else "aiguard_lab.py",
    ),
}


def guard_chat_completions(
    guard_input: GuardInput, aidr_config: Mapping[str, Any] = {}
) -> GuardChatCompletionsResponse:
    ai_guard_token = os.getenv(defaults.ai_guard_token)
    assert ai_guard_token, f"{defaults.ai_guard_token} environment variable not set"
    base_url_template = os.getenv(defaults.base_url_template)
    assert base_url_template, f"{defaults.base_url_template} environment variable not set"

    ai_guard = AIGuard(base_url_template=base_url_template, token=ai_guard_token)
    return ai_guard.guard_chat_completions(
        guard_input=guard_input,
        app_id=aidr_config.get("app_id", DEFAULT_AIDR_METADATA["app_id"]),
        collector_instance_id=aidr_config.get("collector_instance_id", omit),
        event_type=aidr_config.get("event_type", DEFAULT_AIDR_METADATA["event_type"]),
        extra_info=aidr_config.get("extra_info", DEFAULT_AIDR_METADATA["extra_info"]),
        llm_provider=aidr_config.get("llm_provider", DEFAULT_AIDR_METADATA["llm_provider"]),
        model=aidr_config.get("model", DEFAULT_AIDR_METADATA["model"]),
        model_version=aidr_config.get("model_version", DEFAULT_AIDR_METADATA["model_version"]),
        source_ip=aidr_config.get("source_ip", DEFAULT_AIDR_METADATA["source_ip"]),
        source_location=aidr_config.get("source_location", omit),
        tenant_id=aidr_config.get("tenant_id", omit),
        user_id=aidr_config.get("user_id", omit),
    )
