"""Offline Osmos boundary contracts; no transport or live dispatch is enabled."""

from datetime import datetime
import hashlib
import json
import re
import uuid


class BoundaryError(ValueError):
    """Fixed reason codes only; never includes service or request text."""


def _fail(code):
    raise BoundaryError(code)


def _uuid(value):
    if (
        not isinstance(value, str)
        or not re.fullmatch(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", value)
        or uuid.UUID(value).int == 0
    ):
        _fail("OSMOS_INVALID_ID")
    return value.lower()


def _request(value):
    if type(value) is not dict or set(value) != {
        "task_id", "workspace_id", "lakehouse_id", "instruction",
    }:
        _fail("OSMOS_INVALID_REQUEST")
    instruction = value["instruction"]
    if (
        not isinstance(instruction, str) or not instruction.strip()
        or len(instruction) > 8000
        or any(ord(char) < 32 and char not in "\n\t" for char in instruction)
    ):
        _fail("OSMOS_INVALID_REQUEST")
    return {
        **{key: _uuid(value[key]) for key in ("task_id", "workspace_id", "lakehouse_id")},
        "instruction": instruction,
    }


def request_digest(request):
    """Bind future consent to all validated scope and instruction fields."""
    data = json.dumps(_request(request), sort_keys=True, ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def prepare_handoff(request, approval):
    """Validate a proposed approval record; this does not authenticate a human."""
    request = _request(request)
    if type(approval) is not dict or set(approval) != {
        "task_id", "request_sha256", "approved", "capacity_acknowledged",
    }:
        _fail("OSMOS_CAPACITY_CONSENT_REQUIRED")
    if approval["approved"] is not True or approval["capacity_acknowledged"] is not True:
        _fail("OSMOS_CAPACITY_CONSENT_REQUIRED")
    if (
        _uuid(approval["task_id"]) != request["task_id"]
        or approval["request_sha256"] != request_digest(request)
    ):
        _fail("OSMOS_CONSENT_SCOPE_MISMATCH")
    return {
        **request,
        "instruction": request["instruction"] + (
            "\n\nExecution boundary: read-only analysis within the explicitly approved "
            "sources only. The default lakehouse is not an authorization boundary. "
            "Keep data, counts, analysis, messages, logs and errors in Fabric. "
            "Do not modify, publish, export, delete or change permissions. "
            "The local caller may receive only validated operational status."
        ),
    }


def dispatch(request, approval):
    """No flag, consent record, environment variable, or task can enable transport."""
    prepare_handoff(request, approval)
    _fail("OSMOS_LIVE_DISABLED")


def _timestamp(value):
    if not isinstance(value, str) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z", value, re.ASCII
    ):
        _fail("OSMOS_INVALID_STATUS")
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        _fail("OSMOS_INVALID_STATUS")
    return value


def public_status(response, *, expected_task_id):
    """Project untrusted service data before model exposure; no messages or errors."""
    expected = _uuid(expected_task_id)
    if type(response) is not dict or "id" not in response or "status" not in response:
        _fail("OSMOS_INVALID_STATUS")
    task_id = _uuid(response["id"])
    if task_id != expected:
        _fail("OSMOS_TASK_MISMATCH")
    states = ("Created", "Running", "Cancelling", "Cancelled", "Completed", "Failed")
    status = response["status"]
    if type(status) is int and 0 <= status < len(states):
        status = states[status]
    elif type(status) is str and status in tuple(str(index) for index in range(len(states))):
        status = states[int(status)]
    if type(status) is not str or status not in states:
        _fail("OSMOS_INVALID_STATUS")
    result = {"task_id": task_id, "status": status}
    if response.get("operationId") is not None:
        result["operation_id"] = _uuid(response["operationId"])
    details = response.get("runDetails")
    if details is not None:
        if type(details) is not dict:
            _fail("OSMOS_INVALID_STATUS")
        for source, target in (("startedAt", "started_at"), ("completedAt", "completed_at")):
            if details.get(source) is not None:
                result[target] = _timestamp(details[source])
    return result
