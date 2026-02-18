from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Mapping

__all__ = ("RequestError",)


class RequestError(Exception):
    request_id: str
    request_body: Mapping[str, Any]
    response_body: object | None = None

    def __init__(
        self, message: str, *, request_id: str, request_body: Mapping[str, Any], response_body: object | None = None
    ) -> None:  # noqa: ARG002
        super().__init__(message)
        self.message = message

        self.request_id = request_id
        self.request_body = request_body
        self.response_body = response_body
