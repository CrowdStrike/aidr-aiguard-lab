from dataclasses import dataclass


@dataclass
class LogFields:
    citations: str | None = None
    extra_info: str | None = None
    model: str | None = None
    source: str | None = None
    tools: str | None = None

    @classmethod
    def from_dict(cls, data: dict | None) -> "LogFields":
        """
        Hydrate a LogFields instance from a raw dict.
        """
        if not data:
            return cls()
        return cls(
            citations=data.get("citations"),
            extra_info=data.get("extra_info"),
            model=data.get("model"),
            source=data.get("source"),
            tools=data.get("tools"),
        )
