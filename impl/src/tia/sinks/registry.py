"""Sink class registry: the only place that maps a slice kind to semantics."""

from __future__ import annotations

from tia.sinks.base import SinkClass
from tia.sinks.sqli import SqliSinkClass
from tia.sinks.xss import XssSinkClass

_XSS = XssSinkClass()
_SQLI = SqliSinkClass()

_BY_KIND: dict[str, SinkClass] = {
    "Xss": _XSS,
    "SqlInjection": _SQLI,
    "SqlRead": _SQLI,
    "SqlWriteLoose": _SQLI,
}


def sink_class_for(kind: str) -> SinkClass:
    """Look up the plugin; unknown kinds default to the XSS rules (the sink text
    still has to render somewhere), never to a silent pass."""
    return _BY_KIND.get(str(kind), _XSS)
