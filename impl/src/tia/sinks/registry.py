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


_BY_NAME: dict[str, SinkClass] = {plugin.name: plugin for plugin in _BY_KIND.values()}


def sink_class_for(kind: str) -> SinkClass:
    """Look up the plugin by slice kind or by class name.

    Flows carry the class name (``sqli``) while slices carry the NAVI kind
    (``SqlInjection``); both resolve here. Unknown kinds default to the XSS
    rules (the sink text still has to render somewhere), never to a silent pass.
    """
    key = str(kind)
    return _BY_KIND.get(key) or _BY_NAME.get(key) or _XSS
