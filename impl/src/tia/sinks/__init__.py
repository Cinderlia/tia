"""Vulnerability class plugins (SinkClass).

Each class knows only one thing: what counts as a successful trigger for a
single sink, and how to build a candidate payload for its context. Everything
else (queueing, delivery, evidence, reporting) stays class-agnostic.
"""

from tia.sinks.base import Observation, Outcome, SinkClass
from tia.sinks.registry import sink_class_for
from tia.sinks.xss import XssSinkClass

__all__ = ["Observation", "Outcome", "SinkClass", "XssSinkClass", "sink_class_for"]
