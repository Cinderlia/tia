"""Plans that the trigger agent hands to the injection agent.

Two write behaviours are deliberately kept apart:

* :class:`PayloadPlan` - the value carries an XSS payload, so it is crafted for
  the sink context and verified by reflection/execution;
* :class:`ConstraintWrite` - the value only steers a branch (`status=publish`),
  so any semantically correct value will do and it is verified by a probe and a
  directed trace, never by payload reflection.

:class:`ConstraintPlan` orders both kinds of step; it is the single source of
execution order for the injection agent.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

StepKind = Literal["payload", "constraint"]
ReplayMode = Literal["app_request", "direct_sql_only"]
ConstraintOp = Literal["set", "increment", "append"]


class PayloadPlan(BaseModel):
    """How the payload is built and where it is written."""

    model_config = ConfigDict(extra="forbid")

    table: str
    column: str
    payload: str
    tag: str
    context_kind: str = "html_text"
    out_filter: str = "unknown"
    length_budget: int | None = None
    sink: str = ""
    evidence_refs: list[str] = Field(default_factory=list)


class ConstraintWrite(BaseModel):
    """A value that must be present for a branch to let the request through."""

    model_config = ConfigDict(extra="forbid")

    constraint_id: str
    at: str = ""
    predicate: str = ""
    why: str = ""
    table: str
    column: str
    op: ConstraintOp = "set"
    value: Any = None
    sql: str = ""
    depends_on: list[str] = Field(default_factory=list)
    replay: ReplayMode = "app_request"
    confidence: int = Field(default=0, ge=0, le=100)
    evidence_refs: list[str] = Field(default_factory=list)


class Step(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: StepKind
    ref: str
    phase: str = ""


class ConstraintPlan(BaseModel):
    """Ordered plan: payload and constraint steps interleaved as observed."""

    model_config = ConfigDict(extra="forbid")

    steps: list[Step] = Field(default_factory=list)
    payload: PayloadPlan | None = None
    constraints: list[ConstraintWrite] = Field(default_factory=list)
    final_trigger: dict[str, Any] = Field(default_factory=dict)
    baseline: dict[str, Any] = Field(default_factory=dict)

    def constraint(self, constraint_id: str) -> ConstraintWrite | None:
        for item in self.constraints:
            if item.constraint_id == constraint_id:
                return item
        return None

    def ordered_steps(self) -> list[Step]:
        """Steps in the order they must be solved."""
        return list(self.steps)
