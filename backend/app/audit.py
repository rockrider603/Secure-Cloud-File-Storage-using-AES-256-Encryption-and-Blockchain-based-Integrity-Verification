from contextvars import ContextVar
from uuid import uuid4
from sqlalchemy.orm import Session
from .models import AuditEvent
request_correlation_id: ContextVar[str | None] = ContextVar("request_correlation_id", default=None)
def record(db: Session, actor: str | None, kind: str, resource: str | None, outcome: str):
    db.add(AuditEvent(id=str(uuid4()), actor_id=actor, event_type=kind, resource_id=resource, outcome=outcome, correlation_id=request_correlation_id.get()))
