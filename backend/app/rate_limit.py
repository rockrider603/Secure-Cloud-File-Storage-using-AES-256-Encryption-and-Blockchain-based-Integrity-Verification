from collections import defaultdict, deque
from threading import Lock
from time import monotonic
from fastapi import HTTPException, Request

class AuthAttemptLimiter:
    """Process-local development limiter; use a shared store behind production replicas."""
    def __init__(self, limit: int = 10, window_seconds: int = 60):
        self.limit=limit; self.window=window_seconds; self.entries=defaultdict(deque); self.lock=Lock()
    def check(self, request: Request):
        key=request.client.host if request.client else "unknown"; now=monotonic()
        with self.lock:
            attempts=self.entries[key]
            while attempts and now-attempts[0]>=self.window: attempts.popleft()
            if len(attempts)>=self.limit: raise HTTPException(429,"Too many authentication attempts; wait before retrying")
        return key
    def fail(self,key: str):
        with self.lock: self.entries[key].append(monotonic())
    def clear(self,key: str):
        with self.lock: self.entries.pop(key,None)

auth_limiter=AuthAttemptLimiter()
