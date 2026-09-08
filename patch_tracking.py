import sys
import re

with open('agents/common/tracking_store.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Replace MemoryTrackingStore count_attempts_for_pr
content = content.replace(
    """    def count_attempts_for_pr(self, pr_number: int) -> int:
        # ENGINE_ERROR records don't count -- the engine never produced a fix
        # to evaluate, so they shouldn't consume retry budget. See
        # TrackingStatus.ENGINE_ERROR.
        return sum(
            1 for r in self._records.values()
            if r.pr_number == pr_number and r.status != TrackingStatus.ENGINE_ERROR.value
        )""",
    """    def count_attempts_for_pr(self, pr_number: int) -> int:
        attempts = [r.attempt_number for r in self._records.values() if r.pr_number == pr_number and r.status != TrackingStatus.ENGINE_ERROR.value]
        return max(attempts) if attempts else 0"""
)

# Replace FirestoreTrackingStore count_attempts_for_pr
content = content.replace(
    """    def count_attempts_for_pr(self, pr_number: int) -> int:
        # Filtered client-side (not a second Firestore where-clause) to avoid
        # requiring a new composite index for pr_number + status. Volumes here
        # are bounded by MAX_RETRY_ATTEMPTS, so this is cheap. ENGINE_ERROR
        # records don't count -- see TrackingStatus.ENGINE_ERROR.
        docs = self._col.where("pr_number", "==", pr_number).stream()
        return sum(1 for d in docs if d.to_dict().get("status") != TrackingStatus.ENGINE_ERROR.value)""",
    """    def count_attempts_for_pr(self, pr_number: int) -> int:
        docs = self._col.where("pr_number", "==", pr_number).stream()
        attempts = [d.to_dict().get("attempt_number", 1) for d in docs if d.to_dict().get("status") != TrackingStatus.ENGINE_ERROR.value]
        return max(attempts) if attempts else 0"""
)

# Replace FileTrackingStore count_attempts_for_pr
content = content.replace(
    """    def count_attempts_for_pr(self, pr_number: int) -> int:
        with FileLock(self._lock_path):
            return sum(
                1 for v in self._load().values()
                if v.get("pr_number") == pr_number and v.get("status") != TrackingStatus.ENGINE_ERROR.value
            )""",
    """    def count_attempts_for_pr(self, pr_number: int) -> int:
        with FileLock(self._lock_path):
            attempts = [v.get("attempt_number", 1) for v in self._load().values() if v.get("pr_number") == pr_number and v.get("status") != TrackingStatus.ENGINE_ERROR.value]
            return max(attempts) if attempts else 0"""
)


with open('agents/common/tracking_store.py', 'w', encoding='utf-8') as f:
    f.write(content)
