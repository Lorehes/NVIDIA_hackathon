"""Reuse time-limited observations; never reuse a safe verdict or an egress grant."""
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path


class RelationStore:
    def __init__(self, path):
        self.path = Path(path)

    @contextmanager
    def _connect(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        db = sqlite3.connect(self.path, timeout=5)
        db.execute('CREATE TABLE IF NOT EXISTS relations (source TEXT, destination TEXT, observed REAL, '
                   'PRIMARY KEY(source, destination))')
        try:
            with db:
                yield db
        finally:
            db.close()

    def observe(self, chain, now=None):
        now = time.time() if now is None else now
        with self._connect() as db:
            db.execute('DELETE FROM relations WHERE observed < ?', (now - 86400,))
            for first, last in zip(chain, chain[1:]):
                if (first.get('status') in range(300, 400) and not first.get('error') and not first.get('blocked')
                        and not last.get('error') and not last.get('blocked') and last.get('status') is not None):
                    # No paths, query strings, tokens or page content are persisted.
                    db.execute('INSERT OR REPLACE INTO relations VALUES (?, ?, ?)', (first['host'], last['host'], now))
            db.execute('DELETE FROM relations WHERE rowid NOT IN (SELECT rowid FROM relations ORDER BY observed DESC LIMIT 5000)')

    def related(self, host, now=None):
        now = time.time() if now is None else now
        with self._connect() as db:
            return [{'host': d, 'observed_at': t, 'expires_at': t + 86400, 'kind': 'redirect_observed'}
                    for d, t in db.execute('SELECT destination, observed FROM relations WHERE source=? AND observed>=? '
                                          'ORDER BY observed DESC LIMIT 20', (host, now - 86400))]
