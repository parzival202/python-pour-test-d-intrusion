import sys
sys.path.append('.')
from core.database import get_connection

conn = get_connection()
c = conn.cursor()

c.execute('SELECT COUNT(*) FROM sessions WHERE status = "completed"')
print('Completed sessions:', c.fetchone()[0])
c.execute('SELECT COUNT(*) FROM sessions WHERE status = "running"')
print('Running sessions:', c.fetchone()[0])
c.execute('SELECT COUNT(*) FROM sessions WHERE status = "failed"')
print('Failed sessions:', c.fetchone()[0])

conn.close()
