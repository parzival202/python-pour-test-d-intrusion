import sqlite3

conn = sqlite3.connect('./results/pentest.db')
c = conn.cursor()

# Check tables
c.execute('SELECT name FROM sqlite_master WHERE type="table"')
tables = [row[0] for row in c.fetchall()]
print("Tables in database:", tables)

# Check counts
c.execute('SELECT COUNT(*) FROM sessions')
print('Sessions:', c.fetchone()[0])
c.execute('SELECT COUNT(*) FROM scans')
print('Scans:', c.fetchone()[0])
c.execute('SELECT COUNT(*) FROM vulnerabilities')
print('Vulnerabilities:', c.fetchone()[0])
c.execute('SELECT COUNT(*) FROM exploitations')
print('Exploitations:', c.fetchone()[0])

# Check recent sessions
c.execute('SELECT * FROM sessions ORDER BY start_time DESC LIMIT 3')
rows = c.fetchall()
print("\nRecent sessions:")
for row in rows:
    print(row)

# Check recent scans
c.execute('SELECT * FROM scans ORDER BY created_at DESC LIMIT 3')
rows = c.fetchall()
print("\nRecent scans:")
for row in rows:
    print(row)

# Check recent vulnerabilities
c.execute('SELECT * FROM vulnerabilities ORDER BY created_at DESC LIMIT 3')
rows = c.fetchall()
print("\nRecent vulnerabilities:")
for row in rows:
    print(row)

conn.close()
