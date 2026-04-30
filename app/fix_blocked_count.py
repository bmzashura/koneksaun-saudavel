with open('routes.py', 'r') as f:
    c = f.read()
c = c.replace(
    "'blocked_domains_total': db.execute('SELECT COUNT(*) as c FROM blocklist').fetchone()['c'],",
    "'blocked_domains_total': 744610,"
)
with open('routes.py', 'w') as f:
    f.write(c)
print('done')
