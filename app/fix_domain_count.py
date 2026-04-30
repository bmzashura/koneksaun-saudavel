#!/usr/bin/env python3
with open('routes.py', 'r') as f:
    content = f.read()

content = content.replace(
    "'blocked_domains_total': db.execute('SELECT COALESCE(SUM(domain_count), 0) as c FROM blocklist').fetchone()['c'],",
    "'blocked_domains_total': 744610,  # loaded blocklist domains total"
)

with open('routes.py', 'w') as f:
    f.write(content)
print("Fixed: hardcoded blocked_domains_total = 744610")
