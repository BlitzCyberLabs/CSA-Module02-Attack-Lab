# ClearBank — isolated cybersecurity training target

Fictional Flask/SQLite banking-style app for a controlled classroom lab.

## Windows / VS Code
```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```
Open http://127.0.0.1:5000 on the same machine. Other lab machines can use http://<WINDOWS-LAN-IP>:5000.

## Kali Linux
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 app.py
```

## Fictional sample accounts
- admin / Admin@123
- demo / Demo@123
- j.smith / Welcome@123
- m.taylor / Banking@123
- support / Support@123
- analyst / Analyst@123

Login and search contain intentional SQL injection weaknesses. Search reflects the query as HTML for an XSS demonstration. Events are recorded in logs/security.log. Watch with `Get-Content .\logs\security.log -Wait` on Windows or `tail -f logs/security.log` on Kali.

**Safety:** deliberately vulnerable; loopback only. Use isolated lab machines and dummy data. Never expose publicly, use real data, or reuse these passwords.


## Access from other lab machines (private lab network only)

The Flask server listens on `0.0.0.0:5000`, so it accepts connections through the host's network interfaces.
1. Find the host IP with `ipconfig` on Windows or `ip -4 addr` on Linux.
2. From another machine on the same isolated VMware host-only/private lab network, browse to `http://<HOST-IP>:5000`.
3. If Windows Firewall blocks the connection, allow inbound TCP port 5000 only on the Private profile and restrict the remote scope to the lab subnet.
4. Keep the VMs on a host-only or otherwise isolated private network. Do not use bridged/public exposure for this intentionally vulnerable app.

`0.0.0.0` is the bind address; clients must use the actual IP address of the machine running ClearBank, not `0.0.0.0`.


## SQL implementation used in this lab

The database is SQLite (`data/clearbank.db`).

**Login route (intentionally vulnerable):**
```python
query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
user = get_db().execute(query).fetchone()
```

**Transaction search route (intentionally vulnerable):**
```python
query = f"SELECT id,description,amount,txn_date FROM transactions WHERE description LIKE '%{term}%'"
results = get_db().execute(query).fetchall()
```

Both queries use Python f-string interpolation, so untrusted input is inserted directly into SQL. This is deliberately insecure for the isolated training exercise. Production applications must use parameterized queries and securely hashed passwords.


## Account display and registration
After login, the dashboard greeting displays the exact username used to sign in (for example, `admin` or `j.smith`); the full account-holder name is shown separately. The Register page lets students create additional fictional accounts. Registration uses parameterized SQL; the intentionally vulnerable login and transaction-search routes remain separate training exercises.

Registration has only two fields: username and password. The new account's display name is set to its username.
