"""
Intentionally Vulnerable Web Application & REST API Target.
Used for immediate local testing, validation, and demoing the vulnerability scanner.
"""

import uvicorn
from fastapi import FastAPI, Request, Response, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse

test_app = FastAPI(
    title="Vulnerable Demo Target API",
    description="Intentional testbed demonstrating OWASP Top 10 web & API security flaws.",
    version="1.0.0",
)


@test_app.get("/", response_class=HTMLResponse)
def index():
    # Intentionally missing HSTS, CSP, X-Frame-Options, etc.
    html = """
    <!DOCTYPE html>
    <html>
    <head><title>Vulnerable Shop & Portal</title></head>
    <body>
        <h1>Welcome to Acme Demo Portal</h1>
        <p>This is a test application containing intentionally vulnerable endpoints for scanner testing.</p>
        <ul>
            <li><a href="/search?q=test">Search (XSS)</a></li>
            <li><a href="/api/users?id=1">User Lookup (SQLi)</a></li>
            <li><a href="/api/users/1">User Profile (BOLA/IDOR)</a></li>
            <li><a href="/redirect?url=https://example.com">Redirect Gateway (Open Redirect)</a></li>
            <li><a href="/view?file=readme.txt">File Viewer (Path Traversal)</a></li>
        </ul>
        <form action="/login" method="POST">
            <input type="text" name="username" placeholder="Username" />
            <input type="password" name="password" placeholder="Password" />
            <button type="submit">Login</button>
        </form>
    </body>
    </html>
    """
    resp = HTMLResponse(content=html)
    resp.headers["Server"] = "Apache/2.4.41 (Ubuntu) PHP/7.4.3"
    resp.headers["X-Powered-By"] = "PHP/7.4.3"
    # Insecure cookie
    resp.set_cookie(key="session_id", value="dummy_session_12345", httponly=False, secure=False)
    return resp


@test_app.get("/search", response_class=HTMLResponse)
def search(q: str = ""):
    # Intentionally vulnerable to Reflected XSS
    html = f"""
    <!DOCTYPE html>
    <html>
    <head><title>Search Results</title></head>
    <body>
        <h2>Search Results for: {q}</h2>
        <p>No records found matching your query.</p>
    </body>
    </html>
    """
    return HTMLResponse(content=html)


@test_app.get("/api/users")
def get_users_query(id: str = "1"):
    # Intentionally triggers simulated SQL errors on syntax probes
    if "'" in id or '"' in id:
        return JSONResponse(
            status_code=500,
            content={"error": "SQLite3::SQLException: near \"'\": syntax error in SELECT * FROM users WHERE id=" + id},
        )
    return {"user_id": id, "name": "John Doe", "role": "user"}


@test_app.get("/api/users/{user_id}")
def get_user_by_id(user_id: int):
    # Intentionally vulnerable to BOLA / IDOR & Excessive Data Exposure
    users = {
        1: {"id": 1, "username": "alice", "email": "alice@company.internal", "credit_card": "4532-1234-5678-9012", "role": "admin"},
        2: {"id": 2, "username": "bob", "email": "bob@company.internal", "credit_card": "5424-9876-5432-1098", "role": "user"},
        3: {"id": 3, "username": "charlie", "email": "charlie@company.internal", "role": "guest"},
    }
    if user_id in users:
        return users[user_id]
    raise HTTPException(status_code=404, detail="User not found")


@test_app.get("/.env", response_class=PlainTextResponse)
def get_env_file():
    # Intentionally exposed .env
    content = """
    APP_ENV=production
    APP_KEY=base64:u3n45928374982374982374=
    DB_CONNECTION=mysql
    DB_HOST=127.0.0.1
    DB_PORT=3306
    DB_DATABASE=corp_production
    DB_USERNAME=root
    DB_PASSWORD=SuperSecretPassw0rd!123
    AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
    AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
    JWT_SECRET=super-secret-jwt-key-2026
    """
    return PlainTextResponse(content=content)


@test_app.get("/.git/config", response_class=PlainTextResponse)
def get_git_config():
    # Intentionally exposed git
    content = """
    [core]
        repositoryformatversion = 0
        filemode = true
        bare = false
        logallrefupdates = true
    [remote "origin"]
        url = https://github.com/company/internal-secret-app.git
        fetch = +refs/heads/*:refs/remotes/origin/*
    [branch "main"]
        remote = origin
        merge = refs/heads/main
    """
    return PlainTextResponse(content=content)


@test_app.get("/actuator/env")
def get_actuator_env():
    # Intentionally exposed actuator
    return {
        "activeProfiles": ["prod"],
        "propertySources": [
            {"name": "systemProperties", "properties": {"java.runtime.version": {"value": "17.0.2"}}},
            {"name": "applicationConfig: [classpath:/application.yml]", "properties": {"spring.datasource.password": {"value": "******"}}},
        ],
    }


@test_app.get("/redirect")
def open_redirect(url: str = Query(...)):
    # Intentionally vulnerable to Open Redirect
    return Response(status_code=302, headers={"Location": url})


@test_app.get("/view", response_class=PlainTextResponse)
def view_file(file: str = "readme.txt"):
    # Intentionally vulnerable to Path Traversal
    if "etc/passwd" in file:
        return PlainTextResponse(
            "root:x:0:0:root:/root:/bin/bash\n"
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
            "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
        )
    if "win.ini" in file:
        return PlainTextResponse("[fonts]\n[extensions]\n")
    return PlainTextResponse(f"Contents of {file}: Sample file data.")


@test_app.get("/api/secret-data")
def secret_data(request: Request):
    # Intentionally accepts JWT with alg: none
    auth = request.headers.get("Authorization", "")
    if "eyJhbGciOiJub25l" in auth or "Bearer" in auth:
        return {"status": "success", "secret": "CONFIDENTIAL_FINANCIAL_METRICS_2026", "access": "granted"}
    raise HTTPException(status_code=401, detail="Unauthorized")


if __name__ == "__main__":
    print("Starting Vulnerable Test Target on http://127.0.0.1:8888")
    uvicorn.run(test_app, host="127.0.0.1", port=8888)
