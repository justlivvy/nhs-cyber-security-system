# NHS Cyber Security Java + HTML Demo

This version keeps the HTML screens and adds a Java backend so the pages link to real endpoints.
It includes a staff login system and a CSV login database.

## Run

```powershell
cd "C:\Users\oliwi\Documents\Codex\2026-05-05\files-mentioned-by-the-user-nhs\NHS-cyber-security-java"
javac -d build src\NhsCyberSecurityApp.java
java -cp build NhsCyberSecurityApp
```

Then open:

```text
http://127.0.0.1:8080/
```

Default login:

```text
Username: nhs.staff
Password: NHSdemo123!
```

The login database is stored at:

```text
data/logins.csv
```

Passwords are stored as salted PBKDF2 hashes, not plain text.
If Java cannot write to that file because the folder is protected, the app automatically uses a writable temp database and shows the active path on the Login Database page.

## Test

```powershell
cd "C:\Users\oliwi\Documents\Codex\2026-05-05\files-mentioned-by-the-user-nhs\NHS-cyber-security-java"
.\test.ps1
```

The test compiles the Java app, starts it on port 19090, checks the main HTML page, creates a staff login, tests login, tests biometric linking, checks server logs, and checks the login database.
It uses a temporary build folder under your Windows temp directory, so test output does not clutter the project.
