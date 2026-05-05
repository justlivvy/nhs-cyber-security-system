 NHS Cyber Security System

This is a Java and HTML demo of an NHS-style cyber security login system.

The project shows how a staff login, biometric login demo, server logs, and a login database can link together through a Java backend.

## Features

- Staff username and password login
- Create new staff login accounts
- Simple staff dashboard after login
- Biometric registration/login demo linked to staff accounts
- Server logs page showing login activity
- Login database page showing stored users
- Legacy breach demo page for comparison
- Automated test script

## Default Login

```text
Username: nhs.staff
Password: NHSdemo123!
```

## How To Run

Open the project folder in PowerShell, then run:

```powershell
javac -d build src\NhsCyberSecurityApp.java
java -cp build NhsCyberSecurityApp
```

Then open this in a browser:

```text
http://127.0.0.1:8080/
```

## Project Structure

```text
src/NhsCyberSecurityApp.java   Java backend server
web/index.html                 Staff login page
web/register.html              Create staff login page
web/dashboard.html             Staff dashboard
web/popup.html                 Biometric demo page
web/database.html              Login database page
web/server.html                Server logs page
web/sqlmap.html                Legacy breach demo
web/style.css                  Page styling
data/logins.csv                Login database
test.ps1                       Test script
```

## Database

The login database is stored in:

```text
data/logins.csv
```

Passwords are not stored as plain text. They are stored as salted PBKDF2 password hashes.

The database page shows users, roles, biometric IDs, password hash previews, and login times.

## How To Test

Run this in PowerShell from the project folder:

```powershell
.\test.ps1
```

The test checks that:

- the Java app compiles
- the website opens
- staff registration works
- staff login works
- biometric linking works
- server logs are recorded
- the login database returns users
- the legacy breach page data loads

## Sharing With Group Members

Upload the whole project folder to GitHub.

Group members can download it, open the folder in PowerShell, run the Java commands above, and open:

```text
http://127.0.0.1:8080/
```

This runs on their own computer unless the project is deployed online.
