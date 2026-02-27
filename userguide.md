# **InfraHash Application User Guide**

InfraHash is a Flask-based application for managing and synchronizing password hashes. It supports SHA-256 hashing, password cracking (up to 5 characters), CRUD operations, and synchronization between multiple instances.

---

## **Getting Started**

### **Requirements**
- Python 3.9 or higher
- Flask
- SQLAlchemy
- Requests library
- `uv` package manager

### **Installation**
1. Clone the repository:
```sh
git clone <repository-url>
cd infrahash
   ```
2. Install uv:
```sh
pip install uv
```
3. Sync Dependencies:
```sh
uv sync
```

## **Running the Application**
### **Default Configuration**

Run the application with default settings:
```sh
uv run python infrahash.py
```

- Database: data.db (SQLite)
- Port: 5000
- Host: 0.0.0.0

### **Custom Configuration**

You can specify custom database file, port, and host:
```sh
uv run python infrahash.py --db custom.db --port 8080 --host 127.0.0.1
```

- Database: custom.db
- Port: 8080
- Host: 127.0.0.1

## **Using the Application**
### **Web Interface**

1. Open your browser and navigate to: http://\<host>:\<port>

Example:
http://127.0.0.1:5000

2. Password Hashing:
    - Enter a password in the "Password Hash" section.
    - Click "Generate Hash" to create a SHA-256 hash.

3. Password Cracking:
    - Enter a hash in the "Crack Password Hash" section.
    - Click "Crack Hash" to attempt brute-force cracking (up to 5 characters).

4. Stored Passwords:
    - View all stored passwords and hashes in the table.
    - Use the search bar to filter passwords and hashes.


### **API Endpoints**
1. Add a Password
    - Endpoint: POST /api/passwords
    - Description: Add a new password to the database.
    - Request:
```sh
curl -X POST -H "Content-Type: application/json" -d '{"password": "example"}' http://localhost:5000/api/passwords
```

2. Get All Passwords
    - Endpoint: GET /api/passwords
    - Description: Retrieve all passwords from the database.
    - Request:
```sh
curl http://localhost:5000/api/passwords
```

3. Get a Specific Password
    - Endpoint: GET /api/passwords/<password_id>
    - Description: Retrieve a specific password by its ID.
    - Request:
```sh
curl http://localhost:5000/api/passwords/1
```

4. Update a Password
    - Endpoint: PUT /api/passwords/<password_id>
    - Description: Update an existing password.
    - Request:
```sh
curl -X PUT -H "Content-Type: application/json" -d '{"password": "newpassword"}' http://localhost:5000/api/passwords/1
```

5. Delete a Password
    - Endpoint: DELETE /api/passwords/<password_id>
    - Description: Delete a password by its ID.
    - Request:
```sh
curl -X DELETE http://localhost:5000/api/passwords/1
```

6. Sync Passwords
    - Endpoint: POST /api/sync
    - Description: Sync passwords from another instance.
    - Request:
```sh
curl -X POST -H "Content-Type: application/json" -d '{"passwords": [{"password": "example", "hash": "5e884898da28047151d0e56f8dc6292773603d0d6aabbddc8fbb3f8b5e6c1a6"}]}' http://localhost:5000/api/sync
```

7. Trigger Sync
    - Endpoint: POST /api/sync-trigger
    - Description: Trigger synchronization between two instances.
    - Request:
```sh
curl -X POST -H "Content-Type: application/json" -d '{"target_instance": "http://localhost:5001"}' http://localhost:5000/api/sync-trigger
```

## **Testing the Application**
1. Run Two Instances

```sh
uv run python infrahash.py --db instance_a.db --port 5000
uv run python infrahash.py --db instance_b.db --port 5001
```
2. Add Passwords to Instance A

```sh
curl -X POST -H "Content-Type: application/json" -d '{"password": "example"}' http://localhost:5000/api/passwords
```
3. Trigger Sync from Instance A to Instance B

```sh
curl -X POST -H "Content-Type: application/json" -d '{"target_instance": "http://localhost:5001"}' http://localhost:5000/api/sync-trigger
```
4. Verify Passwords on Instance B

```sh
curl http://localhost:5001/api/passwords
```

