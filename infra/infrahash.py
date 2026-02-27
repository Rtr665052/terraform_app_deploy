from flask import Flask, request, jsonify, render_template
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import hashlib
import itertools
import string
import argparse
import requests

app = Flask(__name__)

# Define the table structure
Base = declarative_base()

class Password(Base):
    __tablename__ = "passwords"
    id = Column(Integer, primary_key=True, autoincrement=True)
    password = Column(String, nullable=False)
    hash = Column(String, nullable=False)

# Initialize the database engine and session
def init_db(database_url):
    engine = create_engine(database_url, echo=False)
    Base.metadata.create_all(engine)  # Ensure the table is created
    Session = sessionmaker(bind=engine)
    return Session()

# Flask routes and APIs
@app.route("/", methods=["GET"])
def index():
    rows = session.query(Password).all()
    return render_template("index.html", rows=rows)

@app.route("/hash", methods=["POST"])
def generate_hash():
    password = request.form.get("password")
    existing_entry = session.query(Password).filter_by(password=password).first()
    if existing_entry:
        return render_template("index.html", hash_result=existing_entry.hash, rows=session.query(Password).all())
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    new_entry = Password(password=password, hash=hashed_password)
    session.add(new_entry)
    session.commit()
    return render_template("index.html", hash_result=hashed_password, rows=session.query(Password).all())

@app.route("/crack", methods=["POST"])
def crack_hash():
    hash_to_crack = request.form.get("hash")
    existing_entry = session.query(Password).filter_by(hash=hash_to_crack).first()
    if existing_entry:
        return render_template("index.html", crack_result=existing_entry.password, rows=session.query(Password).all())
    charset = string.ascii_letters + string.digits
    for length in range(1, 6):
        for guess in itertools.product(charset, repeat=length):
            guess = ''.join(guess)
            if hashlib.sha256(guess.encode()).hexdigest() == hash_to_crack:
                new_entry = Password(password=guess, hash=hash_to_crack)
                session.add(new_entry)
                session.commit()
                return render_template("index.html", crack_result=guess, rows=session.query(Password).all())
    return render_template("index.html", crack_result="Password not found (limit: 5 characters)", rows=session.query(Password).all())

@app.route("/api/passwords", methods=["GET"])
def get_passwords():
    rows = session.query(Password).all()
    return jsonify([{"id": row.id, "password": row.password, "hash": row.hash} for row in rows])

@app.route("/api/passwords/<int:password_id>", methods=["GET"])
def get_password(password_id):
    row = session.query(Password).filter_by(id=password_id).first()
    if row:
        return jsonify({"id": row.id, "password": row.password, "hash": row.hash})
    return jsonify({"error": "Record not found"}), 404

@app.route("/api/passwords", methods=["POST"])
def add_password():
    data = request.json
    password = data.get("password")
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    existing_entry = session.query(Password).filter_by(password=password).first()
    if existing_entry:
        return jsonify({"error": "Password already exists", "id": existing_entry.id}), 400
    new_entry = Password(password=password, hash=hashed_password)
    session.add(new_entry)
    session.commit()
    return jsonify({"message": "Password added successfully", "id": new_entry.id}), 201

@app.route("/api/passwords/<int:password_id>", methods=["PUT"])
def update_password(password_id):
    data = request.json
    new_password = data.get("password")
    new_hashed_password = hashlib.sha256(new_password.encode()).hexdigest()
    row = session.query(Password).filter_by(id=password_id).first()
    if not row:
        return jsonify({"error": "Record not found"}), 404
    row.password = new_password
    row.hash = new_hashed_password
    session.commit()
    return jsonify({"message": "Password updated successfully"})

@app.route("/api/passwords/<int:password_id>", methods=["DELETE"])
def delete_password(password_id):
    row = session.query(Password).filter_by(id=password_id).first()
    if not row:
        return jsonify({"error": "Record not found"}), 404
    session.delete(row)
    session.commit()
    return jsonify({"message": "Password deleted successfully"})

# Sync API for sharing passwords between instances
@app.route("/api/sync", methods=["POST"])
def sync_passwords():
    """
    Sync passwords from another instance.
    """
    data = request.json
    for record in data.get("passwords", []):
        # Check if the password already exists
        existing_entry = session.query(Password).filter_by(hash=record["hash"]).first()
        if not existing_entry:
            # Add the new password
            new_entry = Password(password=record["password"], hash=record["hash"])
            session.add(new_entry)
    session.commit()
    return jsonify({"message": "Sync successful"}), 200

@app.route("/api/sync-trigger", methods=["POST"])
def trigger_sync():
    """
    Trigger synchronization between two instances.
    """
    data = request.json
    target_instance = data.get("target_instance")  # URL of the other instance

    # Fetch passwords from this instance
    local_passwords = session.query(Password).all()
    local_data = [{"password": row.password, "hash": row.hash} for row in local_passwords]

    # Send local passwords to the target instance
    response = requests.post(f"{target_instance}/api/sync", json={"passwords": local_data})
    if response.status_code == 200:
        return jsonify({"message": "Sync triggered successfully"}), 200
    return jsonify({"error": "Failed to sync with target instance"}), response.status_code

# Main entry point
if __name__ == "__main__":
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Run the Flask application.")
    parser.add_argument("--db", type=str, default="data.db", help="Database file name (default: data.db)")
    parser.add_argument("--port", type=int, default=5000, help="Port to run the application on (default: 5000)")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Host IP address (default: 0.0.0.0)")
    args = parser.parse_args()

    # Initialize the database
    database_url = f"sqlite:///{args.db}"
    session = init_db(database_url)

    # Run the Flask application
    app.run(host=args.host, port=args.port)
