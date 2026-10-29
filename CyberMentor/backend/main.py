import hashlib
import hmac
import os
import re

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from database.database import get_connection, init_db

app = FastAPI(title="CyberMentor API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup():
    init_db()


# ======================================================================
# AUTH  (Moxa) -- Register / Login
# ======================================================================
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def hash_password(password: str, salt: bytes = None) -> str:
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 120_000)
    return salt.hex() + "$" + digest.hex()


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, digest_hex = stored.split("$")
    except ValueError:
        return False
    check = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), 120_000)
    return hmac.compare_digest(check.hex(), digest_hex)


def user_to_json(row):
    return {
        "id": row["id"],
        "username": row["username"],
        "email": row["email"],
        "xp": row["xp"],
        "level": row["level"],
    }


class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str


class LoginRequest(BaseModel):
    email: str
    password: str


@app.post("/api/auth/register")
def register(req: RegisterRequest):
    username = req.username.strip()
    email = req.email.strip().lower()
    if len(username) < 3:
        raise HTTPException(400, "Username must be at least 3 characters.")
    if not EMAIL_RE.match(email):
        raise HTTPException(400, "Please enter a valid email address.")
    if len(req.password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters.")

    conn = get_connection()
    try:
        if conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone():
            raise HTTPException(409, "An account with this email already exists.")
        cur = conn.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
            (username, email, hash_password(req.password)),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM users WHERE id = ?", (cur.lastrowid,)).fetchone()
        return {"message": "Account created.", "user": user_to_json(row)}
    finally:
        conn.close()


@app.post("/api/auth/login")
def login(req: LoginRequest):
    email = req.email.strip().lower()
    if not email or not req.password:
        raise HTTPException(400, "Email and password are required.")
    conn = get_connection()
    try:
        row = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    finally:
        conn.close()
    if not row or not verify_password(req.password, row["password_hash"]):
        raise HTTPException(401, "Incorrect email or password.")
    return {"message": "Login successful.", "user": user_to_json(row)}


# ======================================================================
# AI MENTOR  (Moxa)
# Educational keyword-matching mentor. It is NOT a real AI model: it picks
# the best prepared answer by matching keywords in the question.
# ======================================================================
MENTOR_TOPICS = [
    {
        "topic": "Phishing",
        "keywords": ["phishing", "phish", "fake email", "suspicious email", "scam email", "spoof"],
        "answer": "Phishing is a trick where an attacker pretends to be someone you trust (a bank, a teacher, a delivery company) to make you click a link or share a password.\n\nSpot it by checking: 1) the real sender address, 2) urgent or threatening language, 3) links whose real destination differs from the text (hover to check), 4) unexpected attachments.\n\nIf unsure, don't click. Open the official site yourself and report the email.",
        "lesson": "phishing-awareness",
    },
    {
        "topic": "Passwords",
        "keywords": ["password", "passphrase", "passwords", "credential", "strong password"],
        "answer": "A strong password is long, unique, and unpredictable. Length matters most: a passphrase of 4 random words (like 'orbit-lemon-tractor-quiet') beats 'P@ssw0rd1'.\n\nNever reuse a password across sites, and use a password manager so you only remember one master passphrase.",
        "lesson": "password-security",
    },
    {
        "topic": "Two-factor authentication",
        "keywords": ["2fa", "mfa", "two factor", "two-factor", "multi factor", "otp", "authenticator"],
        "answer": "Two-factor authentication (2FA) asks for a second proof besides your password, such as a code from an authenticator app. Even if a password leaks, the attacker is stuck.\n\nPrefer an authenticator app or hardware key over SMS codes when possible, and turn it on for email and banking first.",
        "lesson": "password-security",
    },
    {
        "topic": "Malware",
        "keywords": ["malware", "virus", "trojan", "spyware", "worm", "keylogger", "antivirus"],
        "answer": "Malware is software built to harm or spy on you: viruses, trojans (disguised as useful apps), spyware, keyloggers and more.\n\nStay safe: install apps only from official stores, keep your system updated, don't open unexpected attachments, and use a trusted security tool.",
        "lesson": "malware-basics",
    },
    {
        "topic": "Ransomware",
        "keywords": ["ransomware", "ransom", "encrypted files", "files locked"],
        "answer": "Ransomware locks your files and demands payment to unlock them. Your best defence is regular offline backups plus avoiding suspicious attachments and links.\n\nIf you're hit: disconnect from the network, don't pay straight away, and ask a trusted adult, teacher or IT team for help.",
        "lesson": "malware-basics",
    },
    {
        "topic": "Social engineering",
        "keywords": ["social engineering", "manipulat", "impersonat", "pretext", "vishing", "smishing", "baiting"],
        "answer": "Social engineering attacks target people, not computers. Attackers use urgency, authority, fear or friendliness to make you skip your normal caution.\n\nA good habit: pause, verify through a second channel (call the person on a known number), and never share codes or passwords because someone 'from support' asked.",
        "lesson": "phishing-awareness",
    },
    {
        "topic": "Wi-Fi and VPN",
        "keywords": ["wifi", "wi-fi", "public wifi", "vpn", "hotspot", "router", "man in the middle", "mitm"],
        "answer": "Public Wi-Fi can be watched or imitated by attackers. Prefer HTTPS sites, avoid logging into sensitive accounts, and use your mobile data for banking.\n\nA VPN encrypts traffic between your device and the VPN server, which helps on untrusted networks, but it doesn't make you anonymous or protect you from phishing.",
        "lesson": "network-safety",
    },
    {
        "topic": "Firewalls",
        "keywords": ["firewall", "port", "network security", "ddos", "dos attack"],
        "answer": "A firewall filters network traffic using rules, allowing the connections you expect and blocking the rest. Home routers and operating systems include one; keep it switched on.\n\nA DDoS attack floods a service with traffic until it can't respond, which is different from stealing data.",
        "lesson": "network-safety",
    },
    {
        "topic": "SQL injection and XSS",
        "keywords": ["sql injection", "sqli", "xss", "cross site", "injection", "web vulnerability", "owasp"],
        "answer": "SQL injection happens when an app puts user input straight into a database query, letting an attacker change the query. XSS lets an attacker run their script in other users' browsers.\n\nDevelopers prevent both by validating input, using parameterised queries, and escaping output. Learn this safely in practice labs, never on systems you don't own.",
        "lesson": "web-security",
    },
    {
        "topic": "Encryption and hashing",
        "keywords": ["encrypt", "encryption", "hash", "hashing", "https", "tls", "ssl", "cryptography"],
        "answer": "Encryption scrambles data so only someone with the key can read it (it can be reversed). Hashing turns data into a fixed fingerprint that can't be reversed, which is how sites should store passwords.\n\nHTTPS uses encryption (TLS) to protect data between your browser and a website.",
        "lesson": "web-security",
    },
    {
        "topic": "Privacy",
        "keywords": ["privacy", "personal data", "tracking", "social media", "oversharing", "data breach", "leak"],
        "answer": "Privacy means controlling who can see your personal information. Review app permissions, keep social profiles private, and avoid sharing your location, school or ID details publicly.\n\nCheck whether your email appeared in a breach on a trusted breach-notification site and change affected passwords.",
        "lesson": "network-safety",
    },
    {
        "topic": "Backups and updates",
        "keywords": ["backup", "update", "patch", "software update", "outdated"],
        "answer": "Updates fix known security holes, so turn on automatic updates. Backups follow the 3-2-1 idea: 3 copies, on 2 different media, with 1 stored offsite or offline.",
        "lesson": "malware-basics",
    },
    {
        "topic": "Getting started",
        "keywords": ["start", "beginner", "learn", "career", "roadmap", "where do i begin", "how to become"],
        "answer": "Start with the basics: how the internet works, safe habits (passwords, phishing), then networking and web security. Practise in legal sandboxes and with the missions inside CyberMentor.\n\nBegin with the Cyber Academy lessons in order and earn XP as you go.",
        "lesson": "cyber-basics",
    },
    {
        "topic": "CIA triad",
        "keywords": ["cia", "triad", "confidentiality", "integrity", "availability", "what is cyber", "cybersecurity", "cyber security"],
        "answer": "Cybersecurity protects systems and data using three goals, the CIA triad: Confidentiality (only the right people can see it), Integrity (it isn't changed without permission), and Availability (it's there when needed).",
        "lesson": "cyber-basics",
    },
]

GREETINGS = ["hi", "hello", "hey", "yo", "hola", "namaste"]


class MentorRequest(BaseModel):
    message: str


@app.post("/api/mentor/ask")
def mentor_ask(req: MentorRequest):
    text = req.message.strip().lower()
    if not text:
        raise HTTPException(400, "Please type a question for the mentor.")
    if len(text) > 500:
        raise HTTPException(400, "Please keep your question under 500 characters.")

    if text.strip("!. ") in GREETINGS:
        return {
            "topic": "Hello",
            "answer": "Hi, agent! I'm your CyberMentor. Ask me about phishing, passwords, malware, Wi-Fi safety, encryption and more.",
            "lesson": None,
        }

    best, best_score = None, 0
    for topic in MENTOR_TOPICS:
        score = sum(1 for kw in topic["keywords"] if kw in text)
        if score > best_score:
            best, best_score = topic, score

    if not best:
        return {
            "topic": "Not sure yet",
            "answer": "I don't have a prepared answer for that yet. I'm a simple educational mentor, so try asking about phishing, passwords, 2FA, malware, ransomware, Wi-Fi/VPN, firewalls, SQL injection, encryption or privacy.",
            "lesson": None,
        }
    return {"topic": best["topic"], "answer": best["answer"], "lesson": best["lesson"]}
