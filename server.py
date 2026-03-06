beOtop · Serveur complet
Auth + Multi-clients + Rôles (admin / client / kiosque)
Version PostgreSQL
"""

from flask import Flask, request, jsonify, session, redirect, url_for, Response
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import os, csv, io, secrets
from datetime import datetime, date
from functools import wraps
import psycopg2
from psycopg2.extras import RealDictCursor

app = Flask(__name__)
app.secret_key
