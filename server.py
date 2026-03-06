#!/usr/bin/env python3
"""
beOtop - Serveur complet
Auth + Multi-clients + Roles (admin / client / kiosque)
Version PostgreSQL
"""

from flask import Flask, request, jsonify, session, redirect, url_for, Response
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import os
import csv
import io
import secrets
from datetime import datetime, date
from functools import wraps
import psycopg2
from psycopg2.extras import RealDictCursor

app = Flask(__name__
