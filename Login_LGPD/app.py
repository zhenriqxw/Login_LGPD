import os
import random
import sqlite3
import smtplib
import secrets
from datetime import datetime
from email.mime.text import MIMEText
import validators

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, jsonify
)
from werkzeug.security import generate_password_hash, check_password_hash
import re

from flask_wtf import CSRFProtect
from flask_talisman import Talisman

from models import User, DataRequest, PasswordResetToken
from env_email import env_email

app = Flask(__name__, static_url_path='', static_folder='static')
app.secret_key = os.getenv("SECRET_KEY", "chave_secreta_super_segura")

csp = {
    'default-src': [
        '\'self\'',
    ],
    'img-src': [
        '\'self\'',
        'data:',
        'blob:'
    ],
    'style-src': [
        '\'self\'',
        '\'unsafe-inline\'',
        'https://fonts.googleapis.com'
    ],
    'script-src': [
        '\'self\'',
        '\'unsafe-inline\''
    ],
    'font-src': [
        '\'self\'',
        'data:',
        'https://fonts.gstatic.com'
    ]
}

Talisman(app, content_security_policy=csp)

app.config['SESSION_PERMANENT'] = False


app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=False  
)

csrf = CSRFProtect(app)

@app.context_processor
def inject_request():
    return dict(request=request)

def get_db_connection():
    conn = sqlite3.connect("database.db")
    conn.row_factory = sqlite3.Row
    return conn

def send_verification_email(email, verification_code):
    mensagem = f'Seu código de verificação é: {verification_code}'
    assunto = 'Código de Verificação'
    return env_email(email, assunto, mensagem)

def validate_password(password):
    """
    Valida a senha para conter:
    - mínimo 8 caracteres
    - pelo menos uma letra maiúscula
    - pelo menos um número
    - pelo menos um caractere especial
    """
    if len(password) < 8:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'\d', password):
        return False
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False
    return True

@app.before_request
def log_request():
    if 'user_id' in session:
        User.log_access(
            user_id=session['user_id'],
            action=f"{request.method} {request.path}",
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )

@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        block_until = session.get('register_block_until')
        now = datetime.now()
        if block_until:
            block_until_dt = datetime.fromisoformat(block_until)
            if now < block_until_dt:
                wait_seconds = (block_until_dt - now).total_seconds()
                flash(f'Tente novamente em {int(wait_seconds)} segundos.', 'error')
                return redirect(url_for('register'))
            else:
                session.pop('register_block_until', None)
                session.pop('register_failed_attempts', None)

        username = request.form['username']
        email = request.form['email']
        password = request.form['senha']

        if not validators.email(email):
            flash('Endereço de e-mail inválido.', 'error')
            return redirect(url_for('register'))

        if not validate_password(password):
            flash("A senha deve ter no mínimo 8 caracteres, uma letra maiúscula, um número e um caractere especial.", "error")
            return redirect(url_for('register'))

        confirm_password = request.form.get('confirmar_senha')
        if not confirm_password or password != confirm_password:
            flash("A senha e a confirmação de senha não coincidem.", "error")
            return redirect(url_for('register'))

        if 'lgpd_consent' not in request.form:
            flash('Você deve concordar com nossa Política de Privacidade para se registrar', 'error')
            return redirect(url_for('register'))

        try:
            new_user = User(username, email, password)
            user_id = new_user.save()

            verification_code = secrets.token_hex(3) 
            send_verification_email(email, verification_code)

            session.update({
                'verification_code': verification_code,
                'verification_code_created_at': datetime.now().isoformat(),
                'verification_attempts': 0,
                'user_id_temp': user_id,
                'username_temp': username,
                'email': email
            })

            session.pop('register_failed_attempts', None)

            flash('Cadastro realizado com sucesso! Verifique seu e-mail para o código de verificação.', 'success')
            return redirect(url_for('verificar', email=email))
        except ValueError as e:
            failed_attempts = session.get('register_failed_attempts', 0) + 1
            session['register_failed_attempts'] = failed_attempts
            if failed_attempts >= 3:
                block_time = now + timedelta(seconds=10)
                session['register_block_until'] = block_time.isoformat()
                flash('Muitas tentativas falhas. Tente novamente em 10 segundos.', 'error')
            else:
                flash(str(e), 'error')

    return render_template('cadastro.html')

@app.route('/verificar', methods=['GET', 'POST'])
def verificar():
    if request.method == 'POST':
        code = request.form['codigo']
        verification_code = session.get('verification_code')
        created_at_str = session.get('verification_code_created_at')
        attempts = session.get('verification_attempts', 0)

        if created_at_str:
            created_at = datetime.fromisoformat(created_at_str)
            if (datetime.now() - created_at).total_seconds() > 300:
                session.pop('verification_code', None)
                session.pop('verification_code_created_at', None)
                session.pop('verification_attempts', None)
                flash('Código expirado. Por favor, solicite um novo código.', 'error')
                return redirect(url_for('login'))

        if attempts >= 3:
            session.pop('verification_code', None)
            session.pop('verification_code_created_at', None)
            session.pop('verification_attempts', None)
            flash('Número máximo de tentativas excedido. Por favor, solicite um novo código.', 'error')
            return redirect(url_for('login'))

        if code == verification_code:
            user_id = session.pop('user_id_temp', None)
            username = session.pop('username_temp', None)
            session.pop('verification_code', None)
            session.pop('verification_code_created_at', None)
            session.pop('verification_attempts', None)

            if user_id:
                user = User.get_by_id(user_id)
                if user and not user.is_verified:
                    user.set_verified(user_id)

            session.update({
                'user_id': user_id,
                'username': username
            })

            flash('Verificação realizada com sucesso!', 'success')
            return redirect(url_for('dashboard'))
        else:
            session['verification_attempts'] = attempts + 1
            flash('Código de verificação inválido ou expirado. Tente novamente.', 'error')

    return render_template('verificar.html', email=session.get('email'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        block_until = session.get('login_block_until')
        now = datetime.now()
        if block_until:
            block_until_dt = datetime.fromisoformat(block_until)
            if now < block_until_dt:
                wait_seconds = (block_until_dt - now).total_seconds()
                flash(f'Tente novamente em {int(wait_seconds)} segundos.', 'error')
                return redirect(url_for('login'))
            else:
                session.pop('login_block_until', None)
                session.pop('login_failed_attempts', None)

        username = request.form['username']
        password = request.form['password']

        try:
            user, user_id = User.get_by_username(username)
            if user:
                if user.check_password(password):
                    if not user.is_verified:
                        verification_code = secrets.token_hex(3) 
                        send_verification_email(user.email, verification_code)
                        session.update({
                            'verification_code': verification_code,
                            'verification_code_created_at': datetime.now().isoformat(),
                            'verification_attempts': 0,
                            'user_id_temp': user_id,
                            'username_temp': username,
                            'email': user.email
                        })
                        flash('Por favor, verifique seu e-mail antes de fazer login.', 'error')
                        return redirect(url_for('verificar'))

                    session.permanent = False
                    session.update({
                        'user_id': user_id,
                        'username': username
                    })

         
                    session.pop('login_failed_attempts', None)

                    flash('Login realizado com sucesso!', 'success')
                    return redirect(url_for('dashboard'))
                else:
                    failed_attempts = session.get('login_failed_attempts', 0) + 1
                    session['login_failed_attempts'] = failed_attempts
                    if failed_attempts >= 3:
                        block_time = now + timedelta(seconds=10)
                        session['login_block_until'] = block_time.isoformat()
                        flash('Muitas tentativas falhas. Tente novamente em 10 segundos.', 'error')
                    else:
                        flash('Senha incorreta. Tente novamente.', 'error')
            else:
                failed_attempts = session.get('login_failed_attempts', 0) + 1
                session['login_failed_attempts'] = failed_attempts
                if failed_attempts >= 3:
                    block_time = now + timedelta(seconds=10)
                    session['login_block_until'] = block_time.isoformat()
                    flash('Muitas tentativas falhas. Tente novamente em 10 segundos.', 'error')
                else:
                    flash('Usuário não encontrado', 'error')
        except ValueError:
            failed_attempts = session.get('login_failed_attempts', 0) + 1
            session['login_failed_attempts'] = failed_attempts
            if failed_attempts >= 3:
                block_time = now + timedelta(seconds=10)
                session['login_block_until'] = block_time.isoformat()
                flash('Muitas tentativas falhas. Tente novamente em 10 segundos.', 'error')
            else:
                flash('Usuário não encontrado', 'error')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Você foi desconectado com sucesso', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html', username=session.get('username'))

@app.route('/privacy')
def privacy():
    return render_template('privacy.html')

@app.route('/request-data', methods=['POST'])
def request_data():
    if 'user_id' not in session:
        return jsonify({'error': 'Não autenticado'}), 401

    request_type = request.json.get('type')
    if request_type not in ['access', 'rectification', 'deletion', 'portability']:
        return jsonify({'error': 'Tipo de solicitação inválido'}), 400

    DataRequest.create_request(session['user_id'], request_type)
    return jsonify({'success': True})

@app.route('/my-requests')
def my_requests():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    requests = DataRequest.get_user_requests(session['user_id'])
    return render_template('my_requests.html', requests=requests)

from uuid import uuid4
from datetime import timedelta

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        if email:
            email = email.strip().lower()

        if not validators.email(email):
            flash('Endereço de e-mail inválido.', 'error')
            return redirect(url_for('forgot_password'))

        user = None
        user_id = None
        if email:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE LOWER(email) = ?', (email,))
            user_data = cursor.fetchone()
            conn.close()
            if user_data:
                user = User(
                    username=user_data['username'],
                    email=user_data['email'],
                    password_hash=user_data['password_hash'],
                    is_verified=user_data['is_verified']
                )
                user_id = user_data['id']

        if user:
            token = secrets.token_urlsafe()
            expires_at = (datetime.now() + timedelta(minutes=30)).isoformat()
            PasswordResetToken.create_token(user_id, token, expires_at)
            reset_link = url_for('reset_password', token=token, _external=True)
            assunto = "Redefinição de senha"
            mensagem = f"Para redefinir sua senha, clique no link: {reset_link}\nEste link expira em 30 minutos."
            env_email(email, assunto, mensagem)
            flash("Um link para redefinir sua senha foi enviado para seu e-mail.", "success")
            return redirect(url_for('forgot_password'))
        else:
            flash("E-mail não encontrado.", "error")

    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    token_data = PasswordResetToken.get_valid_token(token)
    if not token_data:
        flash("Token inválido ou expirado.", "error")
        return redirect(url_for('forgot_password'))

    if PasswordResetToken.is_token_used(token):
        flash("Este link de redefinição já foi usado.", "error")
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not new_password or not confirm_password:
            flash("Por favor, preencha todos os campos.", "error")
            return render_template('reset_password.html', token=token)

        if new_password != confirm_password:
            flash("As senhas não coincidem.", "error")
            return render_template('reset_password.html', token=token)

        if not validate_password(new_password):
            flash("A senha deve ter no mínimo 8 caracteres, uma letra maiúscula, um número e um caractere especial.", "error")
            return render_template('reset_password.html', token=token)

        user_id = token_data['user_id']
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT password_hash, last_password_change FROM users WHERE id = ?', (user_id,))
        user_row = cursor.fetchone()
        if user_row:
            current_password_hash = user_row['password_hash']
            last_change = user_row['last_password_change']
            if check_password_hash(current_password_hash, new_password):
                flash("Essa senha já foi usada anteriormente.", "error")
                conn.close()
                return render_template('reset_password.html', token=token)
            if last_change:
                last_change_dt = datetime.fromisoformat(last_change)
                if (datetime.now() - last_change_dt).total_seconds() < 1800:  # 30 minutes
                    flash("Você só pode alterar a senha uma vez a cada 30 minutos.", "error")
                    conn.close()
                    return redirect(url_for('login'))

        hashed_password = generate_password_hash(new_password)
        now_iso = datetime.now().isoformat()
        cursor.execute(
            'UPDATE users SET password_hash = ?, last_password_change = ? WHERE id = ?',
            (hashed_password, now_iso, user_id)
        )
        conn.commit()

        cursor.execute(
            'UPDATE password_reset_tokens SET used = 1 WHERE token = ?',
            (token,)
        )
        if cursor.rowcount == 0:
            flash("Erro ao invalidar o token. Por favor, tente novamente.", "error")
            conn.close()
            return render_template('reset_password.html', token=token)

        conn.commit()
        conn.close()

        flash("Senha redefinida com sucesso! Você já pode fazer login.", "success")
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)

if __name__ == '__main__':
    from database import init_db
    init_db()
    app.run(debug=True)
