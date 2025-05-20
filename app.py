from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import psycopg2
import os
from dotenv import load_dotenv
from functools import wraps
from datetime import datetime

# Загрузка переменных окружения
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'default-secret-key')

# Конфигурация PostgreSQL
DB_CONFIG = {
    'dbname': os.getenv('DB_NAME', 'taskflow'),
    'user': os.getenv('DB_USER', 'todo_user'),
    'password': os.getenv('DB_PASSWORD', 'todotodo'),
    'host': os.getenv('DB_HOST', 'localhost'),
    'port': os.getenv('DB_PORT', '5432')
}

def get_db_connection():
    """Создание подключения к базе данных"""
    return psycopg2.connect(**DB_CONFIG)

def init_db():
    """Инициализация структуры базы данных"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            # Таблица пользователей
            cur.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    name VARCHAR(100) NOT NULL,
                    email VARCHAR(100) UNIQUE NOT NULL,
                    password VARCHAR(200) NOT NULL
                )
            ''')
            
            # Таблица задач
            cur.execute('''
                CREATE TABLE IF NOT EXISTS tasks (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                    title VARCHAR(255) NOT NULL,
                    description TEXT,
                    priority VARCHAR(10) NOT NULL,
                    due_date DATE,
                    completed BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.commit()
    except Exception as e:
        conn.rollback()
        print(f"Database initialization error: {e}")
    finally:
        conn.close()

# Инициализация базы данных при старте
init_db()

def login_required(f):
    """Декоратор для проверки аутентификации"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Требуется авторизация', 'error')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        remember = request.form.get('remember') == 'on'

        if not email or not password:
            flash('Заполните все поля', 'error')
            return redirect(url_for('login'))

        conn = get_db_connection()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    'SELECT id, password FROM users WHERE email = %s',
                    (email,)
                )
                user = cur.fetchone()

                if user and check_password_hash(user[1], password):
                    session['user_id'] = user[0]
                    session.permanent = remember
                    flash('Вход выполнен успешно', 'success')
                    next_page = request.args.get('next') or url_for('dashboard')
                    return redirect(next_page)
                else:
                    flash('Неверные учетные данные', 'error')
        except Exception as e:
            flash(f'Ошибка входа: {str(e)}', 'error')
        finally:
            conn.close()

    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirmPassword')

        errors = []
        if not name or len(name) < 2:
            errors.append('Имя должно быть не менее 2 символов')
        if not email or '@' not in email:
            errors.append('Некорректный email')
        if not password or len(password) < 6:
            errors.append('Пароль должен быть не менее 6 символов')
        if password != confirm_password:
            errors.append('Пароли не совпадают')

        if errors:
            for error in errors:
                flash(error, 'error')
            return redirect(url_for('signup'))

        hashed_password = generate_password_hash(password)
        conn = get_db_connection()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    'INSERT INTO users (name, email, password) VALUES (%s, %s, %s)',
                    (name, email, hashed_password)
                )
                conn.commit()
                flash('Регистрация прошла успешно! Теперь войдите', 'success')
                return redirect(url_for('login'))
        except psycopg2.IntegrityError:
            flash('Пользователь с таким email уже существует', 'error')
            conn.rollback()
        except Exception as e:
            flash(f'Ошибка регистрации: {str(e)}', 'error')
            conn.rollback()
        finally:
            conn.close()

    return render_template('signup.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Вы успешно вышли из системы', 'success')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    user_id = session['user_id']
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            # Получаем имя пользователя
            cur.execute('SELECT name FROM users WHERE id = %s', (user_id,))
            user_name = cur.fetchone()[0]
            
            return render_template('dashboard.html', user_name=user_name)
            
    except Exception as e:
        flash(f'Ошибка загрузки данных: {str(e)}', 'error')
        return redirect(url_for('index'))
    finally:
        conn.close()

@app.route('/api/tasks', methods=['GET', 'POST'])
@login_required
def handle_tasks():
    user_id = session['user_id']
    conn = get_db_connection()
    
    if request.method == 'GET':
        try:
            with conn.cursor() as cur:
                # Параметры запроса
                search = request.args.get('search', '')
                status = request.args.get('status', 'all')
                priority = request.args.get('priority', 'all')
                sort = request.args.get('sort', 'new')

                # Базовый запрос
                query = '''
                    SELECT id, title, description, priority, 
                           due_date, completed, created_at 
                    FROM tasks 
                    WHERE user_id = %s
                '''
                params = [user_id]

                # Фильтрация
                if search:
                    query += " AND (title ILIKE %s OR description ILIKE %s)"
                    params.extend([f'%{search}%', f'%{search}%'])
                
                if status != 'all':
                    query += " AND completed = %s"
                    params.append(status == 'completed')
                
                if priority != 'all':
                    query += " AND priority = %s"
                    params.append(priority)

                # Сортировка
                if sort == 'new':
                    query += " ORDER BY created_at DESC"
                elif sort == 'old':
                    query += " ORDER BY created_at ASC"
                elif sort == 'priority':
                    query += """ ORDER BY CASE priority
                              WHEN 'high' THEN 1
                              WHEN 'medium' THEN 2
                              WHEN 'low' THEN 3 END"""

                cur.execute(query, params)
                
                tasks = []
                for task in cur.fetchall():
                    tasks.append({
                        'id': task[0],
                        'title': task[1],
                        'description': task[2],
                        'priority': task[3],
                        'due_date': task[4].isoformat() if task[4] else None,
                        'completed': task[5],
                        'created_at': task[6].isoformat()
                    })
                
                return jsonify(tasks)
                
        except Exception as e:
            return jsonify({'error': str(e)}), 500
        finally:
            conn.close()

    elif request.method == 'POST':
        try:
            data = request.get_json()
            with conn.cursor() as cur:
                cur.execute('''
                    INSERT INTO tasks 
                    (user_id, title, description, priority, due_date)
                    VALUES (%s, %s, %s, %s, %s)
                    RETURNING id, created_at
                ''', (
                    user_id,
                    data['title'],
                    data.get('description'),
                    data['priority'],
                    data.get('dueDate')
                ))
                result = cur.fetchone()
                task_id = result[0]
                created_at = result[1].isoformat()
                conn.commit()
                
                return jsonify({
                    'id': task_id,
                    'created_at': created_at
                }), 201
        except Exception as e:
            conn.rollback()
            return jsonify({'error': str(e)}), 400
        finally:
            conn.close()

@app.route('/api/tasks/<int:task_id>', methods=['GET', 'PUT', 'DELETE'])
@login_required
def handle_task(task_id):
    user_id = session['user_id']
    conn = get_db_connection()
    
    try:
        with conn.cursor() as cur:
            # Проверка прав доступа
            cur.execute('SELECT user_id FROM tasks WHERE id = %s', (task_id,))
            result = cur.fetchone()
            if not result or result[0] != user_id:
                return jsonify({'error': 'Task not found'}), 404

            if request.method == 'GET':
                cur.execute('''
                    SELECT id, title, description, priority, 
                           due_date, completed, created_at 
                    FROM tasks 
                    WHERE id = %s
                ''', (task_id,))
                task = cur.fetchone()
                return jsonify({
                    'id': task[0],
                    'title': task[1],
                    'description': task[2],
                    'priority': task[3],
                    'due_date': task[4].isoformat() if task[4] else None,
                    'completed': task[5],
                    'created_at': task[6].isoformat()
                })

            elif request.method == 'PUT':
                data = request.get_json()
                cur.execute('''
                    UPDATE tasks SET
                        title = %s,
                        description = %s,
                        priority = %s,
                        due_date = %s,
                        completed = %s
                    WHERE id = %s
                ''', (
                    data['title'],
                    data.get('description'),
                    data['priority'],
                    data.get('dueDate'),
                    data.get('completed', False),
                    task_id
                ))
                conn.commit()
                return jsonify({'message': 'Task updated'})

            elif request.method == 'DELETE':
                cur.execute('DELETE FROM tasks WHERE id = %s', (task_id,))
                conn.commit()
                return jsonify({'message': 'Task deleted'})

    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 400
    finally:
        conn.close()

@app.route('/api/stats')
@login_required
def get_stats():
    user_id = session['user_id']
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            # Общая статистика
            cur.execute('''
                SELECT 
                    COUNT(*) FILTER (WHERE completed) AS completed,
                    COUNT(*) AS total,
                    COUNT(*) FILTER (WHERE due_date < CURRENT_DATE AND NOT completed) AS overdue
                FROM tasks
                WHERE user_id = %s
            ''', (user_id,))
            stats = cur.fetchone()
            
            # Статистика по приоритетам
            cur.execute('''
                SELECT 
                    priority,
                    COUNT(*) as count,
                    COUNT(*) FILTER (WHERE completed) as completed
                FROM tasks
                WHERE user_id = %s
                GROUP BY priority
            ''', (user_id,))
            priorities = cur.fetchall()
            
            return jsonify({
                'total': stats[1],
                'completed': stats[0],
                'overdue': stats[2],
                'priorities': {
                    priority: {'total': count, 'completed': completed}
                    for priority, count, completed in priorities
                }
            })
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

@app.route('/forgotpassword')
def forgot_password():
    return render_template('forgot-password.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)