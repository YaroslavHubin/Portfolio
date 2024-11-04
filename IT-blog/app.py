from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient
import pymongo
from functools import wraps
from bson.objectid import ObjectId
import os
from datetime import datetime

from cfg import name

name_db = name

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# Підключення до MongoDB
client = pymongo.MongoClient(name_db)
db = client['user_database']
users_collection = db['users']
articles_collection = db['articles']
topics_collection = db['topics']
posts_collection = db['posts']

@app.route('/')
def index():
    user_role = session.get('role', None)
    username = session.get('username', None)
    return render_template('index.html', role=user_role, username=username)

@app.route('/contacts')
def contacts():
    user_role = session.get('role', None)
    username = session.get('username', None)
    return render_template('contacts.html')

@app.route('/rynok_praci')
def rynok_praci():
    user_role = session.get('role', None)
    username = session.get('username', None)
    articles = articles_collection.find({'category': 'rynok_praci'})
    return render_template('rynok_praci.html', articles=articles, role=user_role, username=username)

@app.route('/python')
def python():
    user_role = session.get('role', None)
    username = session.get('username', None)
    articles = articles_collection.find({'category': 'python'})
    return render_template('python.html', articles=articles, role=user_role, username=username)

@app.route('/java')
def java():
    user_role = session.get('role', None)
    username = session.get('username', None)
    articles = articles_collection.find({'category': 'java'})
    return render_template('java.html', articles=articles, role=user_role, username=username)

@app.route('/c_sharp')
def c_sharp():
    user_role = session.get('role', None)
    username = session.get('username', None)
    articles = articles_collection.find({'category': 'c_sharp'})
    return render_template('c_sharp.html', articles=articles, role=user_role, username=username)

@app.route('/html_css')
def html_css():
    user_role = session.get('role', None)
    username = session.get('username', None)
    articles = articles_collection.find({'category': 'html_css'})
    return render_template('html_css.html', articles=articles, role=user_role, username=username)

@app.route('/JQuery')
def JQuery():
    user_role = session.get('role', None)
    username = session.get('username', None)
    articles = articles_collection.find({'category': 'JQuery'})
    return render_template('JQuery.html', articles=articles, role=user_role, username=username)

@app.route('/new_articles')
def new_articles():
    user_role = session.get('role', None)
    username = session.get('username', None)
    articles = articles_collection.find({'category': 'new_articles'})
    return render_template('new_articles.html', articles=articles, role=user_role, username=username)

# Декоратор для перевірки, чи користувач увійшов в систему
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Декоратор для перевірки, чи користувач є адміністратором
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'admin':
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Декоратор для перевірки, чи користувач є власником
def owner_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'owner':
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_or_owner_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('role') not in ['admin', 'owner']:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        # Перевірка чи користувач або email вже існує
        if users_collection.find_one({'$or': [{'username': username}, {'email': email}]}):
            flash('Username or Email already exists')
            return redirect(url_for('register'))

        # Додавання нового користувача до MongoDB з роллю 'user'
        users_collection.insert_one({
            'username': username,
            'email': email,
            'password': hashed_password,
            'role': 'user'  # Роль за замовчуванням
        })

        flash('User registered successfully!')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Пошук користувача по email
        user = users_collection.find_one({'email': email})

        if user and check_password_hash(user['password'], password):
            session['user_id'] = str(user['_id'])
            session['username'] = user['username']
            session['role'] = user['role']  # Збереження ролі користувача в сесії
            flash(f'Welcome {user["username"]}!')
            return redirect(url_for('index'))
        else:
            flash('Invalid email or password')
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/admin/manage_users', methods=['GET', 'POST'])
@admin_required
def manage_users():
    search_query = request.args.get('search', '')
    if search_query:
        users = users_collection.find({
            '$or': [
                {'username': {'$regex': search_query, '$options': 'i'}},
                {'email': {'$regex': search_query, '$options': 'i'}}
            ]
        })
    else:
        users = users_collection.find()
    return render_template('manage_users.html', users=users)

@app.route('/admin/update_role/<user_id>', methods=['POST'])
@admin_required
def update_role(user_id):
    new_role = request.form['role']
    if new_role == 'owner':
        flash('Admins cannot assign the owner role.')
        return redirect(url_for('manage_users'))

    users_collection.update_one(
        {'_id': ObjectId(user_id)},
        {'$set': {'role': new_role}}
    )
    flash('User role updated successfully!')
    return redirect(url_for('manage_users'))

@app.route('/admin/add_user', methods=['GET', 'POST'])
@admin_required
def add_user():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']

        if role == 'owner':
            flash('Admins cannot create owners.')
            return redirect(url_for('add_user'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        if users_collection.find_one({'$or': [{'username': username}, {'email': email}]}):
            flash('Username or Email already exists')
            return redirect(url_for('add_user'))

        users_collection.insert_one({
            'username': username,
            'email': email,
            'password': hashed_password,
            'role': role
        })

        flash('User added successfully!')
        return redirect(url_for('manage_users'))
    return render_template('add_user.html')

@app.route('/admin/delete_user/<user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    users_collection.delete_one({'_id': ObjectId(user_id)})
    flash('User deleted successfully!')
    return redirect(url_for('manage_users'))

@app.route('/admin/reset_password/<user_id>', methods=['POST'])
@admin_required
def reset_password(user_id):
    new_password = request.form['new_password']
    hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256')
    
    users_collection.update_one(
        {'_id': ObjectId(user_id)},
        {'$set': {'password': hashed_password}}
    )
    
    flash('Password reset successfully!')
    return redirect(url_for('manage_users'))

@app.route('/owner/manage_all_users', methods=['GET', 'POST'])
@owner_required
def manage_all_users():
    search_query = request.args.get('search', '')
    if search_query:
        users = users_collection.find({
            '$or': [
                {'username': {'$regex': search_query, '$options': 'i'}},
                {'email': {'$regex': search_query, '$options': 'i'}}
            ]
        })
    else:
        users = users_collection.find()
    return render_template('manage_all_users.html', users=users)

@app.route('/owner/update_role/<user_id>', methods=['POST'])
@owner_required
def owner_update_role(user_id):
    new_role = request.form['role']
    users_collection.update_one(
        {'_id': ObjectId(user_id)},
        {'$set': {'role': new_role}}
    )
    flash('User role updated successfully!')
    return redirect(url_for('manage_all_users'))

@app.route('/owner/add_user', methods=['GET', 'POST'])
@owner_required
def owner_add_user():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        if users_collection.find_one({'$or': [{'username': username}, {'email': email}]}):
            flash('Username or Email already exists')
            return redirect(url_for('owner_add_user'))

        users_collection.insert_one({
            'username': username,
            'email': email,
            'password': hashed_password,
            'role': role
        })

        flash('User added successfully!')
        return redirect(url_for('manage_all_users'))
    return render_template('owner_add_user.html')

@app.route('/owner/delete_user/<user_id>', methods=['POST'])
@owner_required
def owner_delete_user(user_id):
    users_collection.delete_one({'_id': ObjectId(user_id)})
    flash('User deleted successfully!')
    return redirect(url_for('manage_all_users'))

@app.route('/owner/reset_password/<user_id>', methods=['POST'])
@owner_required
def owner_reset_password(user_id):
    new_password = request.form['new_password']
    hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256')
    
    users_collection.update_one(
        {'_id': ObjectId(user_id)},
        {'$set': {'password': hashed_password}}
    )
    
    flash('Password reset successfully!')
    return redirect(url_for('manage_all_users'))

@app.route('/user/edit', methods=['GET', 'POST'])
@login_required
def edit_user():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        user_id = session['user_id']

        # Перевірка унікальності username та email, якщо вони змінюються
        existing_user = users_collection.find_one({'$or': [{'username': username}, {'email': email}], '_id': {'$ne': ObjectId(user_id)}})
        if existing_user:
            flash('Username or Email already exists')
            return redirect(url_for('edit_user'))

        update_fields = {'username': username, 'email': email}
        if password:
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            update_fields['password'] = hashed_password

        users_collection.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': update_fields}
        )

        flash('User information updated successfully!')
        return redirect(url_for('index'))
    return render_template('edit_user.html')

@app.route('/admin/add_article/<category>', methods=['GET', 'POST'])
@admin_or_owner_required
def add_article(category):
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        code = request.form['code']
        author = session['username']  # Автор - поточний користувач
        created_at = datetime.now()   # Дата створення - поточний час

        # Обгортання коду у теги <pre><code>
        if code:
            code = f"<pre><code>{code}</code></pre>"

        # Об'єднання основного контенту та коду
        full_content = content + code

        articles_collection.insert_one({
            'title': title,
            'content': full_content,
            'category': category,
            'author': author,
            'created_at': created_at
        })

        flash('Article added successfully!')
        return redirect(url_for(category))
    
    # Додавання рендеру шаблону для GET запиту
    return render_template('add_article.html', category=category)

# Редагування статті (доступно для адмінів і овнерів)
@app.route('/admin/edit_article/<article_id>', methods=['GET', 'POST'])
@admin_or_owner_required
def edit_article(article_id):
    article = articles_collection.find_one({'_id': ObjectId(article_id)})
    
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        code = request.form['code']
        updated_at = datetime.now()  # Дата останнього редагування

        # Обгортання коду у теги <pre><code>
        if code:
            code = f"<pre><code>{code}</code></pre>"

        # Об'єднання основного контенту та коду
        full_content = content + code

        articles_collection.update_one(
            {'_id': ObjectId(article_id)},
            {'$set': {
                'title': title,
                'content': full_content,
                'updated_at': updated_at
            }}
        )

        flash('Article updated successfully!')
        return redirect(url_for(article['category']))
    
    # Витягнення контенту та коду зі статті для редагування
    content, code = article['content'], ''
    if '<pre><code>' in content and '</code></pre>' in content:
        content, code = content.split('<pre><code>')
        code = code.split('</code></pre>')[0]

    return render_template('edit_article.html', article=article, content=content, code=code)

# Видалення статті (доступно для адмінів і овнерів)
@app.route('/admin/delete_article/<article_id>', methods=['POST'])
@admin_or_owner_required
def delete_article(article_id):
    article = articles_collection.find_one({'_id': ObjectId(article_id)})
    articles_collection.delete_one({'_id': ObjectId(article_id)})
    flash('Article deleted successfully!')
    return redirect(url_for(article['category']))

@app.route('/admin/user_messages/<user_id>', methods=['GET'])
@admin_or_owner_required
def user_messages(user_id):
    user = users_collection.find_one({'_id': ObjectId(user_id)})
    messages = articles_collection.find({'author': user['username']}).sort('created_at', pymongo.DESCENDING).limit(10)
    messages_list = list(messages)
    return render_template('user_messages.html', user=user, messages=messages_list)

@app.route('/forum')
def forum():
    user_role = session.get('role', None)
    username = session.get('username', None)
    topics = topics_collection.find().sort('created_at', pymongo.DESCENDING)
    return render_template('forum.html', topics=topics, role=user_role, username=username)

@app.route('/forum/topic/<topic_id>')
def view_topic(topic_id):
    user_role = session.get('role', None)
    username = session.get('username', None)
    topic = topics_collection.find_one({'_id': ObjectId(topic_id)})
    posts = posts_collection.find({'topic_id': ObjectId(topic_id)}).sort('created_at', pymongo.DESCENDING)
    return render_template('view_topic.html', topic=topic, posts=posts, role=user_role, username=username)

@app.route('/forum/create_topic', methods=['GET', 'POST'])
@login_required
def create_topic():
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        author = session['username']
        created_at = datetime.now()

        topic_id = topics_collection.insert_one({
            'title': title,
            'content': content,
            'author': author,
            'created_at': created_at
        }).inserted_id

        flash('Topic created successfully!')
        return redirect(url_for('view_topic', topic_id=topic_id))

    return render_template('create_topic.html')

@app.route('/forum/topic/<topic_id>/create_post', methods=['GET', 'POST'])
@login_required
def create_post(topic_id):
    if request.method == 'POST':
        content = request.form['content']
        code = request.form['code']
        author = session['username']
        created_at = datetime.now()

        posts_collection.insert_one({
            'topic_id': ObjectId(topic_id),
            'content': content,  # Зберігаємо контент окремо
            'code': code,        # Зберігаємо код окремо
            'author': author,
            'created_at': created_at
        })

        flash('Post created successfully!')
        return redirect(url_for('view_topic', topic_id=topic_id))

    return render_template('create_post.html', topic_id=topic_id)

@app.route('/forum/edit_topic/<topic_id>', methods=['GET', 'POST'])
@login_required
def edit_topic(topic_id):
    topic = topics_collection.find_one({'_id': ObjectId(topic_id)})

    if session['username'] != topic['author'] and session['role'] not in ['admin', 'owner']:
        flash('You do not have permission to edit this topic.')
        return redirect(url_for('view_topic', topic_id=topic_id))

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        updated_at = datetime.now()

        topics_collection.update_one(
            {'_id': ObjectId(topic_id)},
            {'$set': {
                'title': title,
                'content': content,
                'updated_at': updated_at
            }}
        )

        flash('Topic updated successfully!')
        return redirect(url_for('view_topic', topic_id=topic_id))

    return render_template('edit_topic.html', topic=topic)

@app.route('/forum/edit_post/<post_id>', methods=['GET', 'POST'])
@login_required
def edit_post(post_id):
    post = posts_collection.find_one({'_id': ObjectId(post_id)})

    if session['username'] != post['author'] and session['role'] not in ['admin', 'owner']:
        flash('You do not have permission to edit this post.')
        return redirect(url_for('view_topic', topic_id=post['topic_id']))

    if request.method == 'POST':
        content = request.form['content']
        code = request.form['code']
        updated_at = datetime.now()

        posts_collection.update_one(
            {'_id': ObjectId(post_id)},
            {'$set': {
                'content': content,  # Оновлюємо контент окремо
                'code': code,        # Оновлюємо код окремо
                'updated_at': updated_at
            }}
        )

        flash('Post updated successfully!')
        return redirect(url_for('view_topic', topic_id=post['topic_id']))

    return render_template('edit_post.html', post=post, content=post.get('content', ''), code=post.get('code', ''))

@app.route('/forum/delete_topic/<topic_id>', methods=['POST'])
@login_required
def delete_topic(topic_id):
    topic = topics_collection.find_one({'_id': ObjectId(topic_id)})

    if session['username'] != topic['author'] and session['role'] not in ['admin', 'owner']:
        flash('You do not have permission to delete this topic.')
        return redirect(url_for('view_topic', topic_id=topic_id))

    topics_collection.delete_one({'_id': ObjectId(topic_id)})
    posts_collection.delete_many({'topic_id': ObjectId(topic_id)})  # Видаляємо всі повідомлення теми

    flash('Topic deleted successfully!')
    return redirect(url_for('forum'))

@app.route('/forum/delete_post/<post_id>', methods=['POST'])
@login_required
def delete_post(post_id):
    post = posts_collection.find_one({'_id': ObjectId(post_id)})

    if session['username'] != post['author'] and session['role'] not in ['admin', 'owner']:
        flash('You do not have permission to delete this post.')
        return redirect(url_for('view_topic', topic_id=post['topic_id']))

    posts_collection.delete_one({'_id': ObjectId(post_id)})

    flash('Post deleted successfully!')
    return redirect(url_for('view_topic', topic_id=post['topic_id']))

if __name__ == '__main__':
    app.run(debug=True)
