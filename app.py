import os
from datetime import datetime
from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'netta-secret-key-2024')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///netta.db')
if app.config['SQLALCHEMY_DATABASE_URI'].startswith("postgres://"):
    app.config['SQLALCHEMY_DATABASE_URI'] = app.config['SQLALCHEMY_DATABASE_URI'].replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ==================== МОДЕЛИ ====================

followers = db.Table('followers',
    db.Column('follower_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('followed_id', db.Integer, db.ForeignKey('user.id'))
)

likes = db.Table('likes',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('post_id', db.Integer, db.ForeignKey('post.id'))
)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256))
    display_name = db.Column(db.String(100), default='')
    bio = db.Column(db.String(500), default='')
    avatar_url = db.Column(db.String(500), default='')
    location = db.Column(db.String(100), default='')
    website = db.Column(db.String(200), default='')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    verification = db.Column(db.String(10), default='none')
    verification_request = db.Column(db.Boolean, default=False)
    verification_reason = db.Column(db.String(500), default='')
    role = db.Column(db.String(10), default='user')
    posts = db.relationship('Post', backref='author', lazy='dynamic', cascade='all, delete-orphan')
    followed = db.relationship('User', secondary=followers,
        primaryjoin=(followers.c.follower_id == id),
        secondaryjoin=(followers.c.followed_id == id),
        backref=db.backref('followers_list', lazy='dynamic'), lazy='dynamic')

    def set_password(self, p):
        self.password_hash = generate_password_hash(p)

    def check_password(self, p):
        return check_password_hash(self.password_hash, p)

    def follow(self, u):
        if not self.is_following(u): self.followed.append(u)

    def unfollow(self, u):
        if self.is_following(u): self.followed.remove(u)

    def is_following(self, u):
        return self.followed.filter(followers.c.followed_id == u.id).count() > 0

    def followers_count(self):
        return self.followers_list.count()

    def following_count(self):
        return self.followed.count()

    def feed_posts(self):
        f = Post.query.join(followers, (followers.c.followed_id == Post.user_id)).filter(followers.c.follower_id == self.id)
        o = Post.query.filter_by(user_id=self.id)
        return f.union(o).order_by(Post.created_at.desc())

    def has_liked(self, post):
        return db.session.query(likes).filter(likes.c.user_id == self.id, likes.c.post_id == post.id).count() > 0

    def is_admin(self):
        return self.role == 'admin'


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(500), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    liked_by = db.relationship('User', secondary=likes, backref=db.backref('liked_posts', lazy='dynamic'))

    def likes_count(self):
        return len(self.liked_by)

    def time_ago(self):
        s = (datetime.utcnow() - self.created_at).total_seconds()
        if s < 60: return f"{int(s)}с"
        elif s < 3600: return f"{int(s//60)}м"
        elif s < 86400: return f"{int(s//3600)}ч"
        else: return f"{int(s//86400)}д"


@login_manager.user_loader
def load_user(uid):
    return User.query.get(int(uid))


with app.app_context():
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        a = User(username='admin', email='admin@netta.com', display_name='Netta Admin',
                 bio='Официальный администратор Netta', role='admin', verification='red')
        a.set_password('admin123')
        db.session.add(a)
        db.session.commit()


# ==================== МАРШРУТЫ ====================

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('feed'))
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('feed'))
    if request.method == 'POST':
        u = request.form.get('username', '').strip().lower()
        e = request.form.get('email', '').strip().lower()
        p = request.form.get('password', '')
        p2 = request.form.get('password2', '')
        err = None
        if not u or not e or not p:
            err = 'Заполните все поля'
        elif len(u) < 3:
            err = 'Имя пользователя минимум 3 символа'
        elif len(p) < 6:
            err = 'Пароль минимум 6 символов'
        elif p != p2:
            err = 'Пароли не совпадают'
        elif User.query.filter_by(username=u).first():
            err = 'Имя пользователя занято'
        elif User.query.filter_by(email=e).first():
            err = 'Email уже зарегистрирован'
        if err:
            flash(err, 'danger')
            return render_template('index.html', page='register', username=u, email=e)
        user = User(username=u, email=e, display_name=u)
        user.set_password(p)
        db.session.add(user)
        db.session.commit()
        flash('Регистрация успешна! Войдите в аккаунт.', 'success')
        return redirect(url_for('login'))
    return render_template('index.html', page='register')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('feed'))
    if request.method == 'POST':
        u = request.form.get('username', '').strip().lower()
        p = request.form.get('password', '')
        user = User.query.filter((User.username == u) | (User.email == u)).first()
        if user and user.check_password(p):
            login_user(user)
            flash(f'Добро пожаловать, {user.display_name or user.username}!', 'success')
            return redirect(request.args.get('next') or url_for('feed'))
        flash('Неверное имя пользователя или пароль', 'danger')
        return render_template('index.html', page='login')
    return render_template('index.html', page='login')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/feed', methods=['GET', 'POST'])
@login_required
def feed():
    if request.method == 'POST':
        c = request.form.get('content', '').strip()
        if c:
            db.session.add(Post(content=c[:500], author=current_user))
            db.session.commit()
            flash('Пост опубликован!', 'success')
        return redirect(url_for('feed'))
    page = request.args.get('page', 1, type=int)
    posts = current_user.feed_posts().paginate(page=page, per_page=20, error_out=False)
    return render_template('index.html', page='feed', posts=posts)


@app.route('/explore')
@login_required
def explore():
    page = request.args.get('page', 1, type=int)
    posts = Post.query.order_by(Post.created_at.desc()).paginate(page=page, per_page=20, error_out=False)
    return render_template('index.html', page='feed', posts=posts, explore=True)


@app.route('/profile/<username>')
def profile(username):
    user = User.query.filter_by(username=username.lower()).first_or_404()
    page = request.args.get('page', 1, type=int)
    posts = user.posts.order_by(Post.created_at.desc()).paginate(page=page, per_page=20, error_out=False)
    return render_template('index.html', page='profile', user=user, posts=posts)


@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if request.method == 'POST':
        current_user.display_name = request.form.get('display_name', '')[:100]
        current_user.bio = request.form.get('bio', '')[:500]
        current_user.location = request.form.get('location', '')[:100]
        current_user.website = request.form.get('website', '')[:200]
        current_user.avatar_url = request.form.get('avatar_url', '')[:500]
        db.session.commit()
        flash('Профиль обновлён!', 'success')
        return redirect(url_for('profile', username=current_user.username))
    return render_template('index.html', page='edit_profile')


@app.route('/follow/<username>')
@login_required
def follow(username):
    user = User.query.filter_by(username=username.lower()).first_or_404()
    if user != current_user:
        current_user.follow(user)
        db.session.commit()
    return redirect(url_for('profile', username=username))


@app.route('/unfollow/<username>')
@login_required
def unfollow(username):
    user = User.query.filter_by(username=username.lower()).first_or_404()
    current_user.unfollow(user)
    db.session.commit()
    return redirect(url_for('profile', username=username))


@app.route('/like/<int:post_id>')
@login_required
def like_post(post_id):
    post = Post.query.get_or_404(post_id)
    if current_user.has_liked(post):
        post.liked_by.remove(current_user)
    else:
        post.liked_by.append(current_user)
    db.session.commit()
    return redirect(request.referrer or url_for('feed'))


@app.route('/delete_post/<int:post_id>')
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user and not current_user.is_admin():
        abort(403)
    db.session.delete(post)
    db.session.commit()
    flash('Пост удалён', 'info')
    return redirect(request.referrer or url_for('feed'))


@app.route('/verification', methods=['GET', 'POST'])
@login_required
def verification():
    if current_user.verification != 'none':
        flash('Вы уже верифицированы!', 'info')
        return redirect(url_for('profile', username=current_user.username))
    if current_user.verification_request:
        flash('Ваша заявка уже на рассмотрении', 'info')
        return redirect(url_for('profile', username=current_user.username))
    if request.method == 'POST':
        reason = request.form.get('reason', '').strip()
        if len(reason) < 10:
            flash('Укажите причину (минимум 10 символов)', 'danger')
        else:
            current_user.verification_request = True
            current_user.verification_reason = reason[:500]
            db.session.commit()
            flash('Заявка на верификацию отправлена!', 'success')
            return redirect(url_for('profile', username=current_user.username))
    return render_template('index.html', page='verification')


@app.route('/admin')
@login_required
def admin_dashboard():
    if not current_user.is_admin():
        abort(403)
    users = User.query.order_by(User.created_at.desc()).all()
    vr = User.query.filter_by(verification_request=True).all()
    return render_template('index.html', page='admin', users=users,
                           verification_requests=vr, posts_count=Post.query.count(), users_count=User.query.count())


@app.route('/admin/verify/<int:user_id>/<action>')
@login_required
def admin_verify(user_id, action):
    if not current_user.is_admin():
        abort(403)
    user = User.query.get_or_404(user_id)
    if action == 'approve':
        user.verification = 'blue'
        user.verification_request = False
        flash(f'@{user.username} получил синюю галочку', 'success')
    elif action == 'reject':
        user.verification_request = False
        user.verification_reason = ''
        flash(f'Заявка @{user.username} отклонена', 'warning')
    elif action == 'make_admin':
        user.verification = 'red'
        user.role = 'admin'
        user.verification_request = False
        flash(f'@{user.username} стал администратором', 'success')
    elif action == 'remove_verification':
        user.verification = 'none'
        flash(f'Верификация снята', 'info')
    elif action == 'remove_admin':
        user.verification = 'none'
        user.role = 'user'
        flash(f'Права админа сняты', 'info')
    elif action == 'delete':
        if user.id != current_user.id:
            db.session.delete(user)
            db.session.commit()
            flash('Пользователь удалён', 'danger')
            return redirect(url_for('admin_dashboard'))
    db.session.commit()
    return redirect(url_for('admin_dashboard'))


@app.route('/search')
@login_required
def search():
    q = request.args.get('q', '').strip()
    if not q:
        return redirect(url_for('feed'))
    users = User.query.filter((User.username.ilike(f'%{q}%')) | (User.display_name.ilike(f'%{q}%'))).limit(20).all()
    posts = Post.query.filter(Post.content.ilike(f'%{q}%')).order_by(Post.created_at.desc()).limit(20).all()
    return render_template('index.html', page='search', search_users=users, search_posts=posts, query=q)


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
