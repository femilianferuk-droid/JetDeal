from __future__ import annotations

import os
import secrets
from datetime import datetime, timezone
from functools import wraps

import psycopg
from flask import Flask, abort, flash, g, redirect, render_template_string, request, session, url_for
from markupsafe import Markup
from psycopg.rows import dict_row
from werkzeug.security import check_password_hash, generate_password_hash

DATABASE_URL = os.environ.get("DATABASE_URL")
_schema_ready = False
CATEGORIES = ("Аккаунты", "Подписки", "API доступ")
SERVICES = ("ChatGPT", "Claude", "MiniMax", "DeepSeek", "Gemini", "Kimi")

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", secrets.token_hex(32)),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    MAX_CONTENT_LENGTH=64 * 1024,
)


def get_db():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is required")
    if "db" not in g:
        g.db = psycopg.connect(DATABASE_URL, row_factory=dict_row, connect_timeout=10)
    return g.db


@app.teardown_appcontext
def close_db(_error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def now():
    return datetime.now(timezone.utc)


def init_db():
    global _schema_ready
    if _schema_ready:
        return
    db = get_db()
    with db.cursor() as cursor:
        cursor.execute("SELECT pg_advisory_xact_lock(%s)", (742031,))
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id BIGSERIAL PRIMARY KEY,
                username VARCHAR(30) NOT NULL,
                email VARCHAR(120) NOT NULL,
                password_hash TEXT NOT NULL,
                balance BIGINT NOT NULL DEFAULT 50000 CHECK(balance >= 0),
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            CREATE UNIQUE INDEX IF NOT EXISTS users_username_lower_key ON users (LOWER(username));
            CREATE UNIQUE INDEX IF NOT EXISTS users_email_lower_key ON users (LOWER(email));
            CREATE TABLE IF NOT EXISTS listings (
                id BIGSERIAL PRIMARY KEY,
                seller_id BIGINT NOT NULL REFERENCES users(id),
                title VARCHAR(80) NOT NULL,
                category VARCHAR(30) NOT NULL,
                service VARCHAR(30) NOT NULL,
                description VARCHAR(1000) NOT NULL,
                price BIGINT NOT NULL CHECK(price > 0),
                status VARCHAR(10) NOT NULL DEFAULT 'active' CHECK(status IN ('active','sold')),
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            CREATE TABLE IF NOT EXISTS orders (
                id BIGSERIAL PRIMARY KEY,
                listing_id BIGINT NOT NULL REFERENCES listings(id),
                buyer_id BIGINT NOT NULL REFERENCES users(id),
                seller_id BIGINT NOT NULL REFERENCES users(id),
                amount BIGINT NOT NULL CHECK(amount > 0),
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            CREATE INDEX IF NOT EXISTS idx_listings_status ON listings(status);
            CREATE INDEX IF NOT EXISTS idx_orders_buyer ON orders(buyer_id);
            CREATE INDEX IF NOT EXISTS idx_orders_seller ON orders(seller_id);
        """)
    db.commit()
    _schema_ready = True


@app.before_request
def load_user_and_csrf():
    init_db()
    g.user = None
    if session.get("user_id"):
        g.user = get_db().execute("SELECT * FROM users WHERE id = %s", (session["user_id"],)).fetchone()
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    if request.method == "POST" and not secrets.compare_digest(request.form.get("csrf_token", ""), session["csrf_token"]):
        abort(400, "Недействительный CSRF-токен")


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            flash("Войдите, чтобы продолжить.", "warning")
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def money(value):
    return f"{int(value):,}".replace(",", " ") + " ₽"


app.jinja_env.filters["money"] = money

BASE = r'''<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="description" content="JetDeal — маркетплейс аккаунтов, подписок и API-доступа к нейросетям.">
  <title>{{ title }} — JetDeal</title>
  <style>
    :root{--ink:#111827;--paper:#f6f7f9;--card:#fff;--muted:#667085;--line:#e4e7ec;--blue:#1769e0;--mint:#17b26a;--radius:18px}
    *{box-sizing:border-box}html{background:var(--paper);scroll-behavior:smooth}body{margin:0;color:var(--ink);background:var(--paper);font-family:Inter,Arial,sans-serif;line-height:1.5}a{color:inherit;text-decoration:none}button,input,select,textarea{font:inherit}button{cursor:pointer}.container{width:min(1160px,calc(100% - 32px));margin:auto}.top{position:sticky;top:0;z-index:20;background:rgba(246,247,249,.94);border-bottom:1px solid var(--line);backdrop-filter:blur(12px)}.nav{min-height:70px;display:flex;align-items:center;justify-content:space-between;gap:24px}.brand{font-size:24px;font-weight:900;letter-spacing:-1px}.brand i{font-style:normal;color:var(--blue)}.links{display:flex;align-items:center;gap:20px}.links a{font-size:14px;font-weight:700;color:var(--muted)}.links a:hover{color:var(--ink)}.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;min-height:44px;padding:0 18px;border:1px solid var(--line);border-radius:12px;background:var(--card);color:var(--ink);font-weight:800;transition:.2s}.btn:hover{transform:translateY(-1px);border-color:#b8c0cc}.btn-primary{background:var(--blue);border-color:var(--blue);color:#fff}.btn-dark{background:var(--ink);border-color:var(--ink);color:#fff}.btn-block{width:100%}.balance{padding:8px 12px;border-radius:10px;background:#e9f8f0;color:#087443;font-size:13px;font-weight:900}.hero{padding:72px 0 44px}.hero-grid{display:grid;grid-template-columns:1.35fr .65fr;gap:24px}.hero-main{padding:48px;border-radius:28px;background:var(--ink);color:#fff;overflow:hidden}.eyebrow{display:inline-flex;padding:7px 10px;border-radius:99px;background:#e8f1ff;color:#1255b5;font-size:12px;font-weight:900;text-transform:uppercase;letter-spacing:.08em}.hero .eyebrow{background:#233149;color:#b8d5ff}.hero h1{max-width:720px;margin:20px 0 16px;font-size:clamp(42px,7vw,76px);line-height:.98;letter-spacing:-.06em}.hero p{max-width:600px;margin:0 0 28px;color:#cbd5e1;font-size:18px}.actions{display:flex;flex-wrap:wrap;gap:10px}.trust{display:flex;flex-direction:column;justify-content:space-between;padding:30px;border:1px solid var(--line);border-radius:28px;background:var(--card)}.trust strong{font-size:56px;line-height:1;color:var(--blue);letter-spacing:-.05em}.trust p{color:var(--muted)}.section{padding:28px 0 64px}.section-head{display:flex;align-items:end;justify-content:space-between;gap:16px;margin-bottom:22px}.section-head h2{margin:8px 0 0;font-size:34px;letter-spacing:-.04em}.section-head p{margin:0;color:var(--muted)}.filters{display:grid;grid-template-columns:2fr repeat(3,1fr) auto;gap:10px;padding:14px;border:1px solid var(--line);border-radius:18px;background:var(--card);margin-bottom:20px}.field{display:flex;flex-direction:column;gap:7px}.field label{font-size:13px;font-weight:800}.input{width:100%;min-height:46px;padding:10px 13px;border:1px solid var(--line);border-radius:11px;background:var(--card);color:var(--ink);outline:none}.input:focus{border-color:var(--blue);box-shadow:0 0 0 3px #1769e01a}textarea.input{min-height:130px;resize:vertical}.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:16px}.card{display:flex;flex-direction:column;padding:22px;border:1px solid var(--line);border-radius:var(--radius);background:var(--card);transition:.2s}.card:hover{transform:translateY(-3px);box-shadow:0 14px 34px #10182810}.card-top{display:flex;justify-content:space-between;align-items:center;gap:10px}.service{font-size:13px;font-weight:900;color:var(--blue)}.tag{padding:5px 8px;border-radius:8px;background:var(--paper);color:var(--muted);font-size:11px;font-weight:800}.card h3{margin:28px 0 8px;font-size:20px;line-height:1.25}.card p{display:-webkit-box;overflow:hidden;margin:0 0 20px;color:var(--muted);font-size:14px;-webkit-line-clamp:2;-webkit-box-orient:vertical}.card-foot{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-top:auto}.price{font-size:22px;font-weight:900;letter-spacing:-.03em}.panel{padding:26px;border:1px solid var(--line);border-radius:22px;background:var(--card)}.form-card{width:min(560px,100%);margin:54px auto}.form-card h1{margin:0 0 8px;font-size:34px}.form-card>p{margin:0 0 24px;color:var(--muted)}.form-grid{display:grid;gap:16px}.hint{font-size:12px;color:var(--muted)}.flash-wrap{position:fixed;z-index:40;top:82px;left:50%;width:min(520px,calc(100% - 32px));transform:translateX(-50%)}.flash{padding:13px 16px;border:1px solid var(--line);border-radius:12px;background:var(--card);box-shadow:0 12px 30px #10182818;font-weight:700}.flash.success{border-color:#8bdbb3}.flash.warning{border-color:#f3bd68}.detail{display:grid;grid-template-columns:1.3fr .7fr;gap:20px;padding:54px 0}.detail h1{margin:14px 0;font-size:44px;line-height:1.08;letter-spacing:-.045em}.detail-copy{color:var(--muted);font-size:17px;white-space:pre-line}.buybox{position:sticky;top:94px;height:max-content}.buybox .price{display:block;margin:14px 0;font-size:36px}.meta{display:grid;gap:0;margin:22px 0;border-top:1px solid var(--line)}.meta div{display:flex;justify-content:space-between;padding:13px 0;border-bottom:1px solid var(--line)}.meta span{color:var(--muted)}.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin:24px 0}.stat{padding:20px;border:1px solid var(--line);border-radius:16px;background:var(--card)}.stat strong{display:block;font-size:28px}.stat span{color:var(--muted);font-size:13px}.table-list{display:grid;gap:10px}.row{display:grid;grid-template-columns:1fr auto;align-items:center;gap:12px;padding:16px;border:1px solid var(--line);border-radius:14px;background:var(--card)}.row p{margin:3px 0 0;color:var(--muted);font-size:13px}.empty{padding:44px;text-align:center;border:1px dashed #c9ced6;border-radius:18px;color:var(--muted)}footer{padding:28px 0;border-top:1px solid var(--line);color:var(--muted);font-size:13px}.footer-inner{display:flex;justify-content:space-between;gap:16px}.menu{display:none;border:0;background:transparent;font-size:24px}.notice{padding:12px 14px;border-radius:12px;background:#e8f1ff;color:#164c91;font-size:13px}.danger{color:#b42318}
    @media(max-width:800px){.menu{display:block}.links{display:none;position:absolute;top:70px;left:16px;right:16px;flex-direction:column;align-items:stretch;padding:16px;border:1px solid var(--line);border-radius:16px;background:var(--card)}.links.open{display:flex}.hero{padding-top:36px}.hero-grid,.detail{grid-template-columns:1fr}.hero-main{padding:32px 24px}.trust{gap:34px}.filters{grid-template-columns:1fr}.grid{grid-template-columns:1fr 1fr}.buybox{position:static}.detail h1{font-size:36px}.stats{grid-template-columns:1fr}.section-head{align-items:start;flex-direction:column}}
    @media(max-width:540px){.grid{grid-template-columns:1fr}.hero h1{font-size:43px}.container{width:min(100% - 22px,1160px)}.footer-inner{flex-direction:column}.row{grid-template-columns:1fr}.section{padding-bottom:44px}}
  </style>
</head>
<body>
<header class="top"><nav class="container nav" aria-label="Главная навигация"><a class="brand" href="{{ url_for('index') }}">Jet<i>Deal</i></a><button class="menu" aria-label="Открыть меню" aria-expanded="false" onclick="const links=document.querySelector('.links');links.classList.toggle('open');this.setAttribute('aria-expanded',links.classList.contains('open'))">Меню</button><div class="links"><a href="{{ url_for('index') }}#catalog">Каталог</a>{% if g.user %}<a href="{{ url_for('sell') }}">Продать</a><a href="{{ url_for('dashboard') }}">Кабинет</a><span class="balance">{{ g.user['balance']|money }}</span><a class="btn" href="{{ url_for('logout') }}">Выйти</a>{% else %}<a href="{{ url_for('login') }}">Войти</a><a class="btn btn-primary" href="{{ url_for('register') }}">Регистрация</a>{% endif %}</div></nav></header>
{% with messages=get_flashed_messages(with_categories=true) %}{% if messages %}<div class="flash-wrap">{% for category,message in messages %}<div class="flash {{ category }}">{{ message }}</div>{% endfor %}</div>{% endif %}{% endwith %}
<main>{{ content|safe }}</main>
<footer><div class="container footer-inner"><span>© 2026 JetDeal. Независимый маркетплейс.</span><span>Не хранит пароли и API-ключи · Демо-баланс</span></div></footer>
<script>setTimeout(()=>document.querySelector('.flash-wrap')%s.remove(),4500)</script>
</body></html>'''


def page(title, template, **context):
    content = render_template_string(template, **context)
    return render_template_string(BASE, title=title, content=Markup(content))


CARD = '''<article class="card"><div class="card-top"><span class="service">{{ item.service }}</span><span class="tag">{{ item.category }}</span></div><h3>{{ item.title }}</h3><p>{{ item.description }}</p><div class="card-foot"><span class="price">{{ item.price|money }}</span><a class="btn" href="{{ url_for('listing_detail', listing_id=item.id) }}">Подробнее</a></div></article>'''


@app.route("/")
def index():
    category = request.args.get("category", "")
    service = request.args.get("service", "")
    search = request.args.get("q", "").strip()[:80]
    sort = request.args.get("sort", "new")
    sql = "SELECT l.*,u.username FROM listings l JOIN users u ON u.id=l.seller_id WHERE l.status='active'"
    params = []
    if category in CATEGORIES:
        sql += " AND l.category=%s"; params.append(category)
    if service in SERVICES:
        sql += " AND l.service=%s"; params.append(service)
    if search:
        sql += " AND (l.title LIKE %s OR l.description LIKE %s)"; params += [f"%{search}%", f"%{search}%"]
    order = {"cheap":"l.price ASC", "expensive":"l.price DESC", "new":"l.id DESC"}.get(sort, "l.id DESC")
    items = get_db().execute(sql + " ORDER BY " + order, params).fetchall()
    cards = "".join(render_template_string(CARD, item=item) for item in items)
    template = '''
    <section class="hero"><div class="container hero-grid"><div class="hero-main"><span class="eyebrow">Маркет нейросетей</span><h1>Доступ к AI без лишних шагов.</h1><p>Покупайте и продавайте аккаунты, подписки и API-доступ. Без хранения секретов на платформе.</p><div class="actions"><a class="btn btn-primary" href="#catalog">Смотреть предложения</a><a class="btn" href="{{ url_for('sell') }}">Разместить объявление</a></div></div><aside class="trust"><div><span class="eyebrow">Безопасный процесс</span><p>Деньги переводятся продавцу только после оформления заказа. Данные доступа стороны передают вне JetDeal.</p></div><div><strong>{{ count }}+</strong><p>активных предложений прямо сейчас</p></div></aside></div></section>
    <section class="section" id="catalog"><div class="container"><div class="section-head"><div><span class="eyebrow">Каталог</span><h2>Найдите нужный доступ</h2></div><p>{{ count }} предложений</p></div>
    <form class="filters" method="get"><input class="input" name="q" value="{{ search }}" placeholder="Поиск по каталогу" aria-label="Поиск"><select class="input" name="category" aria-label="Категория"><option value="">Все категории</option>{% for v in categories %}<option {{ 'selected' if v==category }}>{{ v }}</option>{% endfor %}</select><select class="input" name="service" aria-label="Нейросеть"><option value="">Все нейросети</option>{% for v in services %}<option {{ 'selected' if v==service }}>{{ v }}</option>{% endfor %}</select><select class="input" name="sort" aria-label="Сортировка"><option value="new" {{ 'selected' if sort=='new' }}>Сначала новые</option><option value="cheap" {{ 'selected' if sort=='cheap' }}>Сначала дешевле</option><option value="expensive" {{ 'selected' if sort=='expensive' }}>Сначала дороже</option></select><button class="btn btn-dark">Найти</button></form>
    {% if cards %}<div class="grid">{{ cards|safe }}</div>{% else %}<div class="empty">По вашему запросу предложений пока нет.</div>{% endif %}</div></section>'''
    return page("Маркет аккаунтов и подписок", template, count=len(items), cards=Markup(cards), categories=CATEGORIES, services=SERVICES, category=category, service=service, search=search, sort=sort)


@app.route("/register", methods=["GET", "POST"])
def register():
    if g.user: return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        error = None
        if not (3 <= len(username) <= 30): error = "Имя должно содержать от 3 до 30 символов."
        elif "@" not in email or len(email) > 120: error = "Укажите корректный email."
        elif len(password) < 8: error = "Пароль должен содержать минимум 8 символов."
        if error: flash(error, "warning")
        else:
            try:
                row = get_db().execute("INSERT INTO users(username,email,password_hash,balance,created_at) VALUES(%s,%s,%s,%s,%s) RETURNING id", (username,email,generate_password_hash(password),50000,now())).fetchone()
                get_db().commit(); session.clear(); session["user_id"] = row["id"]
                flash("Аккаунт создан. На баланс начислено 50 000 ₽ для демо-покупок.", "success")
                return redirect(url_for("dashboard"))
            except psycopg.IntegrityError:
                get_db().rollback(); flash("Имя или email уже используются.", "warning")
    return page("Регистрация", FORM_AUTH, heading="Создать аккаунт", lead="Получите 50 000 ₽ демо-баланса и протестируйте JetDeal.", action="Регистрация", register=True)


@app.route("/login", methods=["GET", "POST"])
def login():
    if g.user: return redirect(url_for("dashboard"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower(); password = request.form.get("password", "")
        user = get_db().execute("SELECT * FROM users WHERE email=%s", (email,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear(); session["user_id"] = user["id"]
            flash("С возвращением!", "success")
            target = request.args.get("next", "")
            return redirect(target if target.startswith("/") and not target.startswith("//") else url_for("dashboard"))
        flash("Неверный email или пароль.", "warning")
    return page("Вход", FORM_AUTH, heading="Войти в JetDeal", lead="Управляйте покупками и объявлениями в одном месте.", action="Войти", register=False)


FORM_AUTH = '''<section class="container"><div class="panel form-card"><h1>{{ heading }}</h1><p>{{ lead }}</p><form class="form-grid" method="post"><input type="hidden" name="csrf_token" value="{{ session.csrf_token }}">{% if register %}<div class="field"><label for="username">Имя пользователя</label><input class="input" id="username" name="username" minlength="3" maxlength="30" required autocomplete="username"></div>{% endif %}<div class="field"><label for="email">Email</label><input class="input" id="email" name="email" type="email" maxlength="120" required autocomplete="email"></div><div class="field"><label for="password">Пароль</label><input class="input" id="password" name="password" type="password" minlength="8" required autocomplete="{{ 'new-password' if register else 'current-password' }}"></div><button class="btn btn-primary btn-block">{{ action }}</button></form></div></section>'''


@app.route("/logout")
def logout():
    session.clear(); return redirect(url_for("index"))


@app.route("/listing/<int:listing_id>")
def listing_detail(listing_id):
    item = get_db().execute("SELECT l.*,u.username FROM listings l JOIN users u ON u.id=l.seller_id WHERE l.id=%s", (listing_id,)).fetchone()
    if item is None: abort(404)
    template = '''<section class="container detail"><div class="panel"><span class="eyebrow">{{ item.service }} · {{ item.category }}</span><h1>{{ item.title }}</h1><p class="detail-copy">{{ item.description }}</p><div class="notice">JetDeal не хранит логины, пароли и API-ключи. После заказа договоритесь с продавцом о безопасной передаче доступа вне платформы.</div></div><aside class="panel buybox"><span class="tag">{{ 'В продаже' if item.status=='active' else 'Продано' }}</span><span class="price">{{ item.price|money }}</span><div class="meta"><div><span>Продавец</span><b>{{ item.username }}</b></div><div><span>Категория</span><b>{{ item.category }}</b></div><div><span>Сервис</span><b>{{ item.service }}</b></div></div>{% if item.status=='active' and (not g.user or g.user.id != item.seller_id) %}<form method="post" action="{{ url_for('buy', listing_id=item.id) }}"><input type="hidden" name="csrf_token" value="{{ session.csrf_token }}"><button class="btn btn-primary btn-block">Купить за {{ item.price|money }}</button></form>{% elif g.user and g.user.id == item.seller_id %}<div class="notice">Это ваше объявление.</div>{% else %}<button class="btn btn-block" disabled>Предложение продано</button>{% endif %}</aside></section>'''
    return page(item["title"], template, item=item)


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    if request.method == "POST":
        title=request.form.get("title","").strip(); category=request.form.get("category",""); service=request.form.get("service",""); description=request.form.get("description","").strip()
        try: price=int(request.form.get("price",0))
        except ValueError: price=0
        error=None
        if not (8 <= len(title) <= 80): error="Название должно содержать от 8 до 80 символов."
        elif category not in CATEGORIES or service not in SERVICES: error="Выберите корректную категорию и нейросеть."
        elif not (20 <= len(description) <= 1000): error="Описание должно содержать от 20 до 1000 символов."
        elif not (50 <= price <= 1_000_000): error="Цена должна быть от 50 до 1 000 000 ₽."
        if error: flash(error,"warning")
        else:
            row=get_db().execute("INSERT INTO listings(seller_id,title,category,service,description,price,created_at) VALUES(%s,%s,%s,%s,%s,%s,%s) RETURNING id",(g.user["id"],title,category,service,description,price,now())).fetchone(); get_db().commit()
            flash("Объявление опубликовано.","success"); return redirect(url_for("listing_detail",listing_id=row["id"]))
    template='''<section class="container"><div class="panel form-card"><h1>Новое объявление</h1><p>Опишите предложение, но не указывайте логины, пароли и ключи доступа.</p><form class="form-grid" method="post"><input type="hidden" name="csrf_token" value="{{ session.csrf_token }}"><div class="field"><label>Название</label><input class="input" name="title" maxlength="80" required placeholder="Например, ChatGPT Plus на 30 дней"></div><div class="field"><label>Категория</label><select class="input" name="category" required>{% for v in categories %}<option>{{ v }}</option>{% endfor %}</select></div><div class="field"><label>Нейросеть</label><select class="input" name="service" required>{% for v in services %}<option>{{ v }}</option>{% endfor %}</select></div><div class="field"><label>Описание</label><textarea class="input" name="description" minlength="20" maxlength="1000" required placeholder="Срок доступа, формат передачи, особенности предложения"></textarea><span class="hint">Никогда не публикуйте секретные данные.</span></div><div class="field"><label>Цена, ₽</label><input class="input" type="number" name="price" min="50" max="1000000" required></div><button class="btn btn-primary">Опубликовать</button></form></div></section>'''
    return page("Продать",template,categories=CATEGORIES,services=SERVICES)


@app.post("/buy/<int:listing_id>")
@login_required
def buy(listing_id):
    db=get_db()
    try:
        item=db.execute("SELECT * FROM listings WHERE id=%s FOR UPDATE",(listing_id,)).fetchone()
        buyer=db.execute("SELECT * FROM users WHERE id=%s FOR UPDATE",(g.user["id"],)).fetchone()
        if item is None or item["status"]!="active": raise ValueError("Предложение уже недоступно.")
        if item["seller_id"]==buyer["id"]: raise ValueError("Нельзя купить собственное объявление.")
        if buyer["balance"]<item["price"]: raise ValueError("Недостаточно средств на демо-балансе.")
        changed=db.execute("UPDATE listings SET status='sold' WHERE id=%s AND status='active'",(listing_id,)).rowcount
        if changed != 1: raise ValueError("Предложение уже купил другой пользователь.")
        db.execute("UPDATE users SET balance=balance-%s WHERE id=%s",(item["price"],buyer["id"]))
        db.execute("UPDATE users SET balance=balance+%s WHERE id=%s",(item["price"],item["seller_id"]))
        db.execute("INSERT INTO orders(listing_id,buyer_id,seller_id,amount,created_at) VALUES(%s,%s,%s,%s,%s)",(listing_id,buyer["id"],item["seller_id"],item["price"],now()))
        db.commit(); flash("Покупка оформлена. Согласуйте передачу доступа с продавцом вне JetDeal.","success")
    except ValueError as error:
        db.rollback(); flash(str(error),"warning")
    return redirect(url_for("dashboard"))


@app.route("/dashboard")
@login_required
def dashboard():
    db=get_db(); uid=g.user["id"]
    listings=db.execute("SELECT * FROM listings WHERE seller_id=%s ORDER BY id DESC",(uid,)).fetchall()
    purchases=db.execute("SELECT o.*,l.title,u.username FROM orders o JOIN listings l ON l.id=o.listing_id JOIN users u ON u.id=o.seller_id WHERE o.buyer_id=%s ORDER BY o.id DESC",(uid,)).fetchall()
    sales=db.execute("SELECT o.*,l.title,u.username FROM orders o JOIN listings l ON l.id=o.listing_id JOIN users u ON u.id=o.buyer_id WHERE o.seller_id=%s ORDER BY o.id DESC",(uid,)).fetchall()
    template='''<section class="section"><div class="container"><div class="section-head"><div><span class="eyebrow">Личный кабинет</span><h2>Здравствуйте, {{ g.user.username }}</h2></div><a class="btn btn-primary" href="{{ url_for('sell') }}">Новое объявление</a></div><div class="stats"><div class="stat"><strong>{{ g.user.balance|money }}</strong><span>Демо-баланс</span></div><div class="stat"><strong>{{ listings|length }}</strong><span>Мои объявления</span></div><div class="stat"><strong>{{ purchases|length }}</strong><span>Покупки</span></div></div><div class="section-head"><h2>Мои объявления</h2></div><div class="table-list">{% for x in listings %}<a class="row" href="{{ url_for('listing_detail',listing_id=x.id) }}"><div><b>{{ x.title }}</b><p>{{ x.service }} · {{ 'В продаже' if x.status=='active' else 'Продано' }}</p></div><strong>{{ x.price|money }}</strong></a>{% else %}<div class="empty">Вы ещё ничего не продаёте.</div>{% endfor %}</div><div class="section-head" style="margin-top:42px"><h2>Покупки</h2></div><div class="table-list">{% for x in purchases %}<div class="row"><div><b>{{ x.title }}</b><p>Продавец: {{ x.username }}. Передача доступа согласуется вне JetDeal.</p></div><strong>{{ x.amount|money }}</strong></div>{% else %}<div class="empty">Покупок пока нет.</div>{% endfor %}</div><div class="section-head" style="margin-top:42px"><h2>Продажи</h2></div><div class="table-list">{% for x in sales %}<div class="row"><div><b>{{ x.title }}</b><p>Покупатель: {{ x.username }}</p></div><strong>{{ x.amount|money }}</strong></div>{% else %}<div class="empty">Продаж пока нет.</div>{% endfor %}</div></div></section>'''
    return page("Личный кабинет",template,listings=listings,purchases=purchases,sales=sales)


@app.errorhandler(404)
def not_found(_error):
    return page("Не найдено",'<section class="container"><div class="panel form-card"><h1>Страница не найдена</h1><p>Проверьте адрес или вернитесь в каталог.</p><a class="btn btn-primary" href="{{ url_for(\'index\') }}">В каталог</a></div></section>'),404


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
