from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from flask_socketio import SocketIO, send
import bcrypt

import uuid
import sqlite3

app = Flask(__name__)
app.config['SECRET_KEY'] = 'very-long-random-secret-key'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
DATABASE = 'market.db'
socketio = SocketIO(app)

# ---------- DB 연결 ----------
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # 결과를 dict처럼 사용하기 위함
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# ---------- 테이블 생성(최초 실행 시에만) ----------
def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        # ---------- 사용자 테이블 ----------
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                is_blocked INTEGER NOT NULL DEFAULT 0,
                balance INTEGER NOT NULL DEFAULT 0,
                bio TEXT
            )
        """)
        # ---------- 상품 테이블 ----------
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price TEXT NOT NULL,
                seller_id TEXT NOT NULL,
                is_sold INTEGER NOT NULL DEFAULT 0
            )
        """)
        # ---------- 신고 테이블 ----------
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS report (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                reason TEXT NOT NULL
            )
        """)
        # ---------- 송금 내역 테이블 ----------
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS transfer_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id TEXT NOT NULL,
                receiver_id TEXT NOT NULL,
                amount INTEGER NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (sender_id) REFERENCES user(id),
                FOREIGN KEY (receiver_id) REFERENCES user(id)
            )
        """)
        db.commit()

# ---------- 기본 라우트 ----------
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

# ---------- 회원가입 ----------
# ✅ [요구사항1] 사용자 등록 기능: 사람들이 플랫폼에 가입할 수 있도록 지원
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()
        
        if not (3 <= len(username) <= 20 and username.isalnum()):
            flash('사용자명은 3~20자의 영문자, 숫자만 가능합니다.')
            return redirect(url_for('register'))
        if not (8 <= len(password) <= 20):
            flash('비밀번호는 8~20자여야 합니다.')
            return redirect(url_for('register'))
        
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        if cursor.fetchone():
            flash('이미 존재하는 사용자명입니다.')
            return redirect(url_for('register'))
        
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        user_id = str(uuid.uuid4())
        cursor.execute("INSERT INTO user (id, username, password) VALUES (?, ?, ?)",
                       (user_id, username, hashed_password))
        db.commit()
        flash('회원가입이 완료되었습니다. 로그인 해주세요.')
        return redirect(url_for('login'))
    return render_template('register.html')

# ---------- 로그인 ----------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        cursor = db.cursor()
        # username으로만 조회 (password는 해시로 비교할 것이므로 쿼리에 포함시키지 않음)
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        user = cursor.fetchone()
        
        if user:
            # 저장된 해시된 비밀번호와 입력된 비밀번호 비교
            stored_hashed_password = user['password']  # 데이터베이스에서 가져온 해시
            if bcrypt.checkpw(password.encode('utf-8'), stored_hashed_password):
                if user['is_blocked']:
                    flash('이 계정은 차단되어 로그인할 수 없습니다.')
                    return redirect(url_for('login'))
                session['user_id'] = user['id']
                flash('로그인 성공!')
                if user['role'] == 'admin':
                    return redirect(url_for('admin_page'))
                return redirect(url_for('dashboard'))
            else:
                flash('아이디 또는 비밀번호가 올바르지 않습니다.')
                return redirect(url_for('login'))
        else:
            flash('아이디 또는 비밀번호가 올바르지 않습니다.')
            return redirect(url_for('login'))
    return render_template('login.html')

def is_blocked(user_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT is_blocked FROM user WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    return user and user['is_blocked'] == 1


# ---------- 로그아웃 ----------
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('로그아웃되었습니다.')
    return redirect(url_for('index'))

@app.route('/admin')

def admin_page():
    if 'user_id' not in session or not is_admin(session['user_id']):
        flash('관리자만 접근할 수 있습니다.')
        return redirect(url_for('dashboard'))
    
    db = get_db()
    cursor = db.cursor()
    
    # ---------- 모든 사용자 조회 ----------
    cursor.execute("SELECT * FROM user")
    users = cursor.fetchall()
    
    # ---------- 모든 신고 조회 (신고자 username 포함) ----------
    cursor.execute("""
        SELECT r.id, r.reporter_id, u.username AS reporter_username, r.target_id, r.reason
        FROM report r
        JOIN user u ON r.reporter_id = u.id
    """)
    reports = cursor.fetchall()
    
    # ---------- 모든 상품 조회 (판매자 username 포함) ----------
    cursor.execute("""
        SELECT p.*, u.username AS seller_username
        FROM product p
        JOIN user u ON p.seller_id = u.id
    """)
    products = cursor.fetchall()
    
    return render_template('admin.html', users=users, reports=reports, products=products)



# ---------- 채팅 ----------
# ✅ [요구사항3] 사용자 간 실시간 채팅 기능 구현
@socketio.on('send_message')
def handle_send_message_event(data):
    if 'message' not in data or not isinstance(data['message'], str):
        return
    message = data['message'].strip()
    if not (1 <= len(message) <= 500):
        socketio.emit('error', {'message': '메시지는 1~500자여야 합니다.'}, to=request.sid)
        return
    data['message_id'] = str(uuid.uuid4())
    send(data, broadcast=True)

@socketio.on('connect')
def handle_connect():
    if 'user_id' not in session:
        socketio.emit('error', {'message': 'Unauthorized'}, to=request.sid)
        return False
    

def is_admin(user_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT role FROM user WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    return user and user['role'] == 'admin'


# ✅ [요구사항7] 관리자 권한으로 유저 및 상품 관리
@app.route('/admin/product/<product_id>/delete', methods=['POST'])
def admin_delete_product(product_id):
    if 'user_id' not in session or not is_admin(session['user_id']):
        flash('관리자만 접근할 수 있습니다.')
        return redirect(url_for('dashboard'))
    
    db = get_db()
    cursor = db.cursor()
    
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    if not product:
        flash('상품이 없습니다.')
        return redirect(url_for('admin_page'))
    
    # ---------- 상품 삭제 ----------
    cursor.execute("DELETE FROM product WHERE id = ?", (product_id,))
    db.commit()
    flash('상품이 삭제되었습니다.')
    return redirect(url_for('admin_page'))

@app.route('/admin/block/<user_id>', methods=['POST'])
def block_user(user_id):
    if 'user_id' not in session or not is_admin(session['user_id']):
        flash('관리자만 접근할 수 있습니다.')
        return redirect(url_for('dashboard'))
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM user WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    if not user:
        flash('사용자를 찾을 수 없습니다.')
        return redirect(url_for('admin_page'))
    
    if user['role'] == 'admin':
        flash('관리자는 차단할 수 없습니다.')
        return redirect(url_for('admin_page'))
    
    cursor.execute("UPDATE user SET is_blocked = 1 WHERE id = ?", (user_id,))
    db.commit()
    flash(f"{user['username']} 사용자가 차단되었습니다.")
    return redirect(url_for('admin_page'))


@app.route('/admin/unblock/<user_id>', methods=['POST'])
def admin_unblock_user(user_id):
    if 'user_id' not in session or not is_admin(session['user_id']):
        flash('관리자만 접근할 수 있습니다.')
        return redirect(url_for('dashboard'))
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM user WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    if not user:
        flash('사용자를 찾을 수 없습니다.')
        return redirect(url_for('admin_page'))
    
    cursor.execute("UPDATE user SET is_blocked = 0 WHERE id = ?", (user_id,))
    db.commit()
    flash(f"{user['username']} 사용자의 차단이 해제되었습니다.")
    return redirect(url_for('admin_page'))


# ---------- 대시보드 -----------
@app.route('/dashboard', methods=['GET'])
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    cursor = db.cursor()
    # ---------- 현재 사용자 조회 ----------
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    
    # ---------- 검색 ----------
    # ✅ [요구사항6] 상품 검색 기능 (키워드 기반)

    search_query = request.args.get('search', '').strip()
    if search_query:
        cursor.execute("""
            SELECT p.*, u.username AS seller_username
            FROM product p
            JOIN user u ON p.seller_id = u.id
            WHERE p.title LIKE ? OR p.description LIKE ?
        """, (f'%{search_query}%', f'%{search_query}%'))
    else:
        cursor.execute("""
            SELECT p.*, u.username AS seller_username
            FROM product p
            JOIN user u ON p.seller_id = u.id
        """)
    all_products = cursor.fetchall()
    
    return render_template('dashboard.html', products=all_products, user=current_user, search_query=search_query)

@app.route('/profile/<user_id>', methods=['GET', 'POST'])
def profile(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM user WHERE id = ?", (user_id,))
    profile_user = cursor.fetchone()
    if not profile_user:
        flash('사용자를 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST' and session['user_id'] == user_id:
        bio = request.form.get('bio', '')
        cursor.execute("UPDATE user SET bio = ? WHERE id = ?", (bio, user_id))
        
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        if current_password and new_password:
            cursor.execute("SELECT password FROM user WHERE id = ?", (user_id,))
            stored_password = cursor.fetchone()['password']
            if not bcrypt.checkpw(current_password.encode('utf-8'), stored_password):
                flash('현재 비밀번호가 일치하지 않습니다.')
                db.commit()
                return redirect(url_for('profile', user_id=user_id))
            if not (8 <= len(new_password) <= 20):
                flash('새 비밀번호는 8~20자여야 합니다.')
                db.commit()
                return redirect(url_for('profile', user_id=user_id))
            hashed_new_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
            cursor.execute("UPDATE user SET password = ? WHERE id = ?", (hashed_new_password, user_id))
            flash('비밀번호가 변경되었습니다.')
        
        db.commit()
        flash('프로필이 업데이트되었습니다.')
        return redirect(url_for('profile', user_id=user_id))
    
    cursor.execute("SELECT * FROM product WHERE seller_id = ?", (user_id,))
    user_products = cursor.fetchall()
    return render_template('profile.html', user=profile_user, is_owner=(session['user_id'] == user_id), products=user_products)


# ---------- 상품 등록 ----------
# ✅ [요구사항2] 상품 업로드 기능
@app.route('/product/new', methods=['GET', 'POST'])
def new_product():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        price = request.form['price']
        db = get_db()
        cursor = db.cursor()
        product_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO product (id, title, description, price, seller_id) VALUES (?, ?, ?, ?, ?)",
            (product_id, title, description, price, session['user_id'])
        )
        db.commit()
        flash('상품이 등록되었습니다.')
        return redirect(url_for('dashboard'))
    return render_template('new_product.html')

# ---------- 상품 상세 ----------
@app.route('/product/<product_id>')
def view_product(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
    
    cursor.execute("SELECT * FROM user WHERE id = ?", (product['seller_id'],))
    seller = cursor.fetchone()
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    
    return render_template('view_product.html', product=product, seller=seller, user=current_user)

# ✅ [요구사항5] 사용자 간 송금 (구매) 기능
@app.route('/product/<product_id>/buy', methods=['POST'])
def buy_product(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    cursor = db.cursor()
    
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
    if product['is_sold']:
        flash('이미 판매된 상품입니다.')
        return redirect(url_for('view_product', product_id=product_id))
    
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    buyer = cursor.fetchone()
    cursor.execute("SELECT * FROM user WHERE id = ?", (product['seller_id'],))
    seller = cursor.fetchone()
    
    if buyer['id'] == seller['id']:
        flash('자신의 상품은 구매할 수 없습니다.')
        return redirect(url_for('view_product', product_id=product_id))
    
    price = int(product['price'])
    if buyer['balance'] < price:
        flash('소지금이 부족합니다.')
        return redirect(url_for('view_product', product_id=product_id))
    
    new_buyer_balance = buyer['balance'] - price
    new_seller_balance = seller['balance'] + price
    
    cursor.execute("UPDATE user SET balance = ? WHERE id = ?", (new_buyer_balance, buyer['id']))
    cursor.execute("UPDATE user SET balance = ? WHERE id = ?", (new_seller_balance, seller['id']))
    cursor.execute("UPDATE product SET is_sold = 1 WHERE id = ?", (product_id,))
    db.commit()
    
    flash(f'{product["title"]} 상품을 {price}원에 구매했습니다. 남은 소지금: {new_buyer_balance}원')
    return redirect(url_for('dashboard'))


@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()
    user_id = session['user_id']

    if request.method == 'POST':
        receiver_username = request.form['receiver']
        amount = int(request.form['amount'])

        # 수신자 조회
        cursor.execute("SELECT * FROM user WHERE username = ?", (receiver_username,))
        receiver = cursor.fetchone()
        if not receiver:
            flash("수신자가 존재하지 않습니다.")
            return redirect(url_for('transfer'))

        # 송신자 잔액 확인
        cursor.execute("SELECT balance FROM user WHERE id = ?", (user_id,))
        sender = cursor.fetchone()
        if sender['balance'] < amount:
            flash("잔액이 부족합니다.")
            return redirect(url_for('transfer'))

        # 송금 처리
        cursor.execute("UPDATE user SET balance = balance - ? WHERE id = ?", (amount, user_id))
        cursor.execute("UPDATE user SET balance = balance + ? WHERE id = ?", (amount, receiver['id']))
        db.commit()

        flash(f"{receiver_username}님에게 {amount}원을 성공적으로 송금했습니다.")
        return redirect(url_for('dashboard'))

    return render_template('transfer.html')


@app.route('/product/<product_id>', methods=['DELETE'])
def delete_product(product_id):
    if 'user_id' not in session:
        flash('로그인 후 이용해주세요.')
        return redirect(url_for('login'))
    
    db = get_db()
    cursor = db.cursor()
    
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
    
    if product['seller_id'] != session['user_id']:
        flash('본인이 등록한 상품만 삭제할 수 있습니다.')
        return redirect(url_for('view_product', product_id=product_id))
    
    cursor.execute("DELETE FROM product WHERE id = ?", (product_id,))
    db.commit()
    
    flash('상품이 삭제되었습니다.')
    return redirect(url_for('dashboard'))


@app.route('/charge_money', methods=['GET', 'POST'])
def charge_money():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    
    if request.method == 'POST':
        amount = request.form.get('amount', type=int)
        if amount is None or amount <= 0:
            flash('충전 금액은 0보다 커야 합니다.')
            return redirect(url_for('charge_money'))
        
        # ---------- 현재 소지금 추가 ----------
        new_balance = current_user['balance'] + amount
        cursor.execute("UPDATE user SET balance = ? WHERE id = ?", (new_balance, session['user_id']))
        db.commit()
        flash(f'{amount}원이 충전되었습니다. 현재 소지금: {new_balance}원')
        return redirect(url_for('profile', user_id=session['user_id']))
    
    return render_template('charge_money.html', user=current_user)





# ---------- 신고 ----------
# ✅ [요구사항4] 유저/상품 신고 기능 및 관리자 차단 기능

@app.route('/report', methods=['GET', 'POST'])
def report():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        target_id = request.form['target_id']
        reason = request.form['reason']
        db = get_db()
        cursor = db.cursor()
        report_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO report (id, reporter_id, target_id, reason) VALUES (?, ?, ?, ?)",
            (report_id, session['user_id'], target_id, reason)
        )
        db.commit()
        flash('신고가 접수되었습니다.')
        return redirect(url_for('dashboard'))
    return render_template('report.html')

def create_admin():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE username = 'admin'")
        if not cursor.fetchone():
            admin_id = str(uuid.uuid4())
            # 비밀번호를 bcrypt로 해시
            hashed_password = bcrypt.hashpw('admin'.encode('utf-8'), bcrypt.gensalt())
            cursor.execute("INSERT INTO user (id, username, password, bio, role) VALUES (?, ?, ?, ?, ?)",
                           (admin_id, 'admin', hashed_password, 'admin', 'admin'))
            db.commit()
            


if __name__ == '__main__':
    init_db()  # 앱 컨텍스트 내에서 테이블 생성
    create_admin()
    app.jinja_env.globals['is_admin'] = is_admin
    socketio.run(app, debug=True) # 배포시 WSS 적용 (암호화 전송) 