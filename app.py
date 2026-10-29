import hmac
import os
import secrets
import sqlite3
from functools import wraps
from getpass import getpass
from math import isfinite

from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
DB_FILE = os.path.join(os.path.dirname(__file__), "inventory.db")
LOW_STOCK_LIMIT = 5
ROLE_LABELS = {
    "admin": "Admin",
    "inventory_manager": "Inventory Manager",
    "inventory_staff": "Inventory Staff",
}


def load_secret_key():
    """Load a key from the environment or create one in Flask's ignored instance folder."""
    key = os.environ.get("INVENTORY_SECRET_KEY")
    if key:
        return key
    os.makedirs(app.instance_path, exist_ok=True)
    key_file = os.path.join(app.instance_path, "secret_key")
    try:
        with open(key_file, "x", encoding="utf-8") as secret_file:
            secret_file.write(secrets.token_hex(32))
    except FileExistsError:
        pass
    with open(key_file, encoding="utf-8") as secret_file:
        return secret_file.read().strip()


app.secret_key = load_secret_key()
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")


def get_db():
    """Open SQLite and return rows accessible by column name."""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create missing tables while preserving existing products and user accounts."""
    conn = get_db()
    conn.execute(
        """CREATE TABLE IF NOT EXISTS products (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               name TEXT NOT NULL,
               category TEXT NOT NULL,
               quantity INTEGER NOT NULL,
               price REAL NOT NULL)"""
    )
    # Accounts are separate from the existing products table.
    conn.execute(
        """CREATE TABLE IF NOT EXISTS users (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               username TEXT NOT NULL UNIQUE COLLATE NOCASE,
               full_name TEXT NOT NULL,
               password_hash TEXT NOT NULL,
               role TEXT NOT NULL CHECK(role IN (
                   'admin', 'inventory_manager', 'inventory_staff'
               )))"""
    )
    if conn.execute("SELECT COUNT(*) FROM products").fetchone()[0] == 0:
        samples = [
            ("Laptop", "Electronics", 12, 55000.00),
            ("Wireless Mouse", "Accessories", 3, 799.00),
            ("Notebook", "Stationery", 50, 60.00),
            ("USB Cable", "Accessories", 4, 199.50),
            ("Office Chair", "Furniture", 8, 4500.00),
        ]
        conn.executemany(
            "INSERT INTO products (name, category, quantity, price) VALUES (?, ?, ?, ?)",
            samples,
        )
    conn.commit()
    conn.close()


def validate(form):
    """Validate product fields before they are saved."""
    name = form.get("name", "").strip()
    category = form.get("category", "").strip()
    if not name or not category:
        return None, "Name and category are required."
    if len(name) > 100 or len(category) > 100:
        return None, "Name and category must be 100 characters or fewer."
    try:
        quantity = int(form.get("quantity", ""))
        price = float(form.get("price", ""))
    except ValueError:
        return None, "Quantity must be a whole number and price must be a number."
    if quantity < 0 or price < 0 or not isfinite(price):
        return None, "Quantity and price must be valid non-negative numbers."
    return (name, category, quantity, price), None


def login_required(view):
    """Send visitors without a session to the login page."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def role_required(*allowed_roles):
    """Enforce the permitted roles on the server for a route."""
    def decorate(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if g.user is None:
                return redirect(url_for("login"))
            if g.user["role"] not in allowed_roles:
                abort(403)
            return view(*args, **kwargs)
        return wrapped
    return decorate


@app.before_request
def load_logged_in_user():
    """Load the signed-in account and verify tokens on every form submission."""
    user_id = session.get("user_id")
    g.user = None
    if user_id is not None:
        conn = get_db()
        g.user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        conn.close()
        if g.user is None:
            session.clear()
    if request.method == "POST":
        submitted = request.form.get("csrf_token", "")
        expected = session.get("csrf_token", "")
        if not expected or not hmac.compare_digest(submitted, expected):
            abort(400, "The form expired. Please reload the page and try again.")


@app.context_processor
def template_helpers():
    """Make the signed-in user and a CSRF token available to templates."""
    token = session.setdefault("csrf_token", secrets.token_urlsafe(32))
    return {
        "current_user": g.get("user"),
        "role_labels": ROLE_LABELS,
        "csrf_token": token,
    }


@app.route("/login", methods=["GET", "POST"])
def login():
    """Check a password hash and start a signed-in session."""
    if g.user is not None:
        return redirect(url_for("index"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        conn.close()
        if user is None or not check_password_hash(user["password_hash"], password):
            flash("Username or password is incorrect.", "error")
        else:
            session.clear()
            session["user_id"] = user["id"]
            session["csrf_token"] = secrets.token_urlsafe(32)
            flash("Welcome back, " + user["full_name"] + ".", "success")
            return redirect(url_for("index"))
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register a new Inventory Staff account without granting elevated access."""
    if g.user is not None:
        return redirect(url_for("index"))
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirmation = request.form.get("confirm_password", "")
        if not full_name or len(full_name) > 100:
            flash("Enter your name (up to 100 characters).", "error")
        elif not (3 <= len(username) <= 50) or not all(
            char.isalnum() or char in "._-" for char in username
        ):
            flash("Username must be 3–50 characters using letters, numbers, dots, _ or -.", "error")
        elif len(password) < 8:
            flash("Password must contain at least 8 characters.", "error")
        elif password != confirmation:
            flash("Passwords do not match.", "error")
        else:
            conn = get_db()
            try:
                conn.execute(
                    "INSERT INTO users (username, full_name, password_hash, role) "
                    "VALUES (?, ?, ?, 'inventory_staff')",
                    (username, full_name, generate_password_hash(password)),
                )
                conn.commit()
                user_id = conn.execute(
                    "SELECT id FROM users WHERE username = ?", (username,)
                ).fetchone()["id"]
                session.clear()
                session["user_id"] = user_id
                session["csrf_token"] = secrets.token_urlsafe(32)
                flash("Account created. You are signed in as Inventory Staff.", "success")
                return redirect(url_for("index"))
            except sqlite3.IntegrityError:
                flash("That username is already in use.", "error")
            finally:
                conn.close()
    return render_template("register.html")


@app.route("/users")
@role_required("admin")
def manage_users():
    """Let admins view accounts and reset their passwords."""
    conn = get_db()
    users = conn.execute(
        "SELECT id, username, full_name, role FROM users ORDER BY id"
    ).fetchall()
    conn.close()
    return render_template("users.html", users=users)


@app.route("/users/<int:user_id>/reset-password", methods=["POST"])
@role_required("admin")
def reset_user_password(user_id):
    """Reset an account password; only an admin can use this route."""
    password = request.form.get("password", "")
    confirmation = request.form.get("confirm_password", "")
    if len(password) < 8:
        flash("Password must contain at least 8 characters.", "error")
    elif password != confirmation:
        flash("Passwords do not match.", "error")
    else:
        conn = get_db()
        account = conn.execute("SELECT id FROM users WHERE id = ?", (user_id,)).fetchone()
        if account is None:
            flash("User account not found.", "error")
        else:
            conn.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (generate_password_hash(password), user_id),
            )
            conn.commit()
            flash("Password reset successfully.", "success")
        conn.close()
    return redirect(url_for("manage_users"))


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    """End the current signed-in session."""
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


@app.route("/")
@login_required
def index():
    """Show inventory totals and products matching the search filters."""
    search = request.args.get("search", "").strip()
    selected_category = request.args.get("category", "").strip()
    try:
        conn = get_db()
        categories = [row[0] for row in conn.execute(
            "SELECT DISTINCT category FROM products ORDER BY category"
        ).fetchall()]
        total_products, total_units, total_value, low_stock_count = conn.execute(
            "SELECT COUNT(*), COALESCE(SUM(quantity), 0), "
            "COALESCE(SUM(quantity * price), 0), "
            "COALESCE(SUM(CASE WHEN quantity < ? THEN 1 ELSE 0 END), 0) "
            "FROM products", (LOW_STOCK_LIMIT,)
        ).fetchone()
        low_stock_products = conn.execute(
            "SELECT * FROM products WHERE quantity < ? ORDER BY quantity, name",
            (LOW_STOCK_LIMIT,),
        ).fetchall()
        category_rows = conn.execute(
            "SELECT category, COUNT(*) FROM products GROUP BY category ORDER BY category"
        ).fetchall()
        category_labels = [row[0] for row in category_rows]
        category_counts = [row[1] for row in category_rows]
        query = "SELECT * FROM products WHERE name LIKE ?"
        params = [f"%{search}%"]
        if selected_category:
            query += " AND category = ?"
            params.append(selected_category)
        products = conn.execute(query + " ORDER BY id", params).fetchall()
        conn.close()
    except sqlite3.Error:
        flash("Could not read from the database.", "error")
        products, categories = [], []
        total_products, total_units, total_value, low_stock_count = 0, 0, 0, 0
        low_stock_products, category_labels, category_counts = [], [], []
    return render_template(
        "index.html", products=products, total_value=total_value,
        total_products=total_products, limit=LOW_STOCK_LIMIT,
        total_units=total_units, low_stock_count=low_stock_count,
        low_stock_products=low_stock_products,
        category_labels=category_labels, category_counts=category_counts,
        categories=categories, search=search, selected_category=selected_category,
    )


@app.route("/add", methods=["POST"])
@role_required("admin", "inventory_manager")
def add():
    """Add a product for admins and inventory managers."""
    data, error = validate(request.form)
    if error:
        flash(error, "error")
        return redirect(url_for("index"))
    try:
        conn = get_db()
        conn.execute(
            "INSERT INTO products (name, category, quantity, price) VALUES (?, ?, ?, ?)",
            data,
        )
        conn.commit()
        conn.close()
        flash("Product added successfully.", "success")
    except sqlite3.Error:
        flash("Could not add the product.", "error")
    return redirect(url_for("index"))


@app.route("/edit/<int:product_id>", methods=["GET", "POST"])
@role_required("admin", "inventory_manager")
def edit(product_id):
    """Show the edit form (GET) or save validated changes (POST)."""
    try:
        conn = get_db()
        product = conn.execute(
            "SELECT * FROM products WHERE id = ?", (product_id,)
        ).fetchone()
        if product is None:
            conn.close()
            flash("Product not found.", "error")
            return redirect(url_for("index"))
        if request.method == "POST":
            data, error = validate(request.form)
            if error:
                conn.close()
                flash(error, "error")
                return redirect(url_for("edit", product_id=product_id))
            conn.execute(
                "UPDATE products SET name=?, category=?, quantity=?, price=? WHERE id=?",
                data + (product_id,),
            )
            conn.commit()
            conn.close()
            flash("Product updated successfully.", "success")
            return redirect(url_for("index"))
        conn.close()
        return render_template("edit.html", product=product)
    except sqlite3.Error:
        flash("Database error.", "error")
        return redirect(url_for("index"))


@app.route("/delete/<int:product_id>", methods=["POST"])
@role_required("admin")
def delete(product_id):
    """Delete a product; only admins can reach this route."""
    try:
        conn = get_db()
        conn.execute("DELETE FROM products WHERE id = ?", (product_id,))
        conn.commit()
        conn.close()
        flash("Product deleted.", "success")
    except sqlite3.Error:
        flash("Could not delete the product.", "error")
    return redirect(url_for("index"))


def create_account(role):
    """Securely prompt for account details and save only a password hash."""
    full_name = input("Full name: ").strip()
    username = input("Username: ").strip()
    password = getpass("Password: ")
    confirmation = getpass("Confirm password: ")
    if not full_name or not username or len(full_name) > 100 or len(username) > 50:
        print("Name and username are required (up to 100 and 50 characters).")
        return
    if len(password) < 8:
        print("Use a password with at least 8 characters.")
        return
    if password != confirmation:
        print("Passwords did not match.")
        return
    try:
        conn = get_db()
        conn.execute(
            "INSERT INTO users (username, full_name, password_hash, role) VALUES (?, ?, ?, ?)",
            (username, full_name, generate_password_hash(password), role),
        )
        conn.commit()
        conn.close()
        print(f"Created {ROLE_LABELS[role]} account for {username}.")
    except sqlite3.IntegrityError:
        print("That username is already in use.")


@app.cli.command("create-admin")
def create_admin_command():
    """Create an administrator without putting its password in a command."""
    create_account("admin")


@app.cli.command("create-user")
def create_user_command():
    """Create an inventory manager or staff account from a secure prompt."""
    print("Choose role: 1) Inventory Manager  2) Inventory Staff")
    choice = input("Role number: ").strip()
    if choice not in ("1", "2"):
        print("Choose 1 or 2.")
        return
    create_account("inventory_manager" if choice == "1" else "inventory_staff")


@app.cli.command("setup-accounts")
def setup_accounts_command():
    """Set separate initial passwords for the standard admin, manager, and staff users."""
    accounts = [
        ("admin", "admin", "Administrator"),
        ("manager", "inventory_manager", "Inventory Manager"),
        ("staff", "inventory_staff", "Inventory Staff"),
    ]
    passwords = {}
    for username, role, full_name in accounts:
        while True:
            password = getpass(f"Set a password for {username} ({full_name}): ")
            confirmation = getpass("Confirm password: ")
            if len(password) < 8:
                print("Use at least 8 characters.")
            elif password != confirmation:
                print("Passwords did not match.")
            elif password in passwords.values():
                print("Each account must have a different password.")
            else:
                passwords[username] = password
                break

    conn = get_db()
    for username, role, full_name in accounts:
        account = conn.execute(
            "SELECT id FROM users WHERE username = ?", (username,)
        ).fetchone()
        password_hash = generate_password_hash(passwords[username])
        if account:
            conn.execute(
                "UPDATE users SET full_name=?, password_hash=?, role=? WHERE id=?",
                (full_name, password_hash, role, account["id"]),
            )
        else:
            conn.execute(
                "INSERT INTO users (username, full_name, password_hash, role) "
                "VALUES (?, ?, ?, ?)",
                (username, full_name, password_hash, role),
            )
    conn.commit()
    conn.close()
    print("The admin, manager, and staff accounts are ready. Passwords were not displayed.")


init_db()  # Create missing tables without replacing existing inventory data.

if __name__ == "__main__":
    app.run(debug=True)
