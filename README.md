# Inventory Tracker (SQL)

- **Intern ID:** CITS9948
- **Full Name:** MEKALA ANUDEEP
- **Company:** CodTech IT Solutions
- **Internship Duration:** 4 weeks

A beginner-friendly inventory management app built with Python, Flask, SQLite, HTML, and CSS.

## Features

- Sign-in for Admin, Inventory Manager, and Inventory Staff
- Public registration for Inventory Staff accounts
- Password hashes, Flask sessions, and CSRF checks for form submissions
- Role-based product permissions enforced by Flask
- Add, edit, delete, search, and category filter for products
- Dashboard totals, category chart, and low-stock list (quantity below 5)
- Existing product database and records are preserved

## Run in VS Code on Windows

Open this project folder in VS Code. In the PowerShell terminal, run:

```powershell
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
flask --app app setup-accounts
python app.py
```

The `setup-accounts` command securely asks you to choose and confirm a different password for each fixed username: `admin`, `manager`, and `staff`. Password entry is hidden, and only Werkzeug password hashes are saved. Running the command again resets all three passwords. The application generates a private Flask session key in the ignored `instance/` folder. No password or secret needs to be added to the source files.

To create a manager or staff account after setup, run `flask --app app create-user` and choose a role at the prompt.

The **Register an account** link on the sign-in page creates an Inventory Staff account. Public registration cannot grant Admin or Inventory Manager permissions.

Open http://127.0.0.1:5000 and sign in with one of the three accounts and its chosen password.

## Simple role checks

- **Admin:** can view, search, add, edit, and delete products.
- **Inventory Manager:** can view, search, add, and edit products; delete requests are denied by Flask. Sign in as `manager` to change stock quantities using the Add Product form or a product's Edit action.
- **Inventory Staff:** can view and search products; add, edit, and delete requests are denied by Flask.

Admins can open **Manage Accounts** from the sidebar to reset any account's password.

To check persistence, add or edit a product, stop the app with Ctrl+C, start it again with `python app.py`, and confirm the product remains.

The app creates a `users` table the first time it starts. It does not drop or recreate the existing `products` table.
