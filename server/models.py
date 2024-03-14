import secrets
from config import db, bcrypt, MetaData

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    _password = db.Column(db.String)
    financial_goals = db.relationship('FinancialGoal', backref='user', lazy=True)
    accounts = db.relationship('Account', backref='user', lazy=True)
    family_id = db.Column(db.Integer, db.ForeignKey('family.id'))
    insights = db.relationship('Insight', backref='user', lazy=True)

    def validate_email(self, key, address):
        pattern = "([\w\.]+@[A-Za-z]+\.[A-Za-z]+)"
        if not re.match(pattern, address):
            print("made it here")
            raise AttributeError('email addresses must be in standard format: john.doe@example.com')

        return address

    def validate_password(self, key, password):
        errors = []

        if len(password) < 8:
            errors.append('Password must be at least 8 characters.')

        if not re.search(r"[0-9]", password): 
            errors.append('Password must contain at least one number.')

        if not re.search(r"[!@#$%^&*()?]", password):  
            errors.append('Password must contain at least one special character.')

        if errors:
            raise AttributeError(' '.join(errors))

        return password

    def password_hash(self):
        raise AttributeError('Password hashes may not be viewed')

    def password_hash(self, password):
        password_hash = bcrypt.generate_password_hash(
            password.encode('utf-8'))
        self._password = password_hash.decode('utf-8')

    def authenticate(self, password):
        return bcrypt.check_password_hash(
            self._password, password.encode('utf-8'))

    def generate_code(self):
        return secrets.token_hex(8)

    def generate_forgot_password_message(self):
            subject = "Password Reset Requested"
            body = f"""
                <html>
                    <body>
                        <h1>Hi {self.first_name} {self.last_name},</h1>
                        <p>We received a request to reset your password. If you didn't make the request, please ignore this email.</p>
                        <p>Please reset your password with the following code: {self.code}</p>
                        <p>Thank you,</p>
                        <p>Money Magnet</p>
                    </body>
                </html>
                """
            return subject, body, self.email

class Account(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    account_type = db.Column(db.String(50), nullable=False)
    balance = db.Column(db.Float, nullable=False)
    institution_name = db.Column(db.String(100), nullable=False)
    transactions = db.relationship('Transaction', backref='account', lazy=True)

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    account_id = db.Column(db.Integer, db.ForeignKey('account.id'), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'))
    amount = db.Column(db.Float, nullable=False)
    date = db.Column(db.DateTime, nullable=False)
    description = db.Column(db.String(200))
    is_recurring = db.Column(db.Boolean, default=False)

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    budget_allocation = db.Column(db.Float)
    transactions = db.relationship('Transaction', backref='category', lazy=True)

class FinancialGoal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    goal_name = db.Column(db.String(200), nullable=False)
    target_amount = db.Column(db.Float, nullable=False)
    current_amount = db.Column(db.Float, default=0.0)
    target_date = db.Column(db.DateTime)

class Family(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    users = db.relationship('User', backref='family', lazy=True)

class Insight(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    type = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(255), nullable=False)
    generated_date = db.Column(db.DateTime)
