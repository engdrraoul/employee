from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import func
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'votre_clé_secrète_ici'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///employee_vote.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    name = db.Column(db.String(100), nullable=False)
    initials = db.Column(db.String(10))
    is_admin = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_initials(self):
        names = self.name.split()
        return ''.join(name[0].upper() for name in names)[:2]

class VotingSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    start_date = db.Column(db.DateTime, default=datetime.utcnow)
    end_date = db.Column(db.DateTime, nullable=False)
    votes = db.relationship('Vote', backref='session', lazy=True)

    def __repr__(self):
        return f'<VotingSession {self.id}: {self.start_date} - {self.end_date}>'

class Vote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.Integer, db.ForeignKey('voting_session.id'), nullable=False)
    voter_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    nominee_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    vote_count = db.Column(db.Integer, default=0)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    voter = db.relationship('User', foreign_keys=[voter_id], backref='votes_cast')
    nominee = db.relationship('User', foreign_keys=[nominee_id], backref='votes_received')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        role = request.form.get('role', '')

        user = User.query.filter_by(email=email).first()
        
        if not user or not user.check_password(password):
            flash('Email ou mot de passe incorrect.', 'error')
            return redirect(url_for('login'))

        if role == 'admin' and not user.is_admin:
            flash('Vous n\'avez pas les droits administrateur.', 'error')
            return redirect(url_for('login'))
        elif role == 'employee' and user.is_admin:
            flash('Veuillez vous connecter en tant qu\'administrateur.', 'error')
            return redirect(url_for('login'))

        login_user(user)
        flash('Connexion réussie!', 'success')
        
        if user.is_admin:
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('dashboard'))
    
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    # Vérifier s'il n'existe aucun administrateur
    admin_exists = User.query.filter_by(is_admin=True).first()

    if request.method == 'POST':
        email = request.form['email']
        name = request.form['name']
        password = request.form['password']

        # Vérifier si l'email est valide (termine par @2cconseil.com)
        if not email.endswith('@2cconseil.com'):
            flash('Seules les adresses email @2cconseil.com sont autorisées', 'error')
            return redirect(url_for('signup'))

        # Vérifier si l'utilisateur existe déjà
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Un utilisateur avec cet email existe déjà', 'error')
            return redirect(url_for('signup'))

        # Créer un nouvel utilisateur
        new_user = User(email=email, name=name)
        new_user.set_password(password)
        
        # Générer automatiquement les initiales
        new_user.initials = new_user.get_initials()

        # Si aucun admin n'existe, créer un compte admin
        if not admin_exists:
            new_user.is_admin = True
            flash('Premier compte créé avec les droits administrateur', 'success')
        
        # Ajouter l'utilisateur à la base de données
        db.session.add(new_user)
        db.session.commit()

        flash('Compte créé avec succès', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))
    
    active_session = VotingSession.query.order_by(VotingSession.start_date.desc()).first()
    
    nominations = []
    if active_session:
        nominations = Vote.query.filter_by(session_id=active_session.id)\
            .with_entities(Vote.nominee_id, func.count(Vote.id).label('vote_count'))\
            .group_by(Vote.nominee_id)\
            .all()
        
        nominations = [{'nominee': User.query.get(n.nominee_id), 'vote_count': n.vote_count} 
                      for n in nominations]
    
    votes_received = Vote.query.filter_by(nominee_id=current_user.id).count()
    votes_cast = Vote.query.filter_by(voter_id=current_user.id).count()
    votes_remaining = 3 - votes_cast if active_session else 0
    
    vote_history = Vote.query.filter_by(voter_id=current_user.id)\
        .order_by(Vote.timestamp.desc())\
        .limit(5)\
        .all()
    
    victories = 0
    past_sessions = VotingSession.query.filter(VotingSession.end_date < datetime.utcnow())\
        .order_by(VotingSession.end_date.desc())\
        .all()
    
    winners = []
    for session in past_sessions:
        winner = Vote.query.filter_by(session_id=session.id)\
            .with_entities(Vote.nominee_id, func.count(Vote.id).label('votes'))\
            .group_by(Vote.nominee_id)\
            .order_by(func.count(Vote.id).desc())\
            .first()
        
        if winner:
            winners.append({
                'session': session,
                'user': User.query.get(winner.nominee_id),
                'votes': winner.votes
            })
            if winner.nominee_id == current_user.id:
                victories += 1
    
    return render_template('dashboard.html',
                         active_session=active_session,
                         nominations=nominations,
                         votes_received=votes_received,
                         votes_remaining=votes_remaining,
                         victories=victories,
                         vote_history=vote_history,
                         winners=winners)

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_authenticated:
        flash('Veuillez vous connecter', 'danger')
        return redirect(url_for('login'))
    
    if not current_user.is_admin:
        flash('Accès non autorisé', 'danger')
        return redirect(url_for('dashboard'))
    
    active_session = VotingSession.query.order_by(VotingSession.start_date.desc()).first()
    
    nominations = []
    if active_session:
        nominations = Vote.query.filter_by(session_id=active_session.id)\
            .with_entities(Vote.nominee_id, func.count(Vote.id).label('vote_count'))\
            .group_by(Vote.nominee_id)\
            .all()
        
        nominations = [{'nominee': User.query.get(n.nominee_id), 'vote_count': n.vote_count} 
                      for n in nominations]
    
    past_sessions = VotingSession.query.filter(VotingSession.end_date < datetime.utcnow())\
        .order_by(VotingSession.end_date.desc())\
        .all()
    
    winners = []
    for session in past_sessions:
        winner = Vote.query.filter_by(session_id=session.id)\
            .with_entities(Vote.nominee_id, func.count(Vote.id).label('votes'))\
            .group_by(Vote.nominee_id)\
            .order_by(func.count(Vote.id).desc())\
            .first()
        
        if winner:
            winners.append({
                'session': session,
                'user': User.query.get(winner.nominee_id),
                'votes': winner.votes
            })
    
    return render_template('admin_dashboard.html', 
                          active_session=active_session,
                          nominations=nominations,
                          winners=winners)

@app.route('/admin/users')
@login_required
def admin_users():
    if not current_user.is_admin:
        flash('Accès non autorisé', 'danger')
        return redirect(url_for('dashboard'))
    
    users = User.query.all()
    return render_template('admin_users.html', users=users)

@app.route('/create_admin')
def create_admin():
    # Supprimer l'admin existant s'il existe
    existing_admin = User.query.filter_by(email='hmbegham@2cconseil.com').first()
    if existing_admin:
        # Supprimer les votes associés
        Vote.query.filter((Vote.voter_id == existing_admin.id) | (Vote.nominee_id == existing_admin.id)).delete()
        
        # Supprimer l'utilisateur
        db.session.delete(existing_admin)
        db.session.commit()
        
        flash('Compte administrateur précédent supprimé', 'success')
    
    return redirect(url_for('login'))

@app.route('/admin/users/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if not current_user.is_admin:
        flash('Accès non autorisé', 'danger')
        return redirect(url_for('dashboard'))
    
    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        user.name = request.form['name']
        user.email = request.form['email']
        user.is_admin = 'is_admin' in request.form
        
        # Régénérer les initiales
        user.initials = user.get_initials()
        
        db.session.commit()
        flash('Utilisateur mis à jour avec succès', 'success')
        return redirect(url_for('admin_users'))
    
    return render_template('edit_user.html', user=user)

@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        flash('Accès non autorisé', 'danger')
        return redirect(url_for('dashboard'))
    
    user = User.query.get_or_404(user_id)
    
    # Supprimer les votes associés
    Vote.query.filter((Vote.voter_id == user_id) | (Vote.nominee_id == user_id)).delete()
    
    db.session.delete(user)
    db.session.commit()
    
    flash('Utilisateur supprimé avec succès', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/users/toggle_admin/<int:user_id>', methods=['POST'])
@login_required
def toggle_admin(user_id):
    if not current_user.is_admin:
        flash('Accès non autorisé', 'danger')
        return redirect(url_for('dashboard'))
    
    user = User.query.get_or_404(user_id)
    user.is_admin = not user.is_admin
    
    db.session.commit()
    
    action = 'administrateur' if user.is_admin else 'utilisateur standard'
    flash(f'Statut de {user.name} modifié en {action}', 'success')
    return redirect(url_for('admin_users'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        # Mettre à jour le nom
        new_name = request.form['name']
        current_user.name = new_name
        
        # Régénérer les initiales
        current_user.initials = current_user.get_initials()

        # Mettre à jour le mot de passe si un nouveau mot de passe est fourni
        new_password = request.form['password']
        if new_password:
            current_user.set_password(new_password)

        db.session.commit()
        flash('Profil mis à jour avec succès', 'success')
        return redirect(url_for('profile'))

    return render_template('profile.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        db.drop_all()
        db.create_all()
    app.run(debug=True)
