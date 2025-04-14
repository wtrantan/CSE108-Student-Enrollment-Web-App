from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_admin import Admin, AdminIndexView, expose
from flask_admin.contrib.sqla import ModelView
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime
from flask_admin.form import Select2Widget
from wtforms.fields import SelectField


# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///enrollment.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database
db = SQLAlchemy(app)

# Define models
class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), unique=True, nullable=False)
    users = db.relationship('User', backref='role', lazy=True)
    
    def __repr__(self):
        return f'<Role {self.name}>'

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    
    # Relationships
    courses_teaching = db.relationship('Course', backref='teacher', lazy=True)
    enrollments = db.relationship('Enrollment', backref='student', lazy=True)
    
    def __repr__(self):
        return f'<User {self.name}>'

class Course(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    capacity = db.Column(db.Integer, default=30)
    teacher_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.now)
    
    # Relationships
    enrollments = db.relationship('Enrollment', backref='course', lazy=True, cascade="all, delete-orphan")
    
    def __repr__(self):
        return f'<Course {self.name}>'
    
    def get_enrollment_count(self):
        return Enrollment.query.filter_by(course_id=self.id).count()

class Enrollment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'), nullable=False)
    grade = db.Column(db.Float, nullable=True)
    enrollment_date = db.Column(db.DateTime, default=datetime.now)
    
    def __repr__(self):
        return f'<Enrollment {self.student_id} in {self.course_id}>'

# Configure login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Role-based access control
def role_required(role_name):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('login'))
            
            if not current_user.role or current_user.role.name != role_name:
                flash('You do not have permission to access this page.', 'danger')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Admin dashboard statistics
def count_users():
    return User.query.count()

def count_courses():
    return Course.query.count()

def count_enrollments():
    return Enrollment.query.count()

# Custom admin index view
class MyAdminIndexView(AdminIndexView):
    @expose('/')
    def index(self):
        # Add statistics to the admin home page
        self._template_args['admin_view'] = self
        self.count_users = count_users
        self.count_courses = count_courses
        self.count_enrollments = count_enrollments
        return super(MyAdminIndexView, self).index()

    def is_accessible(self):
        return current_user.is_authenticated and current_user.role.name == 'admin'

    def inaccessible_callback(self, name, **kwargs):
        flash('You do not have permission to access the admin panel.', 'danger')
        return redirect(url_for('login'))

# Admin views
class AdminModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.role.name == 'admin'

    def inaccessible_callback(self, name, **kwargs):
        flash('You do not have permission to access the admin panel.', 'danger')
        return redirect(url_for('login'))

class CourseAdminView(AdminModelView):
    form_extra_fields = {
        'teacher_id': SelectField('Teacher', coerce=int, widget=Select2Widget())
    }

    def create_form(self, obj=None):
        form = super().create_form(obj)
        form.teacher_id.choices = [(u.id, u.name) for u in User.query.join(Role).filter(Role.name == 'teacher').all()]
        return form

    def edit_form(self, obj=None):
        form = super().edit_form(obj)
        form.teacher_id.choices = [(u.id, u.name) for u in User.query.join(Role).filter(Role.name == 'teacher').all()]
        return form
# Register admin views
admin = Admin(app, name='Enrollment Admin', template_mode='bootstrap3', index_view=MyAdminIndexView())
admin.add_view(AdminModelView(User, db.session))
admin.add_view(CourseAdminView(Course, db.session))
admin.add_view(AdminModelView(Enrollment, db.session))
admin.add_view(AdminModelView(Role, db.session))

# Routes
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Login failed. Please check your email and password.', 'danger')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        name = request.form.get('name')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        role_id = request.form.get('role_id')
        
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('register'))
        
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already registered.', 'danger')
            return redirect(url_for('register'))
        
        hashed_password = generate_password_hash(password)
        
        new_user = User(
            email=email,
            name=name,
            password=hashed_password,
            role_id=role_id
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    roles = Role.query.all()
    return render_template('register.html', roles=roles)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role:
        if current_user.role.name == 'student':
            return redirect(url_for('student_dashboard'))
        elif current_user.role.name == 'teacher':
            return redirect(url_for('teacher_dashboard'))
        elif current_user.role.name == 'admin':
            return redirect(url_for('admin.index'))
    
    flash('Your account has no assigned role. Please contact an administrator.', 'danger')
    return redirect(url_for('logout'))

# Student routes
@app.route('/student/dashboard')
@login_required
@role_required('student')
def student_dashboard():
    enrollments = Enrollment.query.filter_by(student_id=current_user.id).all()
    enrolled_courses = [enrollment.course for enrollment in enrollments]
    
    # We don't need to pass user=current_user anymore since we're using current_user directly in the template
    return render_template('student/dashboard.html', 
                           courses=enrolled_courses)

@app.route('/student/courses')
@login_required
@role_required('student')
def student_courses():
    all_courses = Course.query.all()
    enrolled_course_ids = [enrollment.course_id for enrollment in 
                          Enrollment.query.filter_by(student_id=current_user.id).all()]
    
    return render_template('student/courses.html', 
                           courses=all_courses,
                           enrolled_course_ids=enrolled_course_ids)

@app.route('/student/enroll/<int:course_id>', methods=['POST'])
@login_required
@role_required('student')
def enroll_course(course_id):
    course = Course.query.get_or_404(course_id)
    
    # Check if student is already enrolled
    existing_enrollment = Enrollment.query.filter_by(
        student_id=current_user.id, 
        course_id=course_id
    ).first()
    
    if existing_enrollment:
        flash('You are already enrolled in this course.', 'warning')
        return redirect(url_for('student_courses'))
    
    # Check if the course has reached capacity
    enrolled_count = Enrollment.query.filter_by(course_id=course_id).count()
    
    if enrolled_count >= course.capacity:
        flash('This course has reached its maximum capacity.', 'danger')
        return redirect(url_for('student_courses'))
    
    # Create new enrollment
    new_enrollment = Enrollment(
        student_id=current_user.id,
        course_id=course_id,
        grade=None,
        enrollment_date=datetime.now()
    )
    
    db.session.add(new_enrollment)
    db.session.commit()
    
    flash(f'Successfully enrolled in {course.name}!', 'success')
    return redirect(url_for('student_dashboard'))

# Teacher routes
@app.route('/teacher/dashboard')
@login_required
@role_required('teacher')
def teacher_dashboard():
    courses = Course.query.filter_by(teacher_id=current_user.id).all()
    return render_template('teacher/dashboard.html', courses=courses)

@app.route('/teacher/course/<int:course_id>')
@login_required
@role_required('teacher')
def teacher_course_detail(course_id):
    course = Course.query.get_or_404(course_id)
    
    # Ensure this teacher is teaching this course
    if course.teacher_id != current_user.id:
        flash('You do not have permission to view this course.', 'danger')
        return redirect(url_for('teacher_dashboard'))
    
    # Get all enrollments for this course
    enrollments = Enrollment.query.filter_by(course_id=course_id).all()
    
    # Get student information for each enrollment
    students = [(enrollment, User.query.get(enrollment.student_id)) 
                for enrollment in enrollments]
    
    return render_template('teacher/course_detail.html',
                           course=course,
                           students=students)

@app.route('/teacher/update_grade/<int:enrollment_id>', methods=['POST'])
@login_required
@role_required('teacher')
def update_grade(enrollment_id):
    enrollment = Enrollment.query.get_or_404(enrollment_id)
    course = Course.query.get(enrollment.course_id)
    
    # Ensure this teacher is teaching this course
    if course.teacher_id != current_user.id:
        flash('You do not have permission to update grades for this course.', 'danger')
        return redirect(url_for('teacher_dashboard'))
    
    new_grade = request.form.get('grade')
    
    # Validate grade
    try:
        new_grade = float(new_grade)
        if new_grade < 0 or new_grade > 100:
            raise ValueError
    except ValueError:
        flash('Invalid grade. Please enter a number between 0 and 100.', 'danger')
        return redirect(url_for('teacher_course_detail', course_id=course.id))
    
    enrollment.grade = new_grade
    db.session.commit()
    
    flash('Grade updated successfully!', 'success')
    return redirect(url_for('teacher_course_detail', course_id=course.id))

# Initialize the database and create default data
def initialize_database():
    with app.app_context():
        db.create_all()
        
        # Create roles if they don't exist
        roles = {
            'student': 'Regular student',
            'teacher': 'Course teacher',
            'admin': 'System administrator'
        }
        
        for role_name, description in roles.items():
            role = Role.query.filter_by(name=role_name).first()
            if not role:
                role = Role(name=role_name)
                db.session.add(role)
        
        db.session.commit()
        
        # Get the roles
        student_role = Role.query.filter_by(name='student').first()
        teacher_role = Role.query.filter_by(name='teacher').first()
        admin_role = Role.query.filter_by(name='admin').first()
        
        # Create an admin user if it doesn't exist
        admin = User.query.filter_by(email='admin@example.com').first()
        if not admin:
            admin = User(
                email='admin@example.com',
                name='Admin User',
                password=generate_password_hash('admin123'),
                role_id=admin_role.id
            )
            db.session.add(admin)
        
        # Create a teacher if it doesn't exist
        teacher = User.query.filter_by(email='teacher@example.com').first()
        if not teacher:
            teacher = User(
                email='teacher@example.com',
                name='Teacher User',
                password=generate_password_hash('teacher123'),
                role_id=teacher_role.id
            )
            db.session.add(teacher)
        
        # Create a student if it doesn't exist
        student = User.query.filter_by(email='student@example.com').first()
        if not student:
            student = User(
                email='student@example.com',
                name='Student User',
                password=generate_password_hash('student123'),
                role_id=student_role.id
            )
            db.session.add(student)
        
        db.session.commit()
        
        # Create some courses if there are none
        if Course.query.count() == 0:
            courses = [
                {
                    'name': 'Introduction to Programming',
                    'description': 'Learn the basics of programming',
                    'capacity': 30
                },
                {
                    'name': 'Web Development',
                    'description': 'Learn how to build web applications',
                    'capacity': 25
                },
                {
                    'name': 'Data Science',
                    'description': 'Introduction to data analysis and machine learning',
                    'capacity': 20
                }
            ]
            
            teacher = User.query.filter_by(email='teacher@example.com').first()
            
            for course_data in courses:
                course = Course(
                    name=course_data['name'],
                    description=course_data['description'],
                    capacity=course_data['capacity'],
                    teacher_id=teacher.id
                )
                db.session.add(course)
            
            db.session.commit()
            
        # Create a sample enrollment
        student = User.query.filter_by(email='student@example.com').first()
        course = Course.query.first()
        
        if student and course:
            enrollment = Enrollment.query.filter_by(
                student_id=student.id,
                course_id=course.id
            ).first()
            
            if not enrollment:
                enrollment = Enrollment(
                    student_id=student.id,
                    course_id=course.id,
                    grade=None,
                    enrollment_date=datetime.now()
                )
                db.session.add(enrollment)
                db.session.commit()

# Initialize database and start the app
if __name__ == '__main__':
    initialize_database()
    app.run(debug=True)