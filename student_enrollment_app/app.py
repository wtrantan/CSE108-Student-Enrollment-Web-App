from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_admin import Admin, AdminIndexView, expose
from flask_admin.contrib.sqla import ModelView
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, SubmitField
from wtforms.validators import DataRequired, Email, Length, Optional
from wtforms.validators import Email

email = StringField('Email', validators=[DataRequired(), Email()])

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
    
    # Modified relationships with cascade options
    courses_teaching = db.relationship('Course', backref='teacher', lazy=True, 
                                      cascade="all, delete-orphan")
    enrollments = db.relationship('Enrollment', backref='student', lazy=True,
                                 cascade="all, delete-orphan", 
                                 primaryjoin="User.id==Enrollment.student_id")
    
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
    column_list = ['id', 'name', 'description', 'capacity', 'teacher_id', 'created_at']
    form_columns = ['name', 'description', 'capacity', 'teacher_id']
    
    def on_model_change(self, form, model, is_created):
        # This ensures the teacher relationship is properly set
        # The form automatically handles the relationship
        pass
    
# Fix for the UserAdminView class

class UserAdminView(AdminModelView):
    column_list = ['id', 'name', 'email', 'role_id', 'created_at']
    column_exclude_list = ['password']  # Exclude password from the list of displayed columns
    form_columns = ['name', 'email', 'password', 'role_id']  # Changed role_id to role
    
    # Create choices for the role field
    form_args = {
        'role': {
            'label': 'Role'
        }
    }
    
    # Ensure that passwords are hashed when changed or set
    def on_model_change(self, form, model, is_created):
        # Hash password only if it's been updated or provided during creation
        if form.password.data:
            model.password = generate_password_hash(form.password.data)
        elif not is_created:
            # If the model is not created (it's an edit), retain the original password if none is provided
            original_model = self.session.query(User).get(model.id)
            if original_model:
                model.password = original_model.password

    def is_accessible(self):
        # Admin can access
        return current_user.is_authenticated and current_user.role.name == 'admin'

    def inaccessible_callback(self, name, **kwargs):
        # Redirect to login if the user is not authorized to access the admin panel
        flash('You do not have permission to access the admin panel.', 'danger')
        return redirect(url_for('login'))

# Add these imports at the top of your file


class EnrollmentAdminView(AdminModelView):
    column_list = ['id', 'student_id', 'course_id', 'grade', 'enrollment_date']
    form_columns = ['student_id', 'course_id', 'grade']
    
    # Format the grade as a float with 1 decimal place
    column_formatters = {
        'grade': lambda v, c, m, p: f"{m.grade:.1f}" if m.grade is not None else "Not graded"
    }
    
    # Use column_filters with the actual column names
    column_filters = ['student_id', 'course_id', 'grade']
    
    def handle_view_exception(self, exc):
        if isinstance(exc, ValueError):
            flash(str(exc), 'error')
            return True  # Indicate that we've handled the exception
        return super(EnrollmentAdminView, self).handle_view_exception(exc)
    
    def create_form(self):
        # Create the form first without parameters
        form = super().create_form()
        
        # Get all students and courses for the dropdowns
        students = User.query.join(Role).filter(Role.name == 'student').all()
        courses = Course.query.all()
        
        # Create choices for the select fields
        student_choices = [(s.id, s.name) for s in students]
        course_choices = [(c.id, c.name) for c in courses]
        
        # Update the form fields with choices
        form.student_id.choices = student_choices
        form.course_id.choices = course_choices
        
        return form
    
    def edit_form(self, obj):
        form = super().edit_form(obj)
        
        # Get all students and courses for the dropdowns
        students = User.query.join(Role).filter(Role.name == 'student').all()
        courses = Course.query.all()
        
        # Create choices for the select fields
        student_choices = [(s.id, s.name) for s in students]
        course_choices = [(c.id, c.name) for c in courses]
        
        # Update the form fields
        form.student_id.choices = student_choices
        form.course_id.choices = course_choices
        
        return form
    
    def validate_form(self, form):
        # Skip validation if form doesn't have student_id (i.e., it's a DeleteForm)
        if not hasattr(form, 'student_id') or not hasattr(form, 'course_id'):
            return True  # allow delete

        student_id = form.student_id.data
        course_id = form.course_id.data

        # Check if student exists
        student = User.query.get(student_id)
        if not student:
            flash('Student does not exist. Please create the user first.', 'danger')
            return False

        # Check if already enrolled
        existing = Enrollment.query.filter_by(student_id=student_id, course_id=course_id).first()
        if existing:
            flash('Student is already enrolled in this course.', 'warning')
            return False

        return True
    
    def on_model_change(self, form, model, is_created):
        # Clear any potential stale session data
        self.session.expire_all()
        self.session.commit()
        
        try:
            # Validate the grade (if provided)
            if model.grade is not None and (model.grade < 0 or model.grade > 100):
                raise ValueError('Grade must be between 0 and 100')
            
            # Check if enrollment already exists only when creating a new one
            if is_created:
                student_id = model.student_id
                course_id = model.course_id
                
                # Double-check student exists
                student = User.query.get(student_id)
                if not student:
                    raise ValueError(f'Student with ID {student_id} does not exist')
                
                # Double-check course exists
                course = Course.query.get(course_id)
                if not course:
                    raise ValueError(f'Course with ID {course_id} does not exist')
                
                # Use raw SQL to check for existing enrollment to avoid session issues
                sql = "SELECT id FROM enrollment WHERE student_id = :sid AND course_id = :cid"
                result = db.session.execute(sql, {"sid": student_id, "cid": course_id}).first()
                
                if result:
                    enrollment_id = result[0]
                    raise ValueError(f'Student "{student.name}" is already enrolled in course "{course.name}" (Enrollment ID: {enrollment_id})')
                
                # Check if the course has reached capacity
                sql_count = "SELECT COUNT(*) FROM enrollment WHERE course_id = :cid"
                enrolled_count = db.session.execute(sql_count, {"cid": course_id}).scalar()
                
                if enrolled_count >= course.capacity:
                    raise ValueError(f'The course "{course.name}" has reached its maximum capacity of {course.capacity}')
        
        except ValueError as e:
            # Re-raise the error so it can be caught by handle_view_exception
            raise ValueError(str(e))
        except Exception as e:
            # Add a generic exception handler to catch other issues
            import traceback
            error_details = traceback.format_exc()
            print(f"Unexpected error: {error_details}")
            raise ValueError(f'Error processing enrollment: {str(e)}')
    
    # Display student and course names in the list view
    def _list_entry(self, context, model, name):
        if name == 'student_id':
            student = User.query.get(model.student_id)
            if student:
                return student.name
            else:
                # Mark this enrollment for deletion since it has an invalid student
                self._mark_invalid_enrollment(model.id)
                return f"Invalid ID: {model.student_id}"
        elif name == 'course_id':
            course = Course.query.get(model.course_id)
            if course:
                return course.name
            else:
                # Mark this enrollment for deletion since it has an invalid course
                self._mark_invalid_enrollment(model.id)
                return f"Invalid ID: {model.course_id}"
        return super()._list_entry(context, model, name)
    
    def _mark_invalid_enrollment(self, enrollment_id):
        # Set a flag to delete this enrollment
        if not hasattr(self, '_invalid_enrollments'):
            self._invalid_enrollments = set()
        self._invalid_enrollments.add(enrollment_id)
    
    # Clean up invalid enrollments when the list view is rendered
    def render(self, template, **kwargs):
        # Clean up invalid enrollments before rendering
        self._cleanup_invalid_enrollments()
        return super().render(template, **kwargs)
    
    def _cleanup_invalid_enrollments(self):
        if hasattr(self, '_invalid_enrollments') and self._invalid_enrollments:
            try:
                for enrollment_id in self._invalid_enrollments:
                    enrollment = Enrollment.query.get(enrollment_id)
                    if enrollment:
                        # Log the deletion
                        print(f"Deleting invalid enrollment: ID={enrollment_id}, Student ID={enrollment.student_id}, Course ID={enrollment.course_id}")
                        db.session.delete(enrollment)
                
                db.session.commit()
                flash(f"Cleaned up {len(self._invalid_enrollments)} invalid enrollment(s)", 'warning')
                # Clear the set after cleanup
                self._invalid_enrollments.clear()
            except Exception as e:
                db.session.rollback()
                print(f"Error cleaning up invalid enrollments: {str(e)}")
            
# Absolute minimum implementation
class BasicUserAdmin(ModelView):
    # Only show name and email
    column_list = ['name', 'email']
    form_columns = ['name', 'email', 'password', 'role_id']
    
# Register admin views
admin = Admin(app, name='Enrollment Admin', template_mode='bootstrap4', index_view=MyAdminIndexView())
admin.add_view(UserAdminView(User, db.session))
admin.add_view(CourseAdminView(Course, db.session))
admin.add_view(EnrollmentAdminView(Enrollment, db.session))


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

@app.route('/student/unenroll/<int:course_id>', methods=['POST'])
@login_required
@role_required('student')
def unenroll_course(course_id):
    # Find the enrollment
    enrollment = Enrollment.query.filter_by(
        student_id=current_user.id, 
        course_id=course_id
    ).first_or_404()
    
    try:
        # Get course name for the flash message
        course_name = enrollment.course.name
        
        # Delete the enrollment
        db.session.delete(enrollment)
        db.session.commit()
        
        flash(f'You have successfully unenrolled from {course_name}.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error while unenrolling: {str(e)}', 'danger')
    
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

#User management form
class UserForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(max=100)])
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=100)])
    password = PasswordField('Password', validators=[Optional(), Length(min=6)])
    role_id = SelectField('Role', coerce=int, validators=[DataRequired()])
    submit = SubmitField('Save')

# Routes for custom user management
# Routes for custom user management
@app.route('/admin/custom_users')
@login_required
@role_required('admin')
def admin_users():
    # Get query parameters
    search = request.args.get('search', '')
    role_id = request.args.get('role', '')
    sort_field = request.args.get('sort', 'id')
    sort_direction = request.args.get('direction', 'asc')
    
    # Start with base query
    query = User.query
    
    # Apply search filter if provided
    if search:
        query = query.filter(
            db.or_(
                User.name.ilike(f'%{search}%'),
                User.email.ilike(f'%{search}%')
            )
        )
    
    # Apply role filter if provided
    if role_id and role_id.isdigit():
        query = query.filter(User.role_id == int(role_id))
    
    # Apply sorting
    if sort_field == 'name':
        if sort_direction == 'desc':
            query = query.order_by(User.name.desc())
        else:
            query = query.order_by(User.name)
    elif sort_field == 'email':
        if sort_direction == 'desc':
            query = query.order_by(User.email.desc())
        else:
            query = query.order_by(User.email)
    elif sort_field == 'created_at':
        if sort_direction == 'desc':
            query = query.order_by(User.created_at.desc())
        else:
            query = query.order_by(User.created_at)
    else:  # Default sort by ID
        if sort_direction == 'desc':
            query = query.order_by(User.id.desc())
        else:
            query = query.order_by(User.id)
    
    # Execute query and get users
    users = query.all()
    
    # Get all roles for the filter dropdown
    roles = Role.query.all()
    
    return render_template(
        'admin/users.html', 
        users=users,
        roles=roles,
        search=search,
        role_id=role_id,
        sort_field=sort_field,
        sort_direction=sort_direction
    )

# Keep the same function names but change the routes
@app.route('/admin/custom_users/create', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def admin_create_user():
    form = UserForm()
    
    # Populate role choices
    form.role_id.choices = [(r.id, r.name) for r in Role.query.all()]
    
    if form.validate_on_submit():
        # Check if email already exists
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash('Email already registered.', 'danger')
            return render_template('admin/user_form.html', form=form, is_edit=False)
        
        # Create new user
        new_user = User(
            name=form.name.data,
            email=form.email.data,
            password=generate_password_hash(form.password.data),
            role_id=form.role_id.data
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('User created successfully!', 'success')
        return redirect(url_for('admin_users'))
    
    return render_template('admin/user_form.html', form=form, is_edit=False)

@app.route('/admin/custom_users/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def admin_edit_user(user_id):
    user = User.query.get_or_404(user_id)
    form = UserForm(obj=user)
    
    # Populate role choices
    form.role_id.choices = [(r.id, r.name) for r in Role.query.all()]
    
    # For GET requests, don't show the password
    if request.method == 'GET':
        form.password.data = ''
    
    if form.validate_on_submit():
        # Update user details
        user.name = form.name.data
        user.email = form.email.data
        user.role_id = form.role_id.data
        
        # Only update password if provided
        if form.password.data:
            user.password = generate_password_hash(form.password.data)
        
        db.session.commit()
        
        flash('User updated successfully!', 'success')
        return redirect(url_for('admin_users'))
    
    return render_template('admin/user_form.html', form=form, is_edit=True, user=user)

@app.route('/admin/custom_users/delete/<int:user_id>', methods=['POST'])
@login_required
@role_required('admin')
def admin_delete_user(user_id):
    user = User.query.get_or_404(user_id)
    
    # Prevent deletion of the current user
    if user.id == current_user.id:
        flash('You cannot delete your own account.', 'danger')
        return redirect(url_for('admin_users'))
    
    # Start a transaction
    try:
        # Get user's role for later checks
        user_role_name = user.role.name if user.role else None
        
        # Handle enrollments - both as student and related to courses taught
        try:
            # Delete enrollments where user is a student
            student_enrollments = Enrollment.query.filter_by(student_id=user.id).all()
            for enrollment in student_enrollments:
                db.session.delete(enrollment)
            db.session.flush()  # Flush changes but don't commit yet
            
            # If teacher, handle course enrollments
            if user_role_name == 'teacher':
                # Get all courses taught by this teacher
                teacher_courses = Course.query.filter_by(teacher_id=user.id).all()
                for course in teacher_courses:
                    # Set teacher_id to NULL
                    course.teacher_id = None
                # Delete course and related enrollments
                db.session.flush()  # Flush changes but don't commit yet
        except Exception as e:
            db.session.rollback()
            flash(f'Error handling user relationships: {str(e)}', 'danger')
            return redirect(url_for('admin_users'))
        
        #Delete the user
        try:
            db.session.delete(user)
            db.session.commit()
            flash('User deleted successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error deleting user: {str(e)}', 'danger')
            return redirect(url_for('admin_users'))
            
    except Exception as e:
        db.session.rollback()
        flash(f'Unexpected error: {str(e)}', 'danger')
    
    return redirect(url_for('admin_users'))




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