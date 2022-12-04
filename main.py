from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps




app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)



# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# CONFIGURE TABLES
class User(UserMixin, db.Model):
    __tablename__ = "users_table"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    email = db.Column(db.String, unique=True, nullable=False)
    password = db.Column(db.String, nullable=False)

    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")


class BlogPost(db.Model):
    __tablename__ = "posts_table"
    id = db.Column(db.Integer, primary_key=True)

    author_id = db.Column(db.Integer, ForeignKey("users_table.id"))
    author = relationship("User", back_populates="posts")

    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    comments = relationship("Comment", back_populates="parent_post")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)

    post_id = db.Column(db.Integer, db.ForeignKey("posts_table.id"))
    parent_post = relationship("BlogPost", back_populates="comments")

    author_id = db.Column(db.Integer, ForeignKey("users_table.id"))
    comment_author = relationship("User", back_populates="comments")


# with app.app_context():
#     db.create_all()


# SET LOGIN MANAGER
login_manager = LoginManager()
login_manager.init_app(app)


# ADMIN SETTINGS
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.id != 1:
            return abort(403, description="Resource not found")
        return f(*args, **kwargs)
    return decorated_function


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# SET ROUTES
@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=["GET", "POST"])
def register():
    error = None
    register_form = RegisterForm()
    if register_form.validate_on_submit():
        passed_email = register_form.email
        user = User.query.filter_by(email=passed_email.data).first()
        if user:
            error = "User already exists."
        else:
            new_user = User(name=register_form.name.data,
                            email=register_form.email.data,
                            password=generate_password_hash(register_form.password.data,
                                                            method='pbkdf2:sha256', salt_length=8))
            db.session.add(new_user)
            db.session.commit()
            flash("Congratulation, your account has been successfully created!")
            login_user(new_user)

            return redirect(url_for("get_all_posts"))

    return render_template("register.html", form=register_form, error=error)


@app.route('/login', methods=["GET", "POST"])
def login():
    error = None
    login_form = LoginForm()
    if login_form.validate_on_submit():
        passed_email = login_form.email.data
        user = User.query.filter_by(email=passed_email).first()
        if not user:
            error = "The email or password you entered is incorrect. Please type again."
        else:
            if not check_password_hash(user.password, login_form.password.data):
                error = "The email or password you entered is incorrect. Please type again."
            else:
                login_user(user)
                flash("You logged in successfully!")
                return redirect(url_for("get_all_posts"))

    return render_template("login.html", form=login_form, error=error)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    error = None
    comments = Comment.query.all()
    comment_form = CommentForm()
    requested_post = BlogPost.query.get(post_id)
    if comment_form.validate_on_submit():
        if current_user.is_authenticated:
            new_comment = Comment(text=comment_form.comment.data,
                                  post_id=post_id,
                                  author_id=current_user.id)
            db.session.add(new_comment)
            db.session.commit()
            return redirect(url_for("show_post", post_id=post_id))
        else:
            error = "Only logged in users can add comments. "

    return render_template("post.html", post=requested_post, form=comment_form, comments=comments, error=error)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            date=date.today().strftime("%B %d, %Y"),
            author_id=current_user.id
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


# if __name__ == "__main__":
#     app.run()
