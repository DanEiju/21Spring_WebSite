from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from flask_login import current_user
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from flaskblog.models import User


class RegistrationForm(FlaskForm):
    username = StringField('ユーザーネーム',
                           validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('メールアドレス',
                        validators=[DataRequired(), Email()])
    password = PasswordField('パスワード', validators=[DataRequired()])
    confirm_password = PasswordField('パスワードの確認',
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('新規登録')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('このユーザーネームは既に使われています。')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('このメールアドレスは既に使われています。')


class LoginForm(FlaskForm):
    email = StringField('メールアドレス',
                        validators=[DataRequired(), Email()])
    password = PasswordField('パスワード', validators=[DataRequired()])
    remember = BooleanField('パスワードを保存')
    submit = SubmitField('ログイン')


class UpdateAccountForm(FlaskForm):
    username = StringField('ユーザーネーム',
                           validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('メールアドレス',
                        validators=[DataRequired(), Email()])
    picture = FileField('プロフィール画像をアップデート', validators=[FileAllowed(['jpg', 'png'])])
    submit = SubmitField('アップデート')

    def validate_username(self, username):
        if username.data != current_user.username:
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError('このユーザーネームは既に使われています。')

    def validate_email(self, email):
        if email.data != current_user.email:
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError('このメールアドレスは既に使われています。')


class PostForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    content = TextAreaField('Content', validators=[DataRequired()])
    submit = SubmitField('Post')


class RequestResetForm(FlaskForm):
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is None:
            raise ValidationError('There is no account with that email. You must register first.')


class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')
