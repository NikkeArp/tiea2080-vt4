#!venv/bin/python
# -*- coding: utf-8 -*-

#Python modules
import hashlib
import sqlite3
from ast import literal_eval
from functools import wraps

#Flask modules
from flask import Flask, render_template, url_for, redirect, request, session, g
from flask_wtf import FlaskForm 
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, PasswordField, SelectField, RadioField
from wtforms.validators import DataRequired, Optional, ValidationError, StopValidation

#my modules
from mylogging import logging, log_exc

#application configurations
app = Flask(__name__)
app.config['SECRET_KEY'] = '0e55da7d-00f4-4e47-b14e-3e6defa0660d'
csrf = CSRFProtect()
csrf.init_app(app)


#--------DECORATORS---------#
def authorized(func):
    @wraps(func)
    def decorated(*args, **kwargs):
        if not session['logged_in']:
            return redirect(url_for('login'))
        return func(*args, **kwargs)
    return decorated
#---------------------------#

#------------------------DATABASE------------------------#
DATABASE = 'hidden/tietokanta' #path to database

def get_db():
    """
    """

    def make_dicts(cursor, row):
        """
        """

        return dict((cursor.description[idx][0], value)
            for idx, value in enumerate(row))

    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    db.execute('PRAGMA foreign_keys=ON')
    db.row_factory = make_dicts
    return db

@app.teardown_appcontext
def close_connection(exception):
    """
    """

    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def query_db(query, args=(), one=False):
    """
    """

    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv
#--------------------------------------------------#


#----------------------ROUTES----------------------#
@app.route('/')
def index():
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login route"""

    def validate_username(form, field):
        """
        Validates username
        """

        team = query_db('SELECT * FROM joukkueet WHERE nimi=? COLLATE NOCASE',
                       [field.data], one=True)
        if team is None:
            raise StopValidation(u'Väärä käyttäjä')
        series = query_db('SELECT * FROM sarjat WHERE id=?',
                        [team.get('sarja')], one=True)
        race = query_db('SELECT * FROM kilpailut WHERE id=?',
                        [series.get('kilpailu')], one=True)
        if race is None or form.race.data != race['nimi']:
            raise StopValidation(u'Väärä kilpailu')
        
    def validate_passw(form, field):
        """
        Validates password
        """

        try:
            team = query_db('SELECT * FROM joukkueet WHERE nimi=? COLLATE NOCASE',
                        [form.username.data], one=True)
            pw_hasher = hashlib.sha512()

            pw_hasher.update(unicode(team['id']) + field.data)
            if pw_hasher.hexdigest() != team['salasana']:
                raise ValidationError(u'Väärä salasana')
        except:
            raise ValidationError(u'Väärä salasana')
        
    class LoginForm(FlaskForm):
        """Form class for logging in"""

        #username stringfield
        username = StringField(u'Tunnus', validators=[DataRequired(),
                        validate_username],
                        filters=[lambda name: name.strip() if name else name],
                        description=u'Joukkueen nimi')
        #password stringfield
        password = PasswordField(u'Salasana', validators=[DataRequired(),
                        validate_passw])
        #race selectionfield
        races = query_db('SELECT * FROM kilpailut')
        race = SelectField(u'Kilpailu', validators=[DataRequired()],
                           choices=map(lambda x: (x['nimi'], x['nimi']), races))
    
    login_form = LoginForm() # Instance of LoginForm

    #Validate form
    if login_form.validate_on_submit():
        team = query_db('SELECT * FROM joukkueet WHERE nimi=? COLLATE NOCASE',
                        [login_form.username.data], one=True)
        race = query_db('SELECT * FROM kilpailut WHERE nimi=?',
                        [login_form.race.data], one=True)
        session['user'] = team['nimi']
        session['logged_in'] = True
        session['race'] = {'name': race['nimi'], 'id': race['id']}
        return redirect(url_for('home')) #redirect route for users home
    else: #Validation failed, render login-page again
        return render_template('login.html', login_form=login_form)


@app.route('/logout')
@authorized
def logout():
    """
    Logout route.
    Clears session variables.
    """

    if 'race' in session: session['race'] = None
    if 'user' in session: session['user'] = None
    if 'logged_in' in session: session['logged_in'] = False
    return redirect(url_for('index'))


@app.route('/home')
@authorized
def home():
    try:
        race = session['race']['name']
        team = session['user']
    except:
        pass
    return render_template('home.html', race=race, team=team)


@app.route('/edit', methods=['GET', 'POST'])
def edit():
    class TeamForm(FlaskForm):
        """Form for editing users team"""

        name = StringField(u'Nimi', validators=[DataRequired()])
        races = query_db('SELECT * FROM sarjat WHERE kilpailu=?', [session['race']['id']])
        series = RadioField(u'Sarja', validators=[DataRequired()], 
                            choices=map(lambda x: (x['nimi'], x['nimi']), races))
        mem1 = StringField(u'Jäsen 1')
        mem2 = StringField(u'Jäsen 2')
        mem3 = StringField(u'Jäsen 3')
        mem4 = StringField(u'Jäsen 4')
        mem5 = StringField(u'Jäsen 5')

    team_form = TeamForm()
    return render_template('team.html', team_form=team_form,
                            team=session['user'], race=session['race']['name'])


@app.route('/teams')
def teams():
    series = query_db('SELECT * FROM sarjat WHERE kilpailu=?',
        [session['race']['id']])
    teams = map(lambda x: {
        'name': x['nimi'], 
        'series': x['sarja'],
        'members': map(lambda y: y.decode('utf-8'),
                        sorted(literal_eval(x['jasenet'])))
    }, query_db('SELECT * FROM joukkueet'))

    race_data = []
    for serie in series:
        race_data.append({
            'name': serie['nimi'],
            'teams' : sorted(filter(lambda x: x['series'] == serie['id'], teams),
                        key=lambda x: x['name']) 
        })
    return render_template('teams.html', team=session['user'],
        race=session['race']['name'],
        race_data=sorted(race_data, key=lambda x: x['name']))


if __name__ == '__main__':
    app.run(debug=True)