#!venv/bin/python
# -*- coding: utf-8 -*-

#Python modules
import hashlib
import sqlite3
from ast import literal_eval
from functools import wraps
from datetime import datetime

#Flask modules
from flask import (Flask, render_template, url_for,
    redirect, request, session, g, flash)
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import (StringField, PasswordField, SelectField, RadioField,
    DateTimeField, BooleanField, SubmitField, IntegerField)
from wtforms.validators import (DataRequired, Optional, ValidationError,
    StopValidation, EqualTo, NumberRange, InputRequired)

#my modules
from mylogging import logging, log_exc

#-------------------Application config------------------#
app = Flask(__name__)
app.config['SECRET_KEY'] = '\xae\xbd\x81\x14\xbd\t\x83s\x82\x1b\x11\xd6 \xb6\xa2\xd8'
csrf = CSRFProtect()
csrf.init_app(app)

#-----------------------DECORATORS----------------------#
def authorized(func):
    @wraps(func)
    def decorated(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return func(*args, **kwargs)
    return decorated

@app.before_request
def load_logged_user():
    usr_id = session.get('user_id')
    g.user = query_db('SELECT * FROM joukkueet WHERE id=?',
        [usr_id], one=True) if usr_id else None
    race_id = session.get('race_id')
    g.race = query_db('SELECT * FROM kilpailut WHERE id=?',
        [race_id], one=True) if race_id else None


#------------------------DATABASE------------------------#

def get_db():
    def make_dicts(cursor, row):
        return dict((cursor.description[idx][0], value)
            for idx, value in enumerate(row))

    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect('hidden/tietokanta')
    db.execute('PRAGMA foreign_keys=ON')
    db.row_factory = make_dicts
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def query_db(query, args=(), one=False):
    db = get_db()
    cur = db.execute(query, args)
    rv = cur.fetchall()
    db.commit()
    cur.close()
    return (rv[0] if rv else None) if one else rv

#----------------------ROUTES----------------------#
@app.route('/')
@app.route('/login', methods=['GET', 'POST'])
def login():
    def validate_race(form, field):
        series = map(lambda x: x['sarja'],
            query_db('SELECT * FROM joukkueet WHERE nimi=? COLLATE NOCASE',
                [form.username.data]))
        races = []
        for serie in series:
            race = query_db('SELECT * FROM kilpailut WHERE id=?',
                [query_db('SELECT * FROM sarjat WHERE id=?', 
                    [serie], one=True)['kilpailu']], one=True)['nimi']
            races.append(race)
        if not filter(lambda x: x == field.data, races):
            raise ValidationError(u'Väärä kilpailu')

    def validate_username(form, field):
        teams = query_db('SELECT * FROM joukkueet WHERE nimi=? COLLATE NOCASE',
            [field.data])
        if not teams: raise StopValidation(u'Väärä käyttäjä')
        
    def validate_passw(form, field):
        try:
            team = query_db('SELECT * FROM joukkueet WHERE nimi=? COLLATE NOCASE',
                [form.username.data], one=True)
            hasher = hashlib.sha512(unicode(team['id']) + field.data)
            if hasher.hexdigest() != team['salasana']:
                raise ValidationError(u'Väärä salasana')
        except:
            raise ValidationError(u'Väärä salasana')
        
    class LoginForm(FlaskForm):
        #username stringfield
        username = StringField(u'Tunnus', 
            validators=[DataRequired(), validate_username],
            filters=[lambda name: name.strip() if name else name])
        #password stringfield
        password = PasswordField(u'Salasana',
            validators=[DataRequired(), validate_passw])
        #race selectionfield
        race = SelectField(u'Kilpailu',
            validators=[DataRequired(), validate_race],
            choices=map(lambda x: (x['nimi'], x['nimi']),
                query_db('SELECT * FROM kilpailut')))
    
    form = LoginForm()
    if form.validate_on_submit():
        team = query_db('SELECT * FROM joukkueet WHERE nimi=? COLLATE NOCASE',
            [form.username.data], one=True)
        race = query_db('SELECT * FROM kilpailut WHERE nimi=?',
            [form.race.data], one=True)
        
        #Set users session variables
        session['user_id'] = team['id']
        session['logged_in'] = True
        session['race_id'] = race['id']

        #redirect route for team-page
        return redirect(url_for('teams'))

    #Validation failed, render login-page again
    return render_template('login.html', form=form)


@app.route('/logout')
@authorized
def logout():
    session.pop('race', None)
    session.pop('user', None)
    if 'logged_in' in session: session['logged_in'] = False
    return redirect(url_for('login'))


@app.route('/edit', methods=['GET', 'POST'])
@authorized
def edit():
    def validate_name(form, field):
        if field.data == g.user['nimi']: return
        series = query_db('SELECT * FROM sarjat WHERE kilpailu=?',
            [g.race['id']])
        for serie in series:
            teams = query_db('SELECT * FROM joukkueet WHERE sarja=?',
                [serie['id']])
            teams = map(lambda x: x['nimi'], query_db('''
            SELECT * FROM joukkueet WHERE sarja=?''', [serie['id']]))
        for name in teams:
            if name == field.data:
                raise ValidationError(u'Kilpailuun rekisteröidytty tällä nimellä')

    class TeamForm(FlaskForm):
        name = StringField(u'Nimi',
            validators=[DataRequired(), validate_name],
            default=g.user['nimi'])
        series = RadioField(u'Sarja', validators=[DataRequired()],
            coerce=int,
            default=g.user['sarja'],  
            choices=sorted(map(lambda x: (x['id'], x['nimi']),
                query_db('SELECT * FROM sarjat WHERE kilpailu=?',
                    [g.race['id']])),
                key=lambda y: y[1]))
        new_password = PasswordField(u'Uusi salasana')
        new_pw_again = PasswordField('Salasana uudelleen',
            validators=[EqualTo('new_password', message=u'Syöttämäsi salasanat eivät täsmää')])
        mem1 = StringField(u'Jäsen 1', validators=[DataRequired()])
        mem2 = StringField(u'Jäsen 2', validators=[DataRequired()])
        mem3 = StringField(u'Jäsen 3', validators=[Optional()])
        mem4 = StringField(u'Jäsen 4', validators=[Optional()])
        mem5 = StringField(u'Jäsen 5', validators=[Optional()])

    form = TeamForm()
    if form.validate_on_submit():
            #Update teams data
        query_db('UPDATE joukkueet SET nimi=?, sarja=?, jasenet=? WHERE id=?',
        [
            form.name.data,
            filter(lambda x: x['id'] == form.series.data,
                query_db('SELECT * FROM sarjat'))[0]['id'],
            gather_members(form),
            g.user['id']
        ])
            #Update users password
        if form.new_password.data:
            hasher = hashlib.sha512(unicode(g.user['id']) +
                form.new_password.data)
            query_db('UPDATE joukkueet SET salasana=? WHERE id=?',
            [hasher.hexdigest(), g.user['id']])

        #Update name to global variable for rendering
        g.user['nimi'] = form.name.data
    else: 
        set_team_defs(form, map(lambda x: x.decode('utf-8'),
            literal_eval(g.user['jasenet'])))
    cps = sorted(query_db('SELECT * FROM tupa WHERE joukkue=?',
        [g.user['id']]), key=lambda x: datetime.strptime(x['aika'],
            '%Y-%m-%d %H:%M:%S')) 
    cps = filter(lambda x: x['rasti'] != 0, cps)
    cps = map(lambda x: {
        'name':  query_db('SELECT * FROM rastit WHERE id=?',
            [x['rasti']], one=True)['koodi'],
        'time': x['aika']
        }, cps)
        #Render team edit template
    return render_template('team.html', form=form, cps=cps)

def set_team_defs(form, members):
    try:
        form.mem1.default=members[0]
        form.mem2.default=members[1]
        form.mem3.default=members[2]
        form.mem4.default=members[3]
        form.mem5.default=members[4]
    except:
        pass
    form.process()

def gather_members(form):
    members = [ form.mem1.data, form.mem2.data, form.mem3.data,
                form.mem4.data, form.mem5.data ]
    result = u""
    for x in filter(lambda x: x != u'' and x, members):
        result += u'"' + x + u'"'  + u','
    return u"[" + result[:-1] + u"]"

@app.route('/teams')
def teams():
    series = query_db('SELECT * FROM sarjat WHERE kilpailu=?',
        [g.race['id']])
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
            'teams' : sorted(filter(lambda x: x['series'] == serie['id'],
                teams), key=lambda x: x['name']) 
        })
    return render_template('teams.html',
        race_data=sorted(race_data, key=lambda x: x['name']))



@app.route('/admin', methods=['GET', 'POST'])
def admin_login():

    def validate_password(form, field):
        hasher = hashlib.sha512()
        hasher.update(app.config['SECRET_KEY'])
        hasher.update(field.data)
        if hasher.hexdigest() != '6e4345a2b8cfb1adf2fbb13f4af0e828bbf26e0adaaa6e02fe2c8fb3659bca546bc90addf640b500fa4ae27b6ae4793e17f713cc9141d507642efd83c5a6bf8b':
            raise ValidationError(u'Väärä salasana')
        
    class AdminLoginForm(FlaskForm):
        password = PasswordField('Salasana',
            validators=[DataRequired(), validate_password])

    login_form = AdminLoginForm()
    if login_form.validate_on_submit():
        session['logged_in'] = True
        return redirect(url_for('admin'))
    else:
        return render_template('admin_login.html', login_form=login_form)

@app.route('/admin-home')
@authorized
def admin():
    return render_template('admin.html',
        races=map(lambda x: x['nimi'], query_db('SELECT * FROM kilpailut')))


@app.route('/admin/<race>', methods=['GET', 'POST'])
@authorized
def admin_races(race):
    race_name = race

    def validate_name(form, field):
       series_in_race = map(lambda x: x['nimi'],
           query_db('SELECT * FROM sarjat WHERE kilpailu=?',
               [query_db('SELECT * FROM kilpailut WHERE nimi=?',
                   [race_name], one=True)['id']])) 
       for s in series_in_race:
           if field.data == s:
               raise ValidationError('Saman niminen sarja jo olemassa')

    class SeriesForm(FlaskForm):
        name = StringField('Nimi', validators=[DataRequired(), validate_name])
        duration = IntegerField('Kesto',
            validators=[InputRequired(), NumberRange(min=1,
                message=u'Keston on oltava suurenmpi kuin 0')])
        distance = IntegerField('Matka', validators=[Optional()])
        start_t = DateTimeField('Alkuaika', validators=[Optional()])
        stop_t = DateTimeField('Loppuaika', validators=[Optional()])

    series_form = SeriesForm()
    race = query_db('SELECT * FROM kilpailut WHERE nimi=?',
        [race], one=True)

    if series_form.validate_on_submit():
        query_db('''INSERT INTO sarjat (nimi, matka, alkuaika, loppuaika, kesto, kilpailu)
            VALUES (:nimi, :matka, :alkuaika, :loppuaika, :kesto, :kilpailu)''',
            {
                'nimi': series_form.name.data,
                'matka': series_form.distance.data if series_form.distance.data != u''
                                                   else u'',
                'alkuaika': series_form.start_t.data,
                'loppuaika': series_form.stop_t.data,
                'kesto': int(series_form.duration.data),
                'kilpailu' : race['id']
            })
    series = query_db('SELECT * FROM sarjat WHERE kilpailu=?',
    [race['id']])
    return render_template('admin_race.html', race=race,
        series=sorted(series, key=lambda x: x['kesto']),
        series_form=series_form)


@app.route('/admin/<race>/<series>', methods=['GET', 'POST'])
@authorized
def admin_series(race, series):

    series = query_db('SELECT * FROM sarjat WHERE nimi=?',
        [series], one=True)
    teams = query_db('SELECT * FROM joukkueet WHERE sarja=?',
        [series['id']])

    def validate_name(form, field):
        for team in teams:
            if field.data == team['nimi']:
                raise ValidationError(u'Sarjassa jo tämän niminen joukkue')


    class TeamForm(FlaskForm):
        """Form for editing users team"""
        team_name = StringField(u'Nimi',
            validators=[DataRequired(), validate_name])
        password = PasswordField(u'Salasana',
            validators=[DataRequired()])
        pw_again = PasswordField('Salasana uudelleen',
            validators=[EqualTo('password', message=u'Syöttämäsi salasanat eivät täsmää'), DataRequired()])
        mem1 = StringField(u'Jäsen 1', validators=[DataRequired()])
        mem2 = StringField(u'Jäsen 2', validators=[DataRequired()])
        mem3 = StringField(u'Jäsen 3', validators=[])
        mem4 = StringField(u'Jäsen 4', validators=[])
        mem5 = StringField(u'Jäsen 5', validators=[])

    def validate_series_name(form, field):
        series_in_race = map(lambda x: x['nimi'],
            query_db('SELECT * FROM sarjat WHERE kilpailu=?',
                [ query_db('SELECT * FROM kilpailut WHERE nimi=?',
                    [race], one=True)['id']])) 
        for s in series_in_race:
            if field.data == s:
                if series['nimi'] != s:
                    raise ValidationError(u'Saman niminen sarja jo olemassa')

    class SeriesForm(FlaskForm):
        '''
        Flask-form for updating or deleting selected series
        '''
        name = StringField('Nimi',
            validators=[DataRequired(), validate_series_name],
            default=series['nimi'])
        duration = IntegerField('Kesto',
            validators=[DataRequired(), NumberRange(min=1, message=u"Keston on oltava suurempi kuin 0")],
            default=series['kesto'])
        distance = StringField('Matka', default=series['matka'])
        start_t = DateTimeField('Alkuaika',
            validators=[Optional()],
            default=datetime.strptime(series['alkuaika'],
                '%Y-%m-%d %H:%M:%S') if series['alkuaika'] else u'')
        stop_t = DateTimeField('Loppuaika',
            validators=[Optional()],
            default=datetime.strptime(series['loppuaika'],
                '%Y-%m-%d %H:%M:%S') if series['loppuaika'] else u'')
        delete = BooleanField('Poista sarja')
        submit = SubmitField('Tallenna')

    team_form = TeamForm()
    series_form = SeriesForm()
    
    if request.form.get('form-name') == u'team' and team_form.validate_on_submit():
        query_db('''
            INSERT
            INTO joukkueet
            (nimi, sarja, salasana, jasenet)
            VALUES (:nimi, :sarja, :salasana, :jasenet)''',
            {
               'nimi': team_form.team_name.data,
               'sarja': series['id'],
               'salasana': None,
               'jasenet': gather_members(team_form)
            })
        created_team = query_db('SELECT * FROM joukkueet WHERE nimi=? AND sarja=?',
            [team_form.team_name.data, series['id']], one=True)
        hasher = hashlib.sha512(unicode(created_team['id']) + team_form.password.data)
        query_db('UPDATE joukkueet SET salasana=? WHERE id=?',
            [hasher.hexdigest(), created_team['id']])
        
    if request.form.get('form-name') == u'series' and series_form.validate_on_submit():

        if series_form.delete.data:
        #Delete checkbox is activated

            #Check if series contains teams
            if query_db('SELECT * FROM joukkueet WHERE sarja=?', [series['id']]):
                flash(u'Sarjassa joukkueita. Poisto peruutettu!', 'error')
                
                #Render same page with error-message
                return render_template('admin_series.html',
                    series=series['nimi'],
                    race=race,
                    teams=sorted(teams, key=lambda x: x['nimi']),
                    series_form=series_form,
                    team_form=team_form)
            
            #Delete series from database
            else:
                query_db('DELETE FROM sarjat WHERE id=?', [series['id']])
                flash(u'Sarja {0} poistettu'.format(series['nimi']), 'success')
                
                #Redirect user to race-listing page with message
                return redirect(url_for('admin_races', race=race))

        #Update series
        query_db('''UPDATE sarjat
                    SET nimi=?, kesto=?, matka=?, alkuaika=?, loppuaika=?
                    WHERE id=?
                    ''', 
            [series_form.name.data, series_form.duration.data,
            series_form.distance.data, series_form.start_t.data,
            series_form.stop_t.data, series['id']])                        

    teams = query_db('SELECT * FROM joukkueet WHERE sarja=?',
        [series['id']])

    #Render same page with updated data
    return render_template('admin_series.html',
        series=series['nimi'],
        race=race,
        teams=sorted(teams, key=lambda x: x['nimi']),
        series_form=series_form,
        team_form=team_form)

@app.route('/admin/<race>/<series>/<team>', methods=['GET', 'POST'])
def admin_team(race, series, team):
    
    session['team_route'] = {
        'race': race,
        'series': series,
        'team': team
    }

    race = query_db('SELECT * FROM kilpailut WHERE nimi=?',
        [race], one=True)
    s_list = query_db('SELECT * FROM sarjat WHERE kilpailu=?',
        [race['id']])
    team = query_db('SELECT * FROM joukkueet WHERE sarja=? AND nimi=?',
        [filter(lambda x: x['nimi'] == series, s_list)[0]['id'], team], one=True)
    team['jasenet'] = map(lambda x: x.decode('utf-8'), literal_eval(team['jasenet'])) 



    def validate_name(form, field):
        if field.data == team['nimi']: return
        existing_teams = []
        for serie in s_list:
            teams = query_db('SELECT * FROM joukkueet WHERE sarja=?',
                [serie['id']])
            existing_teams += (map(lambda x: x['nimi'],
                teams))
        for name in existing_teams:
            if name == field.data:
                raise ValidationError(u'Kilpailuun rekisteröidytty tällä nimellä')

    class TeamForm(FlaskForm):
        """Form for editing users team"""
        name = StringField(u'Nimi',
            validators=[DataRequired(), validate_name],
            default=team['nimi'])
        series = RadioField(u'Sarja', validators=[DataRequired()],
            coerce=int,
            default=team['sarja'],  
            choices=sorted(map(lambda x: (x['id'], x['nimi']), s_list),
                key=lambda y: y[1]))
        new_password = PasswordField(u'Uusi salasana')
        new_pw_again = PasswordField('Salasana uudelleen',
            validators=[EqualTo('new_password',
                message=u'Syöttämäsi salasanat eivät täsmää')])
        delete = BooleanField('Poista')
        mem1 = StringField(u'Jäsen 1', validators=[DataRequired()])
        mem2 = StringField(u'Jäsen 2', validators=[DataRequired()])
        mem3 = StringField(u'Jäsen 3', validators=[])
        mem4 = StringField(u'Jäsen 4', validators=[])
        mem5 = StringField(u'Jäsen 5', validators=[])

    team_form = TeamForm()

    cps = sorted(query_db('SELECT * FROM tupa WHERE joukkue=?',
        [team['id']]), key=lambda x: datetime.strptime(x['aika'],
            '%Y-%m-%d %H:%M:%S')) 
    #cps = filter(lambda x: x['rasti'] != 0 , cps)
    cps = map(lambda x: {
        'cp': x['rasti'],
        'name':  query_db('SELECT * FROM rastit WHERE id=?',
            [x['rasti']], one=True)['koodi'],
        'time': x['aika'],
        'team': x['joukkue']
        }, cps)
    if team_form.validate_on_submit():
        if team_form.delete.data:
            #Check if series contains teams
            if query_db('SELECT * FROM tupa WHERE joukkue=?', [team['id']]):
                flash(u'Joukkueella on rastileimauksia. Poisto peruutettu!', 'error')
                
                #Render same page with error-message
                return render_template('admin_team.html',
                    team_form=team_form,
                    cps=cps)

            #Delete series from database
            else:
                query_db('DELETE FROM joukkueet WHERE id=?', [team['id']])
                flash(u'Joukkue {0} poistettu'.format(team['nimi']), 'success')
                
                # Redirect user to race-listing page with message
                return redirect(url_for('admin_series',
                    race=race['nimi'],
                    series=series))

        query_db('UPDATE joukkueet SET nimi=?, sarja=?, jasenet=? WHERE id=?',
            [   
                team_form.name.data, filter(lambda x: x['id'] == team_form.series.data,
                    query_db('SELECT * FROM sarjat'))[0]['id'],
                gather_members(team_form),
                team['id']
            ])

        if team_form.new_password.data:
            pw_hasher = hashlib.sha512(unicode(team['id']) +
                team_form.new_password.data)
            query_db('UPDATE joukkueet SET salasana=? WHERE id=?',
                [ pw_hasher.hexdigest(), team['id'] ])
    else:
        set_team_defs(team_form, team['jasenet'])

    return render_template('admin_team.html',
        team_form=team_form, cps=cps)


@app.route('/admin/checkpoints', methods=['GET', 'POST'])
def admin_checkpoints():
    cps = query_db( '''
                    SELECT * FROM rastit
                    LEFT OUTER JOIN tupa
                    ON rastit.id = tupa.rasti
                    ''')
    teams = query_db('SELECT * FROM joukkueet')

    freq = {}
    for x in cps:
        if x['joukkue']:
            if x['id'] in freq: freq[x['id']] += 1
            else: freq[x['id']] = 1
        else:
            freq[x['id']] = 0

    cps = {cp['id']:cp for cp in cps}.values()
    for x in cps:
        x['freq'] = freq[x['id']]

    return render_template('admin_cps.html',
        cps=sorted(cps, key=lambda x: x['koodi']),
        teams=teams)

@app.route('/admin/checkpoint/<team>/<time>/<cp>', methods=['GET', 'POST'])
def admin_cp(team, time, cp):
    all_cps = query_db('SELECT * FROM rastit')
    class StampForm(FlaskForm):
        e_time = DateTimeField(u'Leimausaika', 
            default=datetime.strptime(time, '%Y-%m-%d %H:%M:%S'))
        check_p = SelectField(u'Rasti', coerce=int,
            default=cp,
            choices=map(lambda x: (x['id'], x['koodi']), all_cps))
        delete = BooleanField('Poista leimaus')

    form = StampForm()
    if form.validate_on_submit():
        if form.delete.data:
            query_db('DELETE FROM tupa WHERE joukkue=? AND aika=? AND rasti=?',
                [team, time, cp])
        else:
            query_db('UPDATE tupa SET aika=?, rasti=? WHERE aika=? AND joukkue=? AND rasti=?',
                [
                    form.e_time.data,
                    form.check_p.data,
                    time, team, cp
                ])
        return redirect(url_for('admin_team',
            race=session['team_route']['race'],
            team=session['team_route']['team'],
            series=session['team_route']['series']))
    
    return render_template('admin_stamp_event.html', form=form)

if __name__ == '__main__':
    app.run(debug=True)