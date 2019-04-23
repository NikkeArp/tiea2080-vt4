#!/venv/bin/python
# -*- coding: python -*-

#Flask modules
from flask import Flask, render_template, url_for, redirect, request, session

#my modules
from mylogging import logging, log_exc

#application configurations
app = Flask(__name__)
app.config['SECRET_KEY'] = u'Nr*\xcf\xd8\xc7\xb5N\xf9\x9f\x98\xe2'


@app.route('/')
def hello():
    return 'Hello World!'

if __name__ == '__main__':
    app.run(debug=True)