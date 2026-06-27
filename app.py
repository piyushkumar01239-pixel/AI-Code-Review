from flask import Flask, render_template
from dotenv import load_dotenv
import os

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'fallback-secret-key')

@app.route('/')
def index():
    return '<h1>CodeGuard is running!</h1>'

if __name__ == '__main__':
    app.run(debug=True)