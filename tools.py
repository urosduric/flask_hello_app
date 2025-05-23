
# Kill any process on this port
'''
kill -9 $(lsof -t -i:5005)
'''

# To run the app in the terminal
'''
cd /Users/urosduric/flask_hello_app
source venv/bin/activate
python app.py 5005     
'''

# send to github
'''
git init
git add .
git commit -m "Initial commit: Flask application with risk factors management"
git remote -v | cat
git push origin main | cat
'''