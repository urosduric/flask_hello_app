
# Kill any process on this port
'''
kill -9 $(lsof -t -i:5004)
'''

# To run the app in the terminal
'''
cd /Users/urosduric/flask_hello_app
source venv/bin/activate
python app.py 5005     
'''

# send to github
'''
git add .gitignore requirements.txt README.md app.py templates/ tools.py create_admin.py Procfile | cat
git commit -m "Initial commit: Risk Management Application" | cat
git remote -v | cat
git push origin main | cat
'''