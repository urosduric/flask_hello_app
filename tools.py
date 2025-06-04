
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
cd /Users/urosduric/flask_hello_app && git checkout main && git add templates/*.html *.py && git commit -m "Update project files" && git push origin main
'''

