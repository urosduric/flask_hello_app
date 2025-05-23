
#Some terminal commands:

'To generate all tables and maybe even new columns in database so it works'
'''
python3 -c "from app import app, db; app.app_context().push(); db.create_all()
'''

'Kill old app and start it again - watch for the port'
'''
lsof -i :5004 | grep LISTEN | awk '{print $2}' | xargs kill -9
python app.py
'''

'Push current files to github - if you added new files, discuss this with agent'
'''
git add app.py tools.py requirements.txt templates/ instance/ stock_data.csv treasury_5y_data.csv create_admin.py generate_stock_data.py generate_treasury_data.py
git commit -m "Add all necessary files for production: templates, database, data files, and scripts"
git push origin main
'''