
#Some terminal commands:

'To generate all tables and maybe even new columns in database so it works'
#python3 -c "from app import app, db; app.app_context().push(); db.create_all()"

'Kill old app and start it again - watch for the port'
# lsof -i :5004 | grep LISTEN | awk '{print $2}' | xargs kill -9
# python app.py

'Push current files to github - if you added new files, discuss this with agent'
'''
git add app.py tools.py requirements.txt templates/ instance/ stock_data.csv treasury_5y_data.csv create_admin.py generate_stock_data.py generate_treasury_data.py
(venv) (base) urosduric@Uross-Air flask_hello_app % 
git commit -m "Add all necessary files for production: templates, database, data files, and scripts"
 create mode 100644 templates/new_fund.html
 create mode 100644 templates/new_portfolio.html
 create mode 100644 templates/new_risk_factor.html
 create mode 100644 templates/portfolios.html
 create mode 100644 templates/register.html
 create mode 100644 templates/risk_factors.html
 create mode 100644 templates/upload_risk_factor_data.html
 create mode 100644 templates/user_page.html
 create mode 100644 templates/user_profile.html
 create mode 100644 templates/users.html
 create mode 100644 templates/view_benchmark.html
 create mode 100644 templates/view_portfolio.html
 create mode 100644 templates/view_risk_factor.html
 create mode 100644 tools.py
 create mode 100644 treasury_5y_data.csv
(venv) (base) urosduric@Uross-Air flask_hello_app %
git push origin main
'''