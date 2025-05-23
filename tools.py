
#Some terminal commands:

#python3 -c "from app import app, db; app.app_context().push(); db.create_all()"

# lsof -i :5004 | grep LISTEN | awk '{print $2}' | xargs kill -9
# python app.py
