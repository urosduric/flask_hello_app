# Risk Management Application

A Flask-based web application for managing investment portfolios and risk factors.

## Features

- User authentication and authorization
- Portfolio management
- Fund tracking
- Benchmark management
- Risk factor analysis
- Data visualization

## Setup

1. Clone the repository:
```bash
git clone <repository-url>
cd flask_hello_app
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Initialize the database:
```bash
flask db init
flask db migrate
flask db upgrade
```

5. Run the application:
```bash
python app.py
```

The application will be available at `http://localhost:5004`

## Environment Variables

Create a `.env` file in the root directory with the following variables:
```
SECRET_KEY=your-secret-key
```

## Project Structure

- `app.py`: Main application file
- `templates/`: HTML templates
- `static/`: Static files (CSS, JavaScript, images)
- `instance/`: Instance-specific files (database)
- `migrations/`: Database migration files

## Dependencies

- Flask: Web framework
- Flask-SQLAlchemy: Database ORM
- Flask-Login: User authentication
- Flask-Migrate: Database migrations
- Pandas: Data manipulation
- Werkzeug: WSGI utilities
- SQLAlchemy: SQL toolkit
- python-dotenv: Environment variable management
