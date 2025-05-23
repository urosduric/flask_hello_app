import os
import subprocess
import signal
import sys
import time

def kill_app():
    """Kill the Flask app running on port 5004"""
    try:
        # Find the process using port 5004
        result = subprocess.run(['lsof', '-i', ':5004'], capture_output=True, text=True)
        if result.stdout:
            # Extract PID and kill the process
            pid = result.stdout.split('\n')[1].split()[1]
            os.kill(int(pid), signal.SIGKILL)
            print(f"Successfully killed process {pid}")
        else:
            print("No process found running on port 5004")
    except Exception as e:
        print(f"Error killing process: {e}")

def start_app():
    """Start the Flask app in the background"""
    try:
        # Get the current Python executable path
        python_path = sys.executable
        
        # Start the app in the background
        process = subprocess.Popen(
            [python_path, 'app.py'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Wait a moment to ensure the app starts
        time.sleep(2)
        
        # Check if the app is running on port 5004
        result = subprocess.run(['lsof', '-i', ':5004'], capture_output=True, text=True)
        if result.stdout:
            print("Flask app started successfully and is running on port 5004")
            print("You can access it at http://localhost:5004")
        else:
            print("Error: Flask app failed to start")
            stdout, stderr = process.communicate()
            print(f"Error details: {stderr}")
            
    except Exception as e:
        print(f"Error starting app: {e}")

def restart_app():
    """Kill and restart the Flask app"""
    kill_app()
    time.sleep(1)  # Wait a moment to ensure the port is freed
    start_app()

def init_db():
    """Initialize or update the database schema"""
    try:
        # Import here to avoid circular imports
        from app import app, db
        with app.app_context():
            db.create_all()
        print("Database initialized successfully")
    except Exception as e:
        print(f"Error initializing database: {e}")

def push_to_github():
    """Push current changes to GitHub"""
    try:
        # Add all necessary files
        files_to_add = [
            'app.py',
            'tools.py',
            'requirements.txt',
            'templates/',
            'instance/',
            'stock_data.csv',
            'treasury_5y_data.csv',
            'create_admin.py',
            'generate_stock_data.py',
            'generate_treasury_data.py'
        ]
        
        # Add files
        subprocess.run(['git', 'add'] + files_to_add, check=True)
        
        # Commit changes
        subprocess.run([
            'git', 'commit', 
            '-m', "Add all necessary files for production: templates, database, data files, and scripts"
        ], check=True)
        
        # Push to GitHub
        subprocess.run(['git', 'push', 'origin', 'main'], check=True)
        
        print("Successfully pushed changes to GitHub")
    except subprocess.CalledProcessError as e:
        print(f"Error during git operations: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")

def show_help():
    """Display available functions and their descriptions"""
    print("\nAvailable functions:")
    print("1. kill_app() - Kill the Flask app running on port 5004")
    print("2. start_app() - Start the Flask app")
    print("3. restart_app() - Kill and restart the Flask app")
    print("4. init_db() - Initialize or update the database schema")
    print("5. push_to_github() - Push current changes to GitHub")
    print("6. show_help() - Display this help message")

# Only run when the script is executed directly
if __name__ == "__main__":
    # Change this line to run a different function
    push_to_github()
