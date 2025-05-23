from app import app, db, User

def create_admin_user():
    with app.app_context():
        # Check if admin user already exists
        admin = User.query.filter_by(username='admin').first()
        if admin:
            print('Admin user already exists')
            return
        
        # Create admin user
        admin = User(username='admin', user_type='admin')
        admin.set_password('admin123')  # Change this to a secure password
        
        db.session.add(admin)
        db.session.commit()
        print('Admin user created successfully')

if __name__ == '__main__':
    create_admin_user() 