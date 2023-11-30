from database_test import User, db

def add_data():
    admin = User(username='admin', email='admin@example.com')
    guest = User(username='guest', email='guest@example.com')

    db.session.add(admin)
    db.session.add(guest)

    db.session.commit()


def read_data():
    all_users = User.query.all()
    user_with_id_2 = User.query.get(2)
    user_by_email = User.query.filter_by(email='fulano@usp.br').first()
    user_by_email_or_none = User.query.filter_by(email='fulano@usp.br').first_or_404(description='There is no user with email fulano@usp.br')

    return all_users, user_with_id_2, user_by_email, user_by_email_or_none

