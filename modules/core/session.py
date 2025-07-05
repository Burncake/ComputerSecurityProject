_current_user = None

def login_user(user_obj):
    global _current_user
    _current_user = user_obj

def logout_user():
    global _current_user
    _current_user = None

def is_logged_in():
    return _current_user is not None

def get_user():
    return _current_user
