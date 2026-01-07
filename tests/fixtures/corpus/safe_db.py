from models import User


def handle(_user):
    return None


def fetch_active(users):
    qs = User.objects.filter(active=True)
    for user in users:
        handle(user)
    return list(qs)
