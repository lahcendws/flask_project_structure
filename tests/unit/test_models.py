import pytest as pytest

from app.models import Utilisateur


@pytest.fixture(scope='module')
def new_user():
    user = Utilisateur('patkennedy79@gmail.com', 'FlaskIsAwesome','user')
    return user
