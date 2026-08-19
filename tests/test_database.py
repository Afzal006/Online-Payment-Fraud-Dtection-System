import pytest
from sqlalchemy.exc import IntegrityError
from app import create_app
from app.extensions import db
from app.models.user import User
from app.models.transaction import Transaction
from app.models.alert import Alert
from database.init_db import init_database
from database.seed_db import seed_database


@pytest.fixture
def app():
    """Create test application with in-memory SQLite database."""
    app = create_app("testing")
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


def test_database_initialization_utility(app):
    """Verify init_database script initializes expected tables."""
    success = init_database(app)
    assert success is True


def test_idempotent_database_seeding(app):
    """Verify seed_database creates user and admin, and multiple runs do not duplicate."""
    # First seed
    seed_database(app)
    assert User.query.filter_by(email="user@example.com").count() == 1
    assert User.query.filter_by(email="admin@example.com").count() == 1

    # Second seed (idempotent check)
    seed_database(app)
    assert User.query.filter_by(email="user@example.com").count() == 1
    assert User.query.filter_by(email="admin@example.com").count() == 1


def test_duplicate_email_rejected(app):
    """Verify database unique constraint on email."""
    u1 = User(name="User One", email="unique@example.com", role="USER")
    u1.set_password("Password123!")
    db.session.add(u1)
    db.session.commit()

    u2 = User(name="User Two", email="unique@example.com", role="USER")
    u2.set_password("Password123!")
    db.session.add(u2)

    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()


def test_valid_user_and_admin_creation(app):
    """Verify creation and role differentiation for USER and ADMIN."""
    user = User(name="Standard User", email="standard@example.com", role="USER")
    user.set_password("Password123!")
    admin = User(name="Admin User", email="admin_role@example.com", role="ADMIN")
    admin.set_password("AdminPass123!")

    db.session.add_all([user, admin])
    db.session.commit()

    assert user.is_admin is False
    assert admin.is_admin is True
    assert user.check_password("Password123!") is True
    assert admin.check_password("AdminPass123!") is True


def test_user_password_hash_never_serialized(app):
    """Verify to_dict does not leak password_hash."""
    user = User(name="Secret User", email="secret@example.com", role="USER")
    user.set_password("SuperSecret123!")
    db.session.add(user)
    db.session.commit()

    data = user.to_dict()
    assert "password_hash" not in data
    assert data["email"] == "secret@example.com"


def test_transaction_relationships_and_foreign_keys(app):
    """Verify User -> Transaction and Transaction -> Alert relationships."""
    user = User(name="Tx User", email="txuser@example.com", role="USER")
    user.set_password("Password123!")
    db.session.add(user)
    db.session.commit()

    tx = Transaction(
        user_id=user.id,
        type="TRANSFER",
        amount=500.0,
        oldbalance_org=1000.0,
        newbalance_orig=500.0,
        oldbalance_dest=0.0,
        newbalance_dest=500.0,
        prediction=0,
        fraud_probability=0.05,
        risk_score=5,
        risk_level="LOW",
        decision="APPROVE_IMMEDIATELY",
    )
    db.session.add(tx)
    db.session.commit()

    alert = Alert(
        transaction_id=tx.id,
        user_id=user.id,
        severity="MEDIUM",
        message="Notice alert",
        status="OPEN",
    )
    db.session.add(alert)
    db.session.commit()

    # Relationship navigation
    assert user.transactions.count() == 1
    assert tx.user.email == "txuser@example.com"
    assert tx.alert.id == alert.id
    assert alert.transaction.amount == 500.0
    assert alert.user.name == "Tx User"


def test_database_rollback_on_failed_transaction(app):
    """Verify session rollback cleans uncommitted state."""
    user = User(name="Rollback User", email="rollback@example.com", role="USER")
    user.set_password("Password123!")
    db.session.add(user)
    db.session.commit()

    # Attempt to insert an invalid transaction (e.g. missing required field)
    try:
        invalid_tx = Transaction(user_id=user.id, type=None, amount=100.0)
        db.session.add(invalid_tx)
        db.session.commit()
    except Exception:
        db.session.rollback()

    assert Transaction.query.filter_by(user_id=user.id).count() == 0
