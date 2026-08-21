"""Initial hardened schema for users, transactions, and alerts.

Revision ID: 001_initial_hardened_schema
Revises: 
Create Date: 2026-08-18 15:25:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '001_initial_hardened_schema'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # 1. Create users table
    op.create_table(
        'users',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('name', sa.String(length=100), nullable=False),
        sa.Column('email', sa.String(length=120), nullable=False),
        sa.Column('password_hash', sa.String(length=255), nullable=False),
        sa.Column('role', sa.String(length=20), nullable=False, server_default='USER'),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.CheckConstraint("role IN ('USER', 'ADMIN')", name='check_user_role'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_users_email'), 'users', ['email'], unique=True)
    op.create_index(op.f('ix_users_created_at'), 'users', ['created_at'], unique=False)

    # 2. Create transactions table
    op.create_table(
        'transactions',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('step', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('type', sa.String(length=20), nullable=False),
        sa.Column('amount', sa.Float(), nullable=False),
        sa.Column('name_orig', sa.String(length=50), nullable=True),
        sa.Column('oldbalance_org', sa.Float(), nullable=False),
        sa.Column('newbalance_orig', sa.Float(), nullable=False),
        sa.Column('name_dest', sa.String(length=50), nullable=True),
        sa.Column('oldbalance_dest', sa.Float(), nullable=False),
        sa.Column('newbalance_dest', sa.Float(), nullable=False),
        sa.Column('prediction', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('fraud_probability', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('risk_score', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('risk_level', sa.String(length=20), nullable=False, server_default='LOW'),
        sa.Column('decision', sa.String(length=50), nullable=False, server_default='APPROVE_IMMEDIATELY'),
        sa.Column('status', sa.String(length=30), nullable=False, server_default='APPROVED'),
        sa.Column('requires_otp', sa.Boolean(), nullable=False, server_default=sa.text('0')),
        sa.Column('otp_code', sa.String(length=10), nullable=True),
        sa.Column('otp_expires_at', sa.DateTime(), nullable=True),
        sa.Column('otp_attempts', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('explanation_json', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.CheckConstraint('amount > 0', name='check_tx_amount_positive'),
        sa.CheckConstraint('fraud_probability >= 0.0 AND fraud_probability <= 1.0', name='check_tx_fraud_prob_range'),
        sa.CheckConstraint('risk_score >= 0 AND risk_score <= 100', name='check_tx_risk_score_range'),
        sa.CheckConstraint("risk_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')", name='check_tx_risk_level'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_transactions_user_id'), 'transactions', ['user_id'], unique=False)
    op.create_index(op.f('ix_transactions_created_at'), 'transactions', ['created_at'], unique=False)
    op.create_index(op.f('ix_transactions_user_id_created_at'), 'transactions', ['user_id', 'created_at'], unique=False)

    # 3. Create alerts table
    op.create_table(
        'alerts',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('transaction_id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('alert_type', sa.String(length=50), nullable=False),
        sa.Column('severity', sa.String(length=20), nullable=False),
        sa.Column('message', sa.Text(), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('resolved_at', sa.DateTime(), nullable=True),
        sa.CheckConstraint("severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')", name='check_alert_severity'),
        sa.CheckConstraint("status IN ('OPEN', 'ACKNOWLEDGED', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE', 'ESCALATED', 'DISMISSED')", name='check_alert_status'),
        sa.ForeignKeyConstraint(['transaction_id'], ['transactions.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_alerts_transaction_id'), 'alerts', ['transaction_id'], unique=True)
    op.create_index(op.f('ix_alerts_user_id'), 'alerts', ['user_id'], unique=False)
    op.create_index(op.f('ix_alerts_status'), 'alerts', ['status'], unique=False)
    op.create_index(op.f('ix_alerts_created_at'), 'alerts', ['created_at'], unique=False)


def downgrade():
    op.drop_table('alerts')
    op.drop_table('transactions')
    op.drop_table('users')
