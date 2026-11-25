"""harden identity verification

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
Create Date: 2026-11-25 10:30:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'b2c3d4e5f6a7'
down_revision = 'a1b2c3d4e5f6'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('verification_submissions', schema=None) as batch_op:
        batch_op.drop_constraint('ck_verification_submission_status', type_='check')
        batch_op.create_check_constraint(
            'ck_verification_submission_status',
            "status IN ("
            "'AWAITING_CONFIRMATION', 'PENDING_REVIEW', 'UNDER_REVIEW', "
            "'NEEDS_RESUBMISSION', 'REJECTED', "
            "'APPROVED', 'PENDING_CHAIN', "
            "'CHAIN_FAILED', 'VERIFIED', 'QUARANTINED'"
            ")",
        )
        batch_op.add_column(sa.Column('deletion_reason', sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column('quarantined', sa.Boolean(), server_default=sa.text('false'), nullable=False))
        batch_op.add_column(sa.Column('quarantine_reason', sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column('confirmed_at', sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column('correction_mismatch', sa.Boolean(), server_default=sa.text('false'), nullable=False))

    with op.batch_alter_table('ocr_results', schema=None) as batch_op:
        batch_op.alter_column('encrypted_text', existing_type=sa.Text(), nullable=True)
        batch_op.add_column(sa.Column('encrypted_corrected_data', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('corrected_at', sa.DateTime(timezone=True), nullable=True))


def downgrade():
    with op.batch_alter_table('ocr_results', schema=None) as batch_op:
        batch_op.drop_column('corrected_at')
        batch_op.drop_column('encrypted_corrected_data')
        batch_op.alter_column('encrypted_text', existing_type=sa.Text(), nullable=False)

    with op.batch_alter_table('verification_submissions', schema=None) as batch_op:
        batch_op.drop_column('correction_mismatch')
        batch_op.drop_column('confirmed_at')
        batch_op.drop_column('quarantine_reason')
        batch_op.drop_column('quarantined')
        batch_op.drop_column('deletion_reason')
        batch_op.drop_constraint('ck_verification_submission_status', type_='check')
        batch_op.create_check_constraint(
            'ck_verification_submission_status',
            "status IN ("
            "'PENDING_REVIEW', 'UNDER_REVIEW', "
            "'NEEDS_RESUBMISSION', 'REJECTED', "
            "'APPROVED', 'PENDING_CHAIN', "
            "'CHAIN_FAILED', 'VERIFIED'"
            ")",
        )
