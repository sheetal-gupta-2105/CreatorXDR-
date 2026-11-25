"""merge threat detection and identity hardening migrations

Revision ID: e692d1d0af59
Revises: 228fcf071718, b2c3d4e5f6a7
Create Date: 2026-11-26 00:20:11.224758

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'e692d1d0af59'
down_revision = ('228fcf071718', 'b2c3d4e5f6a7')
branch_labels = None
depends_on = None


def upgrade():
    pass


def downgrade():
    pass
