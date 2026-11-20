"""add identity extraction and duplicate detection

Revision ID: 62b515398615
Revises: c43121d2b4bf
Create Date: 2026-11-20 23:52:45.233710

"""

"""add identity extraction and duplicate detection

Revision ID: 62b515398615
Revises: c43121d2b4bf
"""

from alembic import op
import sqlalchemy as sa


revision = "62b515398615"
down_revision = "c43121d2b4bf"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table(
        "ocr_results",
        schema=None,
    ) as batch_op:
        batch_op.add_column(
            sa.Column(
                "encrypted_identity_data",
                sa.Text(),
                nullable=True,
            )
        )

        batch_op.add_column(
            sa.Column(
                "extraction_status",
                sa.String(length=20),
                nullable=False,
                server_default="UNSUPPORTED",
            )
        )

    with op.batch_alter_table(
        "verification_submissions",
        schema=None,
    ) as batch_op:
        batch_op.add_column(
            sa.Column(
                "duplicate_detected",
                sa.Boolean(),
                nullable=False,
                server_default=sa.false(),
            )
        )


def downgrade():
    with op.batch_alter_table(
        "verification_submissions",
        schema=None,
    ) as batch_op:
        batch_op.drop_column("duplicate_detected")

    with op.batch_alter_table(
        "ocr_results",
        schema=None,
    ) as batch_op:
        batch_op.drop_column("extraction_status")
        batch_op.drop_column("encrypted_identity_data")
