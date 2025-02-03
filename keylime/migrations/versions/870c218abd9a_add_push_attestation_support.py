"""Create attestations table and columns to enable push attestation protocol

Revision ID: 870c218abd9a
Revises: 330024be7bef
Create Date: 2024-02-23 00:02:34.715180

"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "870c218abd9a"
down_revision = "330024be7bef"
branch_labels = None
depends_on = None


def upgrade(engine_name):
    globals()[f"upgrade_{engine_name}"]()


def downgrade(engine_name):
    globals()[f"downgrade_{engine_name}"]()


def upgrade_registrar():
    pass


def downgrade_registrar():
    pass


def upgrade_cloud_verifier():
    op.create_table(
        "attestations",
        sa.Column("agent_id", sa.String(80), sa.ForeignKey("verifiermain.agent_id")),
        sa.Column("index", sa.Integer),
        sa.Column("nonce", sa.LargeBinary(128)),
        sa.Column("status", sa.String(8), server_default="waiting"),
        sa.Column("tpm_quote", sa.Text, nullable=True),
        sa.Column("hash_algorithm", sa.String(15)),
        sa.Column("signing_scheme", sa.String(15)),
        sa.Column("starting_ima_offset", sa.Integer),
        sa.Column("ima_entries", sa.Text, nullable=True),
        sa.Column("quoted_ima_entries_count", sa.Integer, nullable=True),
        sa.Column("mb_entries", sa.LargeBinary, nullable=True),
        # ISO8601 datetimes with microsecond precision in the UTC timezone are never more than 32 characters
        sa.Column("nonce_created_at", sa.String(32)),
        sa.Column("nonce_expires_at", sa.String(32)),
        sa.Column("evidence_received_at", sa.String(32), nullable=True),
        sa.Column("boottime", sa.String(32)),
        sa.PrimaryKeyConstraint("agent_id", "index"),
    )
    op.add_column("verifiermain", sa.Column("accept_attestations", sa.Boolean))


def downgrade_cloud_verifier():
    op.drop_table("attestations")
    op.drop_column("verifiermain", "accept_attestations")
