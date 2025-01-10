"""add ek_ca_chain column

Revision ID: 4c161e609e9d
Revises: 330024be7bef
Create Date: 2024-10-18 15:33:02.471238

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '4c161e609e9d'
down_revision = '330024be7bef'
branch_labels = None
depends_on = None


def upgrade(engine_name):
    globals()[f"upgrade_{engine_name}"]()


def downgrade(engine_name):
    globals()[f"downgrade_{engine_name}"]()





def upgrade_registrar():
    op.add_column("registrarmain", sa.Column("ek_ca_chain", sa.String(length=2048), nullable=True))


def downgrade_registrar():
    op.drop_column("registrarmain", "mtls_cert")


def upgrade_cloud_verifier():
    pass


def downgrade_cloud_verifier():
    pass

