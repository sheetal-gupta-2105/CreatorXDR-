from pathlib import Path
from alembic.config import Config
from alembic.script import ScriptDirectory


def test_alembic_has_single_head():
    """Ensure the Alembic migration graph has no branched/multiple heads."""
    backend_dir = Path(__file__).resolve().parents[1]
    alembic_ini = backend_dir / "migrations" / "alembic.ini"
    cfg = Config(str(alembic_ini))
    cfg.set_main_option("script_location", str(backend_dir / "migrations"))

    script = ScriptDirectory.from_config(cfg)
    heads = script.get_heads()
    assert len(heads) == 1, f"Expected 1 Alembic head, found {len(heads)}: {heads}"
