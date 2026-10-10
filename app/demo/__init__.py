"""End-to-end demonstration entry points (T06).

Run the closed loop (alert, runtime, tools, evidence, summary) with::

    python -m app.demo.investigation --case CASE-001

The module is intentionally not re-exported here: importing it from this
``__init__`` would double-import it when the file is executed with ``-m``.
Import it directly instead::

    from app.demo.investigation import run_investigation_demo
"""
