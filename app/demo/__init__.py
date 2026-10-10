"""End-to-end demonstration entry points (T06 + T07).

Deterministic planning demo::

    python -m app.demo.investigation --case CASE-001

Model-driven planning demo (scripted or live)::

    python -m app.demo.llm_investigation --case CASE-001 --mode scripted
    python -m app.demo.llm_investigation --case CASE-001 --mode live

The modules are intentionally not re-exported here: importing them from this
``__init__`` would double-import the module when it is executed with ``-m``.
Import them directly instead::

    from app.demo.investigation import run_investigation_demo
    from app.demo.llm_investigation import run_llm_investigation
"""
