"""Root conftest.

Its only job is to exist: pytest prepends the directory containing the
root-level ``conftest.py`` to ``sys.path``, which is what makes ``remediations``
and ``notifier`` importable from the tests without an editable install.
"""
