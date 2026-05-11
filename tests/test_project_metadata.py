from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib


def test_dev_dependencies_include_pytest():
    pyproject = tomllib.loads(Path("pyproject.toml").read_text())

    dev_dependencies = pyproject["tool"]["poetry"]["group"]["dev"]["dependencies"]

    assert "pytest" in dev_dependencies
