default:
    @just --list

install:
    uv sync

test *args:
    uv run pytest -vvv {{args}}

lint:
    ruff check

format:
    uv run isort ./fwt ./tests
    ruff format
