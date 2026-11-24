"""Check the frozen documentation-only inventory, not scanner execution."""

from pathlib import PurePosixPath


def check(files: dict[str, str]) -> bool:
    if set(files) != {"README.md", "guide.mdx"}:
        return False
    return all(
        PurePosixPath(path).suffix in {".md", ".mdx"}
        and isinstance(text, str)
        and bool(text.strip())
        for path, text in files.items()
    )
