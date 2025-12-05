# small formatting utilities (expand as needed)
def truncate_secret(s: str, max_len: int = 80) -> str:
    if not s:
        return s
    if len(s) <= max_len:
        return s
    return s[:max_len] + "..."
