def to_toon(data: list) -> str:
    """
    Converts a list of dictionaries to Token-Oriented Object Notation (TOON) format.
    TOON is a compact, line-based format where keys are headers and values are tab-separated.
    It organizes nested keys using dot notation (e.g., "principal.user.userid").

    Args:
        data (list): A list of dictionaries (e.g., JSON objects).

    Returns:
        str: The TOON formatted string.
    """
    if not data:
        return ""

    def flatten_dict(d, parent_key='', sep='.'):
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(flatten_dict(v, new_key, sep=sep).items())
            elif isinstance(v, list):
                # Simple handling for lists: join with comma or just keep as string
                # For TOON, maybe just str(v) is enough for now, or we could explode?
                # Let's keep it simple: str(v)
                items.append((new_key, str(v)))
            else:
                items.append((new_key, v))
        return dict(items)

    flattened_data = [flatten_dict(item) for item in data]

    # Collect all unique keys
    all_keys = set()
    for item in flattened_data:
        all_keys.update(item.keys())

    headers = sorted(list(all_keys))

    # Build the TOON string
    lines = []

    # Header line
    lines.append("  ".join(headers))

    for item in flattened_data:
        row_values = []
        for header in headers:
            val = item.get(header, "")
            val_str = str(val).replace('\n', ' ').replace('\r', '')
            # Aggressive truncation for very long values to save tokens
            if len(val_str) > 100:
                val_str = val_str[:97] + "..."
            row_values.append(val_str)
        lines.append("  ".join(row_values))

    return "\n".join(lines)
