import re
from pathlib import Path

PATTERNS = {
    "EMAIL": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
    "PHONE": r"(?<!\w)(?:\+91[- ]?)?[6-9]\d{9}(?!\w)",
    "API_KEY": r"\b(?:sk-[A-Za-z0-9_-]{12,}|"
               r"AKIA[A-Z0-9]{16})\b",
    "EMPLOYEE_ID": r"\bEMP[-_]?\d{3,}\b",
}

def redact_text(text):
    counts = {}

    for label, pattern in PATTERNS.items():
        text, count = re.subn(
            pattern, f"[{label}_REDACTED]", text,
            flags=re.IGNORECASE
        )
        if count:
            counts[label] = count

    return text, counts

def main():
    source = Path("input/sample.txt")
    destination = Path("output/sample_redacted.txt")

    if not source.exists():
        print(f"Input file not found: {source}")
        return

    original = source.read_text(encoding="utf-8")
    cleaned, counts = redact_text(original)

    destination.write_text(cleaned, encoding="utf-8")

    print("\nRedaction complete!")
    print("Items detected:", counts or "None")
    print("Saved to:", destination.resolve())
    print("\nRedacted preview:\n")
    print(cleaned)

if __name__ == "__main__":
    main()
