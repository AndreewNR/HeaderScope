# headerscope/scorer.py
PENALTIES = {
    "High": 15,
    "Medium": 8,
    "Low": 3
}

def calculate_score(findings: list) -> int:
    score = 100

    for f in findings:
        if f["status"] == "missing":
            score -= PENALTIES.get(f["severity"], 0)

    return max(score, 0)
