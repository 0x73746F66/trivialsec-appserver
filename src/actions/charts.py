
import json
from trivialsec.models.finding import Finding
from trivialsec.services.findings import aggregate_sum

def findings_severity_horizontal_bar(findings: list):
    info = aggregate_sum(findings, Finding.RATING_INFO, 'severity_normalized', 'score_to_rating')
    low = aggregate_sum(findings, Finding.RATING_LOW, 'severity_normalized', 'score_to_rating')
    medium = aggregate_sum(findings, Finding.RATING_MEDIUM, 'severity_normalized', 'score_to_rating')
    high = aggregate_sum(findings, Finding.RATING_HIGH, 'severity_normalized', 'score_to_rating')
    critical = aggregate_sum(findings, Finding.RATING_CRITICAL, 'severity_normalized', 'score_to_rating')
    data = []
    background_color = []
    labels = []
    if info > 0:
        data.append(info)
        labels.append(Finding.RATING_INFO)
        background_color.append(f"rgb({', '.join(map(str, Finding.SEVERITY_INFO_RGB))})")
    if low > 0:
        data.append(low)
        labels.append(Finding.RATING_LOW)
        background_color.append(f"rgb({', '.join(map(str, Finding.SEVERITY_LOW_RGB))})")
    if medium > 0:
        data.append(medium)
        labels.append(Finding.RATING_MEDIUM)
        background_color.append(f"rgb({', '.join(map(str, Finding.SEVERITY_MEDIUM_RGB))})")
    if high > 0:
        data.append(high)
        labels.append(Finding.RATING_HIGH)
        background_color.append(f"rgb({', '.join(map(str, Finding.SEVERITY_HIGH_RGB))})")
    if critical > 0:
        data.append(critical)
        labels.append(Finding.RATING_CRITICAL)
        background_color.append(f"rgb({', '.join(map(str, Finding.SEVERITY_CRITICAL_RGB))})")
    return json.dumps({
        "labels": labels,
        "datasets": [{
            "label": "Severity",
            "data": data,
            "fill": False,
            'barPercentage': 0.5,
            'barThickness': 6,
            'maxBarThickness': 8,
            'minBarLength': 2,
            "backgroundColor": background_color
        }]
    })
