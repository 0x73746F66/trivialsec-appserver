
import json
from trivialsec.models import Finding
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

def findings_severity_donut(findings: list):
    return json.dumps({
        'datasets': [{
            'backgroundColor': [
                f"rgb({', '.join(map(str, Finding.SEVERITY_INFO_RGB))})",
                f"rgb({', '.join(map(str, Finding.SEVERITY_LOW_RGB))})",
                f"rgb({', '.join(map(str, Finding.SEVERITY_MEDIUM_RGB))})",
                f"rgb({', '.join(map(str, Finding.SEVERITY_HIGH_RGB))})",
                f"rgb({', '.join(map(str, Finding.SEVERITY_CRITICAL_RGB))})",
            ],
            'hoverBackgroundColor': [
                f"rgba({', '.join(map(str, Finding.SEVERITY_INFO_RGB))}, 0.5)",
                f"rgba({', '.join(map(str, Finding.SEVERITY_LOW_RGB))}, 0.5)",
                f"rgba({', '.join(map(str, Finding.SEVERITY_MEDIUM_RGB))}, 0.5)",
                f"rgba({', '.join(map(str, Finding.SEVERITY_HIGH_RGB))}, 0.5)",
                f"rgba({', '.join(map(str, Finding.SEVERITY_CRITICAL_RGB))}, 0.5)",
            ],
            'data': [
                aggregate_sum(findings, Finding.RATING_INFO, 'severity_normalized', 'score_to_rating'),
                aggregate_sum(findings, Finding.RATING_LOW, 'severity_normalized', 'score_to_rating'),
                aggregate_sum(findings, Finding.RATING_MEDIUM, 'severity_normalized', 'score_to_rating'),
                aggregate_sum(findings, Finding.RATING_HIGH, 'severity_normalized', 'score_to_rating'),
                aggregate_sum(findings, Finding.RATING_CRITICAL, 'severity_normalized', 'score_to_rating'),
            ]
        }],
        'labels': [
            Finding.RATING_INFO,
            Finding.RATING_LOW,
            Finding.RATING_MEDIUM,
            Finding.RATING_HIGH,
            Finding.RATING_CRITICAL,
        ]
    })

def findings_criticality_donut(findings: list):
    return json.dumps({
        'datasets': [{
            'backgroundColor': [
                f"rgb({', '.join(map(str, Finding.CRITICALITY_INFO_RGB))})",
                f"rgb({', '.join(map(str, Finding.CRITICALITY_LOW_RGB))})",
                f"rgb({', '.join(map(str, Finding.CRITICALITY_MEDIUM_RGB))})",
                f"rgb({', '.join(map(str, Finding.CRITICALITY_HIGH_RGB))})",
                f"rgb({', '.join(map(str, Finding.CRITICALITY_CRITICAL_RGB))})",
            ],
            'hoverBackgroundColor': [
                f"rgba({', '.join(map(str, Finding.CRITICALITY_INFO_RGB))}, 0.5)",
                f"rgba({', '.join(map(str, Finding.CRITICALITY_LOW_RGB))}, 0.5)",
                f"rgba({', '.join(map(str, Finding.CRITICALITY_MEDIUM_RGB))}, 0.5)",
                f"rgba({', '.join(map(str, Finding.CRITICALITY_HIGH_RGB))}, 0.5)",
                f"rgba({', '.join(map(str, Finding.CRITICALITY_CRITICAL_RGB))}, 0.5)",
            ],
            'data': [
                aggregate_sum(findings, Finding.RATING_INFO, 'detail_criticality', 'score_to_rating'),
                aggregate_sum(findings, Finding.RATING_LOW, 'detail_criticality', 'score_to_rating'),
                aggregate_sum(findings, Finding.RATING_MEDIUM, 'detail_criticality', 'score_to_rating'),
                aggregate_sum(findings, Finding.RATING_HIGH, 'detail_criticality', 'score_to_rating'),
                aggregate_sum(findings, Finding.RATING_CRITICAL, 'detail_criticality', 'score_to_rating'),
            ]
        }],
        'labels': [
            Finding.RATING_INFO,
            Finding.RATING_LOW,
            Finding.RATING_MEDIUM,
            Finding.RATING_HIGH,
            Finding.RATING_CRITICAL,
        ]
    })

def findings_confidence_donut(findings: list):
    return json.dumps({
        'datasets': [{
            'backgroundColor': [
                f"rgb({', '.join(map(str, Finding.CONFIDENCE_HIGH_RGB))})",
                f"rgb({', '.join(map(str, Finding.CONFIDENCE_MEDIUM_RGB))})",
                f"rgb({', '.join(map(str, Finding.CONFIDENCE_LOW_RGB))})",
            ],
            'hoverBackgroundColor': [
                f"rgba({', '.join(map(str, Finding.CONFIDENCE_HIGH_RGB))}, 0.5)",
                f"rgba({', '.join(map(str, Finding.CONFIDENCE_MEDIUM_RGB))}, 0.5)",
                f"rgba({', '.join(map(str, Finding.CONFIDENCE_LOW_RGB))}, 0.5)",
            ],
            'data': [
                aggregate_sum(findings, Finding.CONFIDENCE_HIGH, 'detail_confidence', 'score_to_confidence'),
                aggregate_sum(findings, Finding.CONFIDENCE_MEDIUM, 'detail_confidence', 'score_to_confidence'),
                aggregate_sum(findings, Finding.CONFIDENCE_LOW, 'detail_confidence', 'score_to_confidence'),
            ]
        }],
        'labels': [
            Finding.CONFIDENCE_HIGH,
            Finding.CONFIDENCE_MEDIUM,
            Finding.CONFIDENCE_LOW,
        ]
    })
