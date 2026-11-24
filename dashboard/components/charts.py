"""
Plotly Charting Components for CyberSentinel SOC Dashboard.
"""
from typing import Dict, Any, List
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
import numpy as np


def plot_threat_donut(threat_distribution: Dict[str, int]) -> go.Figure:
    """Renders a modern cybersecurity donut chart for detected threat categories."""
    labels = list(threat_distribution.keys())
    values = list(threat_distribution.values())
    
    # Custom SOC palette
    color_map = {
        "BENIGN": "#10b981",
        "DDoS": "#ef4444",
        "DoS Hulk": "#f97316",
        "PortScan": "#eab308",
        "FTP-Patator": "#a855f7",
        "SSH-Patator": "#06b6d4",
        "ANOMALY": "#ec4899",
    }
    colors = [color_map.get(l, "#64748b") for l in labels]

    fig = go.Figure(data=[go.Pie(
        labels=labels,
        values=values,
        hole=0.55,
        marker=dict(colors=colors, line=dict(color='#0b0f19', width=2)),
        textinfo='label+percent',
        hoverinfo='label+value+percent'
    )])
    
    fig.update_layout(
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color='#e2e8f0'),
        margin=dict(t=20, b=20, l=20, r=20),
        legend=dict(orientation="h", yanchor="bottom", y=-0.2, xanchor="center", x=0.5),
        height=320
    )
    return fig


def plot_confusion_matrix(cm: List[List[int]], target_names: List[str], title: str = "Confusion Matrix") -> go.Figure:
    """Renders an interactive heatmap for a confusion matrix."""
    fig = px.imshow(
        cm,
        labels=dict(x="Predicted Class", y="Actual Ground Truth", color="Flow Records"),
        x=target_names,
        y=target_names,
        text_auto=True,
        color_continuous_scale="Viridis",
        title=title
    )
    fig.update_layout(
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color='#e2e8f0'),
        margin=dict(t=40, b=20, l=20, r=20),
        height=380
    )
    return fig


def plot_feature_importances(features_dict: Dict[str, float], title: str = "Top Predictive Flow Features") -> go.Figure:
    """Renders a horizontal bar chart of feature importances."""
    df = pd.DataFrame(list(features_dict.items()), columns=["Feature", "Importance"])
    df = df.sort_values(by="Importance", ascending=True)

    fig = px.bar(
        df,
        x="Importance",
        y="Feature",
        orientation="h",
        color="Importance",
        color_continuous_scale="Tealgrn",
        title=title
    )
    fig.update_layout(
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color='#e2e8f0'),
        margin=dict(t=40, b=20, l=20, r=20),
        height=380,
        coloraxis_showscale=False
    )
    return fig


def plot_model_comparison_bar(models_metrics: Dict[str, Any]) -> go.Figure:
    """Renders grouped bar chart comparing Accuracy, Macro F1, and Latency."""
    names = []
    accs = []
    f1s = []
    latencies = []

    for key, data in models_metrics.items():
        names.append(data.get("name", key))
        accs.append(data.get("accuracy", 0.0) * 100)
        f1s.append(data.get("f1_macro", data.get("f1_score", 0.0)) * 100)
        latencies.append(data.get("inference_latency_ms_per_1k", 0.0))

    fig = go.Figure()
    fig.add_trace(go.Bar(x=names, y=accs, name="Accuracy (%)", marker_color="#38bdf8"))
    fig.add_trace(go.Bar(x=names, y=f1s, name="F1-Score (%)", marker_color="#10b981"))

    fig.update_layout(
        barmode='group',
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color='#e2e8f0'),
        title="Model Accuracy & F1-Score Comparison",
        margin=dict(t=40, b=20, l=20, r=20),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
        height=320
    )
    return fig
