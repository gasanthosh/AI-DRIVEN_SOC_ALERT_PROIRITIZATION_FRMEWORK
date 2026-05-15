"""
schemas.py — Pydantic models for FastAPI request/response validation.
"""

from typing import Optional, List
from pydantic import BaseModel, Field


# ── Request ──────────────────────────────────────────────────────────────────

class TrafficFeatures(BaseModel):
    """
    Raw network flow features (matches CIC-IDS-2017 columns after cleaning).
    All fields are optional to allow partial inputs; missing fields are filled
    with 0.0 by the API before model inference.
    """
    Destination_Port: Optional[float] = Field(default=0.0, alias="Destination Port")
    Flow_Duration: Optional[float] = Field(default=0.0, alias="Flow Duration")
    Total_Fwd_Packets: Optional[float] = Field(default=0.0, alias="Total Fwd Packets")
    Total_Backward_Packets: Optional[float] = Field(default=0.0, alias="Total Backward Packets")
    Total_Length_of_Fwd_Packets: Optional[float] = Field(default=0.0, alias="Total Length of Fwd Packets")
    Total_Length_of_Bwd_Packets: Optional[float] = Field(default=0.0, alias="Total Length of Bwd Packets")
    Fwd_Packet_Length_Max: Optional[float] = Field(default=0.0, alias="Fwd Packet Length Max")
    Fwd_Packet_Length_Min: Optional[float] = Field(default=0.0, alias="Fwd Packet Length Min")
    Fwd_Packet_Length_Mean: Optional[float] = Field(default=0.0, alias="Fwd Packet Length Mean")
    Fwd_Packet_Length_Std: Optional[float] = Field(default=0.0, alias="Fwd Packet Length Std")
    Bwd_Packet_Length_Max: Optional[float] = Field(default=0.0, alias="Bwd Packet Length Max")
    Bwd_Packet_Length_Min: Optional[float] = Field(default=0.0, alias="Bwd Packet Length Min")
    Bwd_Packet_Length_Mean: Optional[float] = Field(default=0.0, alias="Bwd Packet Length Mean")
    Bwd_Packet_Length_Std: Optional[float] = Field(default=0.0, alias="Bwd Packet Length Std")
    Flow_Bytes_per_s: Optional[float] = Field(default=0.0, alias="Flow Bytes/s")
    Flow_Packets_per_s: Optional[float] = Field(default=0.0, alias="Flow Packets/s")
    Flow_IAT_Mean: Optional[float] = Field(default=0.0, alias="Flow IAT Mean")
    Flow_IAT_Std: Optional[float] = Field(default=0.0, alias="Flow IAT Std")
    Flow_IAT_Max: Optional[float] = Field(default=0.0, alias="Flow IAT Max")
    Flow_IAT_Min: Optional[float] = Field(default=0.0, alias="Flow IAT Min")

    class Config:
        populate_by_name = True
        extra = "allow"   # Accept any additional columns from the real dataset


class SimulateRequest(BaseModel):
    """Simple simulation request — just pick an attack type to generate."""
    attack_type: str = Field(
        default="DDoS",
        description="One of: BENIGN, DDoS, DoS GoldenEye, PortScan, FTP-Patator, "
                    "SSH-Patator, Web Attack – Brute Force, Heartbleed, Botnet"
    )
    count: int = Field(default=1, ge=1, le=100)


# ── Responses ─────────────────────────────────────────────────────────────────

class PredictionResponse(BaseModel):
    attack_type: str
    priority: str
    confidence: float
    risk_score: float
    action: str
    timestamp: str
    is_benign: bool


class AlertResponse(BaseModel):
    id: int
    timestamp: str
    attack_type: str
    priority: str
    confidence: float
    risk_score: float
    action: str
    is_benign: bool


class MetricsResponse(BaseModel):
    total_alerts: int
    high: int
    medium: int
    low: int
    benign_count: int
    attack_count: int
    false_positive_estimate: int
    fpr_estimate: float
    precision_estimate: float
    label_distribution: dict


class HealthResponse(BaseModel):
    status: str
    model_loaded: bool
    alert_count: int
