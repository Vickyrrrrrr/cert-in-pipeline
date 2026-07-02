"""Pydantic data models for pipeline state."""

from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime


class TargetInfo(BaseModel):
    domain: str
    scope: list[str] = Field(default_factory=list)
    exclude: list[str] = Field(default_factory=list)


class ModelConfig(BaseModel):
    name: str = "ollama/qwen2.5:7b"
    api_base: Optional[str] = None
    api_key: Optional[str] = None
    temperature: float = 0.1
    max_tokens: int = 4096
    timeout: int = 120


class StepResult(BaseModel):
    skill: str
    input: dict
    output: Optional[dict] = None
    raw_response: Optional[str] = None
    status: str = "pending"
    error: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.now)


class PipelineState(BaseModel):
    target: TargetInfo
    model: ModelConfig
    mode: str = "benchmark"
    steps: dict[str, StepResult] = Field(default_factory=dict)
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
