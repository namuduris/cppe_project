from __future__ import annotations

import os
from datetime import datetime
from typing import Any

import pandas as pd
from pydantic import BaseModel, Field
from fastapi import FastAPI, Request
from langchain_core.output_parsers import JsonOutputParser
from langchain_core.prompts import PromptTemplate
from langchain_groq import ChatGroq

app = FastAPI(title="Autonomous FinOps & Security Agent", version="1.0.0")

# In-memory quarantine list for demo purposes.
BLOCKED_DEVICES: set[str] = set()

class IncidentAnalysis(BaseModel):
    classification: str = Field(description="One of NORMAL, DOS, BUFFER_OVERFLOW")
    summary: str = Field(description="Two-sentence technical incident summary")


parser = JsonOutputParser(pydantic_object=IncidentAnalysis)

prompt = PromptTemplate.from_template(
    "You are an Autonomous SecOps and FinOps AI Agent. Analyze the following raw IoT network payload: {payload}. "
    "Perform two tasks: 1. Classify the attack type strictly as 'NORMAL', 'DOS', or 'BUFFER_OVERFLOW'. "
    "2. Write a concise, two-sentence summary explaining the attacker's technical intent and how this specific "
    "attack vector drives up hyperscaler cloud ingestion billing. Output your response in strict JSON format "
    "with the keys 'classification' and 'summary'."
)

llm = ChatGroq(
    model="llama-3.1-8b-instant",
    temperature=0,
    api_key=os.getenv("GROQ_API_KEY"),
)
security_chain = prompt | llm | parser


def _normalize_classification(value: Any) -> str:
    classification = str(value).strip().upper()
    if classification in {"NORMAL", "DOS", "BUFFER_OVERFLOW"}:
        return classification
    return "NORMAL"


def _fallback_summary(classification: str, payload: str) -> str:
    preview = payload[:100].replace("\n", " ").replace("\r", " ")
    return (
        f"The payload was heuristically classified as {classification} after LLM processing failed. "
        f"Observed payload preview: {preview}"
    )


def analyze_payload_with_llm(payload: str) -> dict[str, str]:
    try:
        result = security_chain.invoke({"payload": payload})
        classification = _normalize_classification(result.get("classification", "NORMAL"))
        summary = str(result.get("summary", "")).strip() or _fallback_summary(classification, payload)
        return {"classification": classification, "summary": summary}
    except Exception:
        # Keep API resilient even if model credentials/service are unavailable.
        return {
            "classification": "NORMAL",
            "summary": _fallback_summary("NORMAL", payload),
        }


def check_billing_spike() -> dict[str, Any]:
    """
    Mock FinOps check that simulates AWS ingestion cost trend.
    Replace with boto3 Cost Explorer queries in production.
    """
    df = pd.DataFrame(
        {
            "day": pd.date_range(end=datetime.utcnow(), periods=7, freq="D"),
            "ingestion_cost_usd": [12.1, 12.4, 11.9, 12.3, 12.2, 12.5, 37.8],
        }
    )

    baseline = float(df["ingestion_cost_usd"].iloc[:-1].mean())
    latest = float(df["ingestion_cost_usd"].iloc[-1])
    spiking = latest > (baseline * 1.5)

    return {
        "spiking": spiking,
        "latest_cost_usd": round(latest, 2),
        "baseline_cost_usd": round(baseline, 2),
    }


def _extract_payload(event: dict[str, Any]) -> tuple[str, str]:
    payload = (
        event.get("payload")
        or event.get("log")
        or event.get("message")
        or event.get("raw")
        or ""
    )

    src = event.get("src") or event.get("device") or "unknown-device"
    return str(payload), str(src)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/analyze")
async def analyze(request: Request) -> dict[str, Any]:
    body = await request.json()

    # Fluent Bit HTTP output often sends batches; normalize to a list.
    events = body if isinstance(body, list) else [body]
    results: list[dict[str, Any]] = []

    for event in events:
        payload, src = _extract_payload(event)
        llm_result = analyze_payload_with_llm(payload)
        attack_label = llm_result["classification"]
        incident_summary = llm_result["summary"]
        print(f"[INCIDENT REPORT] {incident_summary}")

        billing = check_billing_spike()

        should_block = attack_label in {"DOS", "BUFFER_OVERFLOW"} and billing["spiking"]
        action = "monitor"

        if should_block:
            BLOCKED_DEVICES.add(src)
            action = "block-device-to-reduce-aws-cost"
            print(
                "[AUTO-RESPONSE] Attack detected + billing spike. "
                f"Autonomously blocking compromised IoT device: {src}"
            )

        results.append(
            {
                "source": src,
                "attack_type": attack_label,
                "incident_report": incident_summary,
                "billing": billing,
                "action": action,
                "blocked_devices": sorted(BLOCKED_DEVICES),
            }
        )

    return {
        "received_events": len(events),
        "results": results,
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("agent_api:app", host="0.0.0.0", port=5000, reload=True)
