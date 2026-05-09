from __future__ import annotations

from fastapi import APIRouter, Depends, File, UploadFile

from ..deps import get_state
from ...models import ApiEnvelope, InstrumentRequest, ProtocolAnalyzeRequest, RiskAnalyzeRequest, RiskPreviewRequest, SeedGenerateRequest
from ...state import AppState

router = APIRouter(tags=['offline'])


@router.post('/api/v1/offline/protocol/analyze', response_model=ApiEnvelope)
def analyze_protocol(req: ProtocolAnalyzeRequest, state: AppState = Depends(get_state)) -> ApiEnvelope:
    return ApiEnvelope(data=state.local_client.analyze_protocol(req), msg='protocol extracted')


@router.post('/api/v1/offline/seeds/generate', response_model=ApiEnvelope)
def generate_seeds(req: SeedGenerateRequest, state: AppState = Depends(get_state)) -> ApiEnvelope:
    return ApiEnvelope(data=state.local_client.generate_seeds(req), msg='seeds generated')


@router.post('/api/v1/offline/risk/analyze', response_model=ApiEnvelope)
def analyze_risk(req: RiskAnalyzeRequest, state: AppState = Depends(get_state)) -> ApiEnvelope:
    return ApiEnvelope(data=state.local_client.analyze_risk(req), msg='risk analysis generated')


@router.post('/api/v1/offline/risk/preview', response_model=ApiEnvelope)
def preview_risk(req: RiskPreviewRequest, state: AppState = Depends(get_state)) -> ApiEnvelope:
    return ApiEnvelope(data=state.local_client.preview_risk(req), msg='risk analysis preview')


@router.post('/api/v1/offline/risk/upload', response_model=ApiEnvelope)
async def upload_risk_result(file: UploadFile = File(...), state: AppState = Depends(get_state)) -> ApiEnvelope:
    payload = await file.read()
    result = state.instrument_service.save_uploaded_analysis(file.filename or 'final_analysis.json', payload)
    return ApiEnvelope(data=result, msg='risk result uploaded')


@router.post('/api/v1/offline/instrument', response_model=ApiEnvelope)
def instrument_source(req: InstrumentRequest, state: AppState = Depends(get_state)) -> ApiEnvelope:
    return ApiEnvelope(data=state.local_client.instrument_source(req), msg='instrumentation complete')
