from pydantic import BaseModel
from typing import List

class EmailIn(BaseModel):
    sender: str
    subject: str
    body: str

class EmailOut(BaseModel):
    id: int
    sender: str
    subject: str
    verdict: str
    risk_score: int
    urls: List[str]
    flagged_keywords: List[str]
