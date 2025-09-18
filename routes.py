from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database import get_db
from app import models
from app.schemas import EmailIn, EmailOut
from app.parser import parse_email

router = APIRouter()

@router.post("/analyze-email/", response_model=dict)
def analyze_email(payload: EmailIn, db: Session = Depends(get_db)):
    # 1) Run parser
    parsed = parse_email(payload.model_dump())
    urls = parsed.get("urls", [])
    flags = parsed.get("flagged_keywords", [])
    score = int(parsed.get("risk_score", 0))
    verdict = parsed.get("verdict", "Legitimate")

    # 2) Save Email
    email = models.Email(
        sender=payload.sender,
        subject=payload.subject,
        body=payload.body,
        verdict=verdict,
        risk_score=score,
        flagged_keywords=",".join(flags),
    )
    db.add(email)
    db.flush()  # get email.id before commit

    # 3) Save URLs
    for u in urls:
        db.add(models.Url(email_id=email.id, url=u))

    # 4) Audit
    db.add(models.AuditLog(action="ANALYZE_EMAIL", email_id=email.id, detail=f"score={score} verdict={verdict}"))

    db.commit()
    db.refresh(email)

    return {
        "analysis": {
            "email_id": email.id,
            "sender": email.sender,
            "subject": email.subject,
            "urls": urls,
            "flagged_keywords": flags,
            "risk_score": score,
            "verdict": verdict,
        }
    }

@router.get("/emails", response_model=dict)
def list_emails(db: Session = Depends(get_db)):
    rows = db.query(models.Email).order_by(models.Email.created_at.desc()).limit(50).all()
    items = [
        {"id": r.id, "sender": r.sender, "subject": r.subject, "verdict": r.verdict, "risk": r.risk_score}
        for r in rows
    ]
    return {"items": items}

@router.get("/emails/{email_id}", response_model=EmailOut)
def get_email(email_id: int, db: Session = Depends(get_db)):
    r = db.query(models.Email).filter(models.Email.id == email_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Email not found")
    urls = [u.url for u in db.query(models.Url).filter(models.Url.email_id == email_id).all()]
    flags = r.flagged_keywords.split(",") if r.flagged_keywords else []
    return EmailOut(
        id=r.id,
        sender=r.sender,
        subject=r.subject,
        verdict=r.verdict,
        risk_score=r.risk_score,
        urls=urls,
        flagged_keywords=flags,
    )

# Optional alias for your current Dashboard call
@router.get("/recent", response_model=dict, operation_id="recent_emails_get")
def recent_emails(db: Session = Depends(get_db)):
    rows = db.query(models.Email).order_by(models.Email.created_at.desc()).limit(10).all()
    items = [
        {"id": r.id, "sender": r.sender, "subject": r.subject, "verdict": r.verdict, "risk": r.risk_score}
        for r in rows
    ]
    return {"items": items}
