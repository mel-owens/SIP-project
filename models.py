from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, func
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
from app.database import Base

class Email(Base):
    __tablename__ = "emails"

    id = Column(Integer, primary_key=True, index=True)
    sender = Column(String, index=True)
    subject = Column(String)
    body = Column(Text)
    verdict = Column(String, index=True)     # Phishing | Suspicious | Legitimate
    risk_score = Column(Integer)             # 0..100
    flagged_keywords = Column(Text)          # comma-separated list for simplicity
    created_at = Column(DateTime, default=lambda: 
                        datetime.now(timezone.utc), index=True)

    urls = relationship("Url", back_populates="email", 
        cascade="all, delete-orphan", passive_deletes=True,
            order_by="desc(Url.created_at)",)

class Url(Base):
    __tablename__ = "urls"

    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(Integer, ForeignKey("emails.id", ondelete="CASCADE"), index=True, nullable=False,)
 
    risk_score = Column(Integer, default=0)  # e.g. 0 = safe, 100 = high risk
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)
       
    
    url = Column(Text, index=True)
    email = relationship("Email", back_populates="urls")

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True)
    action = Column(String)                  # e.g., ANALYZE_EMAIL
    email_id = Column(Integer, index=True, nullable=True)
    detail = Column(Text)                    # free-form text/JSON
    created_at = Column(DateTime, default=datetime.utcnow, index=True)