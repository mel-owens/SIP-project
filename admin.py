from sqladmin import Admin, ModelView
from app.models import Email, Url, AuditLog

class EmailAdmin(ModelView, model=Email):
    column_list = [Email.id, Email.created_at, Email.sender, Email.subject, Email.verdict, Email.risk_score]
    column_searchable_list = [Email.sender, Email.subject]
    column_sortable_list = [Email.created_at, Email.risk_score]
    name_plural = "Emails"

class UrlAdmin(ModelView, model=Url):
    column_list = [Url.id, Url.email_id, Url.url]
    column_searchable_list = [Url.url]

class AuditAdmin(ModelView, model=AuditLog):
    column_list = [AuditLog.id, AuditLog.created_at, AuditLog.action, AuditLog.email_id]
    column_searchable_list = [AuditLog.action]

def init_admin(app, engine):
    admin = Admin(app, engine, title="Tailored Learning – Admin")
    admin.add_view(EmailAdmin)
    admin.add_view(UrlAdmin)
    admin.add_view(AuditAdmin)
