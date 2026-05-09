"""SIEM Africa - Models miroir des tables M2.

Tous ont managed=False. Le schema est gere par le Module 2.
"""
import json
from django.db import models
from django.conf import settings


# ============================================================================
class SignatureCategory(models.Model):
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True, null=True)

    class Meta:
        db_table = "signature_categories"
        managed = False

    def __str__(self):
        return self.name


# ============================================================================
class Country(models.Model):
    code = models.CharField(max_length=3)
    name = models.CharField(max_length=100)
    region = models.CharField(max_length=100, blank=True, null=True)

    class Meta:
        db_table = "countries"
        managed = False

    def __str__(self):
        return self.name


# ============================================================================
class Signature(models.Model):
    SOURCE_CHOICES = [("wazuh", "Wazuh"), ("snort", "Snort")]
    SEVERITY_CHOICES = [
        ("INFO", "Info"), ("LOW", "Low"), ("MEDIUM", "Medium"),
        ("HIGH", "High"), ("CRITICAL", "Critical"),
    ]

    source = models.CharField(max_length=10, choices=SOURCE_CHOICES)
    rule_id = models.CharField(max_length=20)
    category = models.ForeignKey(SignatureCategory, on_delete=models.PROTECT,
                                 db_column="category_id")
    title = models.CharField(max_length=200)
    description = models.TextField(blank=True, null=True)
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES)
    confidence = models.IntegerField(default=70)
    remediation = models.TextField(blank=True, null=True)

    mitre_tactic_id = models.CharField(max_length=20, blank=True, null=True)
    mitre_technique_id = models.CharField(max_length=20, blank=True, null=True)

    is_enabled = models.BooleanField(default=True)
    is_unknown = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "signatures"
        managed = False
        unique_together = [["source", "rule_id"]]

    def __str__(self):
        return f"[{self.source}] {self.rule_id}"


# ============================================================================
class AISignatureCache(models.Model):
    signature_hash = models.CharField(max_length=64, unique=True)
    source = models.CharField(max_length=10)
    rule_id = models.CharField(max_length=20)
    raw_message = models.TextField(blank=True, null=True)

    ai_description = models.TextField()
    ai_remediation = models.TextField(blank=True, null=True)
    ai_severity = models.CharField(max_length=10)
    ai_mitre_tactic = models.CharField(max_length=20, blank=True, null=True)
    ai_mitre_technique = models.CharField(max_length=20, blank=True, null=True)

    model_used = models.CharField(max_length=50)
    response_time_ms = models.IntegerField(default=0)
    used_count = models.IntegerField(default=0)
    last_used_at = models.DateTimeField(blank=True, null=True)
    is_validated = models.BooleanField(default=False)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "ai_signature_cache"
        managed = False

    def remediation_list(self):
        if not self.ai_remediation:
            return []
        try:
            data = json.loads(self.ai_remediation)
            return data if isinstance(data, list) else [str(data)]
        except (json.JSONDecodeError, TypeError):
            return [self.ai_remediation]


# ============================================================================
class Alert(models.Model):
    STATUS_CHOICES = [
        ("NEW", "Nouvelle"), ("ACKNOWLEDGED", "Vue"),
        ("INVESTIGATING", "En cours"), ("RESOLVED", "Resolue"),
        ("FALSE_POSITIVE", "Faux positif"),
    ]

    alert_uuid = models.CharField(max_length=36, unique=True)
    signature = models.ForeignKey(Signature, on_delete=models.PROTECT,
                                  db_column="signature_id")
    severity = models.CharField(max_length=10)
    confidence = models.IntegerField(default=70)
    title = models.CharField(max_length=200)
    description = models.TextField(blank=True, null=True)

    src_ip = models.CharField(max_length=45, blank=True, null=True)
    dst_ip = models.CharField(max_length=45, blank=True, null=True)
    src_port = models.IntegerField(blank=True, null=True)
    dst_port = models.IntegerField(blank=True, null=True)
    protocol = models.CharField(max_length=20, blank=True, null=True)

    asset_id = models.IntegerField(blank=True, null=True)
    event_count = models.IntegerField(default=1)
    first_seen = models.DateTimeField()
    last_seen = models.DateTimeField()

    ai_status = models.CharField(max_length=20, default="not_required")
    ai_description = models.TextField(blank=True, null=True)
    ai_remediation = models.TextField(blank=True, null=True)
    ai_severity = models.CharField(max_length=10, blank=True, null=True)
    ai_model_used = models.CharField(max_length=50, blank=True, null=True)
    ai_cache = models.ForeignKey(AISignatureCache, on_delete=models.SET_NULL,
                                  blank=True, null=True, db_column="ai_cache_id")
    ai_processed_at = models.DateTimeField(blank=True, null=True)

    enriched_data = models.TextField(blank=True, null=True)
    status = models.CharField(max_length=20, default="NEW", choices=STATUS_CHOICES)

    acknowledged_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL,
        blank=True, null=True, related_name="alerts_acknowledged",
        db_column="acknowledged_by_id",
    )
    acknowledged_at = models.DateTimeField(blank=True, null=True)
    resolved_at = models.DateTimeField(blank=True, null=True)
    resolution_notes = models.TextField(blank=True, null=True)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "alerts"
        managed = False
        ordering = ["-created_at"]

    def __str__(self):
        return f"#{self.id} [{self.severity}] {self.title[:60]}"

    @property
    def severity_color(self):
        return {
            "CRITICAL": "danger", "HIGH": "warning", "MEDIUM": "info",
            "LOW": "success", "INFO": "secondary",
        }.get(self.severity, "secondary")

    @property
    def severity_icon(self):
        return {
            "CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡",
            "LOW": "🟢", "INFO": "⚪",
        }.get(self.severity, "⚪")

    @property
    def ai_badge_text(self):
        return {
            "not_required": "📚 Knowledge Base",
            "pending": "⏳ Analyse en cours",
            "cached": "🤖 AI (cache)",
            "fresh": "🤖 AI Analysis",
            "failed": "⚠️ AI Failed",
        }.get(self.ai_status, "?")

    @property
    def ai_badge_color(self):
        return {
            "not_required": "secondary", "pending": "warning",
            "cached": "info", "fresh": "primary", "failed": "danger",
        }.get(self.ai_status, "secondary")

    def remediation_list(self):
        text = self.ai_remediation or self.signature.remediation if self.signature else None
        if not text:
            return []
        try:
            data = json.loads(text)
            return data if isinstance(data, list) else [str(data)]
        except (json.JSONDecodeError, TypeError):
            return [t.strip() for t in text.splitlines() if t.strip()]

    def get_description(self):
        """Description la plus utile (priorite a l'IA, fallback BDD)."""
        return self.ai_description or self.description or "(pas de description)"


# ============================================================================
class AlertFilter(models.Model):
    signature = models.ForeignKey(Signature, on_delete=models.CASCADE,
                                  db_column="signature_id", blank=True, null=True)
    action = models.CharField(max_length=20, default="IGNORE")
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL,
        blank=True, null=True, db_column="created_by_id",
    )

    class Meta:
        db_table = "alert_filters"
        managed = False


# ============================================================================
class Setting(models.Model):
    key = models.CharField(max_length=100, primary_key=True)
    value = models.TextField(blank=True, null=True)
    description = models.TextField(blank=True, null=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "settings"
        managed = False

    def __str__(self):
        return f"{self.key} = {self.value}"

    @classmethod
    def get(cls, key, default=None):
        try:
            return cls.objects.get(key=key).value
        except cls.DoesNotExist:
            return default

    @classmethod
    def get_bool(cls, key, default=False):
        val = (cls.get(key) or "").strip().lower()
        if val in ("true", "1", "yes", "on"):
            return True
        if val in ("false", "0", "no", "off"):
            return False
        return default

    @classmethod
    def set(cls, key, value, description=None):
        obj, created = cls.objects.get_or_create(
            key=key, defaults={"value": str(value), "description": description}
        )
        if not created:
            obj.value = str(value)
            if description:
                obj.description = description
            obj.save()
        return obj


# ============================================================================
class KpiHistory(models.Model):
    snapshot_date = models.DateField()
    metric_name = models.CharField(max_length=100)
    metric_value = models.FloatField()
    country = models.ForeignKey(Country, on_delete=models.SET_NULL,
                                blank=True, null=True, db_column="country_id")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "kpi_history"
        managed = False
        ordering = ["-snapshot_date"]


# ============================================================================
class AuditLog(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL,
                             blank=True, null=True, db_column="user_id")
    action = models.CharField(max_length=100)
    resource_type = models.CharField(max_length=50)
    resource_id = models.CharField(max_length=50, blank=True, null=True)
    details = models.TextField(blank=True, null=True)
    level = models.CharField(max_length=10, default="INFO")
    ip_address = models.CharField(max_length=45, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "audit_log"
        managed = False
        ordering = ["-created_at"]


# ============================================================================
class EmailLog(models.Model):
    recipient = models.CharField(max_length=255)
    subject = models.CharField(max_length=500, blank=True, null=True)
    status = models.CharField(max_length=20)
    error_message = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "email_logs"
        managed = False
        ordering = ["-created_at"]
