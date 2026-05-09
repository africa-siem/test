"""SIEM Africa - Vues About.

Page de presentation du projet :
  - 4 pays cibles (Cameroun, Gabon, Congo, RDC)
  - Stats globales du SIEM
  - Architecture
  - Equipe
"""
from django.contrib.auth.decorators import login_required
from django.shortcuts import render

from core.models import Alert, Signature, AISignatureCache


COUNTRIES = [
    {
        "code": "CM",
        "name": "Cameroun",
        "flag": "🇨🇲",
        "capital": "Yaounde",
        "population": "27 millions",
        "tech_hub": "Douala (Silicon Mountain)",
        "context": (
            "Le Cameroun, pays bilingue de l'Afrique centrale, "
            "connait une transformation numerique acceleree. "
            "Plus de 250 000 PME utilisent des services en ligne, "
            "souvent sans protection cyber adequate."
        ),
    },
    {
        "code": "GA",
        "name": "Gabon",
        "flag": "🇬🇦",
        "capital": "Libreville",
        "population": "2,4 millions",
        "tech_hub": "Libreville",
        "context": (
            "Le Gabon investit massivement dans l'economie numerique "
            "via le programme Gabon Egalite. Les PME sont vulnerables : "
            "73% n'ont aucune solution de monitoring de securite."
        ),
    },
    {
        "code": "CG",
        "name": "Republique du Congo",
        "flag": "🇨🇬",
        "capital": "Brazzaville",
        "population": "5,7 millions",
        "tech_hub": "Pointe-Noire",
        "context": (
            "Le Congo developpe son ecosysteme tech autour de Brazzaville "
            "et Pointe-Noire. Les PME du secteur petrolier et logistique "
            "sont des cibles privilegiees pour les ransomwares."
        ),
    },
    {
        "code": "CD",
        "name": "Republique Democratique du Congo",
        "flag": "🇨🇩",
        "capital": "Kinshasa",
        "population": "102 millions",
        "tech_hub": "Kinshasa",
        "context": (
            "La RDC, premier pays francophone d'Afrique en population, "
            "voit emerger des milliers de PME tech a Kinshasa et Lubumbashi. "
            "Le marche local de la cybersecurite est encore en construction."
        ),
    },
]


@login_required
def home(request):
    """Page A propos."""
    # Stats projet (depuis BDD)
    total_alerts = Alert.objects.count()
    total_signatures = Signature.objects.count()
    total_ai_cache = AISignatureCache.objects.count()
    resolved_alerts = Alert.objects.filter(status="RESOLVED").count()

    project_stats = {
        "alerts_processed": total_alerts,
        "signatures_db": total_signatures,
        "ai_analyses": total_ai_cache,
        "resolved": resolved_alerts,
    }

    # Stats sectorielles (chiffres pour le memoire / soutenance)
    africa_stats = {
        "market_2024": "4,84",        # Mds USD
        "market_2033": "25,79",       # Mds USD
        "growth_cagr": "20,6",        # %
        "sme_targeted_pct": 61,       # %
        "avg_breach_cost": "4,88",    # M USD
    }

    return render(request, "about/home.html", {
        "countries": COUNTRIES,
        "project_stats": project_stats,
        "africa_stats": africa_stats,
    })
