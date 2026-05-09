"""SIEM Africa - Middleware theme light/dark."""
from django.utils.deprecation import MiddlewareMixin


class ThemeMiddleware(MiddlewareMixin):
    """Determine le theme actif a partir de l'user ou du cookie."""

    DEFAULT_THEME = "light"
    VALID_THEMES = {"light", "dark"}

    def process_request(self, request):
        theme = self.DEFAULT_THEME

        user = getattr(request, "user", None)
        if user and user.is_authenticated:
            pref = getattr(user, "theme_preference", None)
            if pref in self.VALID_THEMES:
                theme = pref

        cookie_theme = request.COOKIES.get("theme")
        if cookie_theme in self.VALID_THEMES:
            theme = cookie_theme

        request.theme = theme
        return None
