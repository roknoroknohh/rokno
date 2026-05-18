#!/usr/bin/env python3
# tech_detect.py - Detect technologies from response

import re


class TechDetect:
    def __init__(self, target_url: str):
        self.target = target_url

    def detect(self, html: str = "", headers: dict = None) -> list:
        """Detect technologies from HTML and headers."""
        if headers is None:
            headers = {}
        detected = []
        text = (html + " " + str(headers)).lower()

        signatures = {
            "WordPress": ["/wp-content/", "wp-includes", "wordpress"],
            "Drupal": ["drupal", "/sites/default/"],
            "Joomla": ["joomla", "/media/jui/"],
            "React": ["react", "data-reactroot"],
            "Vue.js": ["vue.js", "__vue__"],
            "Angular": ["angular", "ng-app"],
            "jQuery": ["jquery"],
            "Bootstrap": ["bootstrap"],
            "Laravel": ["laravel", "laravel_session"],
            "Django": ["django", "csrftoken"],
            "Flask": ["werkzeug"],
            "Express.js": ["express"],
            "Nginx": ["nginx"],
            "Apache": ["apache"],
            "Cloudflare": ["cloudflare", "cf-ray"],
            "PHP": ["php", "x-powered-by: php"],
            "ASP.NET": ["asp.net", "__viewstate"],
            "Ruby on Rails": ["rails", "x-request-id"],
        }

        for tech, signs in signatures.items():
            for sign in signs:
                if sign in text:
                    detected.append(tech)
                    break

        return list(set(detected))
