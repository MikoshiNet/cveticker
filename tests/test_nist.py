# pylint: disable=missing-ignore
import pytest
import os

from modules.nist.nist import parse_nist_html, get_content_for_output, format_nist_api_response, get_nist_api_cves

os.environ['CVETICKER_MODE'] = 'testing'


MOCK_CVE = "CVE-2024-32109"
MOCK_NIST_HTML_RESPONSE = """
<div class="col-lg-3 col-sm-6">\r\n\t\t\t\t\t\t\t\t\t\t\t\t<span><strong>Base\r\n\t\t\t\t\t\t\t\t\t\t\t\t\t\tScore:</strong>&nbsp;<span class="severityDetail"> <a\r\n\t\t\t\t\t\t\t\t\t\t\t\t\t\tid="Cvss3CnaCalculatorAnchor"\r\n\t\t\t\t\t\t\t\t\t\t\t\t\t\thref="/vuln-metrics/cvss/v3-calculator?name=CVE-2024-32109&amp;vector=AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N&amp;version=3.1&amp;source=Patchstack"\r\n\t\t\t\t\t\t\t\t\t\t\t\t\t\tdata-testid="vuln-cvss3-cna-panel-score"\r\n\t\t\t\t\t\t\t\t\t\t\t\t\t\tclass="label label-warning">4.3 MEDIUM</a></span></span>\r\n\t\t\t\t\t\t\t\t\t\t\t</div>
 \r\n\t\t\t\t\t\t\t\t\t\t\t"""

# this might be deprecated soon
MOCK_DB_DATA = {"resultsPerPage": 4, "startIndex": 0, "totalResults": 4, "format": "NVD_CVE", "version": "2.0", "timestamp": "2024-04-11T16:24:50.233", "vulnerabilities": [{"cve": {"id": "CVE-2023-29483", "sourceIdentifier": "cve@mitre.org", "published": "2024-04-11T14:15:12.010", "lastModified": "2024-04-11T14:15:12.010", "vulnStatus": "Received", "descriptions": [{"lang": "en", "value": "eventlet before 0.35.2, as used in dnspython before 2.6.0, allows remote attackers to interfere with DNS name resolution by quickly sending an invalid packet from the expected IP address and source port, aka a \"TuDoor\" attack. In other words, dnspython does not have the preferred behavior in which the DNS name resolution algorithm would proceed, within the full time window, in order to wait for a valid packet. NOTE: dnspython 2.6.0 is unusable for a different reason that was addressed in 2.6.1."}], "metrics": {}, "references": [{"url": "https://github.com/eventlet/eventlet/issues/913", "source": "cve@mitre.org"}, {"url": "https://github.com/eventlet/eventlet/releases/tag/v0.35.2", "source": "cve@mitre.org"}, {"url": "https://github.com/rthalley/dnspython/issues/1045", "source": "cve@mitre.org"}, {"url": "https://github.com/rthalley/dnspython/releases/tag/v2.6.0", "source": "cve@mitre.org"}, {"url": "https://security.snyk.io/vuln/SNYK-PYTHON-DNSPYTHON-6241713", "source": "cve@mitre.org"}, {"url": "https://www.dnspython.org/", "source": "cve@mitre.org"}]}}, {"cve": {"id": "CVE-2024-32105", "sourceIdentifier": "audit@patchstack.com", "published": "2024-04-11T14:15:12.143", "lastModified": "2024-04-11T14:15:12.143", "vulnStatus": "Received", "descriptions": [{"lang": "en", "value": "Cross-Site Request Forgery (CSRF) vulnerability in ELEXtensions ELEX WooCommerce Dynamic Pricing and Discounts.This issue affects ELEX WooCommerce Dynamic Pricing and Discounts: from n/a through 2.1.2.\n\n"}], "metrics": {"cvssMetricV31": [{"source": "audit@patchstack.com", "type": "Secondary", "cvssData": {"version": "3.1", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N", "attackVector": "NETWORK", "attackComplexity": "LOW", "privilegesRequired": "NONE", "userInteraction": "REQUIRED", "scope": "UNCHANGED", "confidentialityImpact": "NONE", "integrityImpact": "LOW", "availabilityImpact": "NONE", "baseScore": 4.3, "baseSeverity": "MEDIUM"}, "exploitabilityScore": 2.8, "impactScore": 1.4}]}, "weaknesses": [{"source": "audit@patchstack.com", "type": "Secondary", "description": [{"lang": "en", "value": "CWE-352"}]}], "references": [{"url": "https://patchstack.com/database/vulnerability/elex-woocommerce-dynamic-pricing-and-discounts/wordpress-elex-woocommerce-dynamic-pricing-and-discounts-plugin-2-1-2-cross-site-request-forgery-csrf-vulnerability-2?_s_id=cve", "source": "audit@patchstack.com"}]}}, {"cve": {"id": "CVE-2024-0881", "sourceIdentifier": "contact@wpscan.com", "published": "2024-04-11T16:15:24.800", "lastModified": "2024-04-11T16:15:24.800", "vulnStatus": "Received", "descriptions": [{"lang": "en", "value": "The Post Grid, Form Maker, Popup Maker, WooCommerce Blocks, Post Blocks, Post Carousel  WordPress plugin before 2.2.76 does not prevent password protected posts from being displayed in the result of some unauthenticated AJAX actions, allowing unauthenticated users to read such posts"}], "metrics": {}, "references": [{"url": "https://wpscan.com/vulnerability/e460e926-6e9b-4e9f-b908-ba5c9c7fb290/", "source": "contact@wpscan.com"}]}}, {"cve": {"id": "CVE-2024-31678", "sourceIdentifier": "cve@mitre.org", "published": "2024-04-11T16:15:25.127", "lastModified": "2024-04-11T16:15:25.127", "vulnStatus": "Received", "descriptions": [{"lang": "en", "value": "Sourcecodester Loan Management System v1.0 is vulnerable to SQL Injection via the \"password\" parameter in the \"login.php\" file."}], "metrics": {}, "references": [{"url": "https://github.com/CveSecLook/cve/issues/10", "source": "cve@mitre.org"}]}}]}

MOCK_NIST_RESPONSE = {
    "resultsPerPage": 1,
    "startIndex": 0,
    "totalResults": 1,
    "format": "NVD_CVE",
    "version": "2.0",
    "timestamp": "2024-04-04T02:41:39.950",
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2024-0367",
                "sourceIdentifier": "security@wordfence.com",
                "published": "2024-03-30T05:15:34.243",
                "lastModified": "2024-04-01T01:12:59.077",
                "vulnStatus": "Awaiting Analysis",
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "The Unlimited Elements For Elementor plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the link field of an installed widget (e.g., 'Button Link') in all versions up to, and including, 1.5.96 due to insufficient input sanitization and output escaping on user supplied attributes. This makes it possible for authenticated attackers, with contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page."
                    },
                    {
                        "lang": "es",
                        "value": "El complemento Unlimited Elements For Elementor para WordPress es vulnerable a cross-site scripting almacenado a trav\u00e9s del campo de enlace de un widget instalado (por ejemplo, 'Enlace de bot\u00f3n') en todas las versiones hasta la 1.5.96 incluida debido a una sanitizaci\u00f3n de entrada insuficiente y salida que se escapa en los atributos proporcionados por el usuario. Esto hace posible que atacantes autenticados, con acceso de nivel de colaborador y superior, inyecten scripts web arbitrarios en p\u00e1ginas que se ejecutar\u00e1n cada vez que un usuario acceda a una p\u00e1gina inyectada."
                    }
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "source": "security@wordfence.com",
                            "type": "Secondary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N",
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                                "privilegesRequired": "LOW",
                                "userInteraction": "NONE",
                                "scope": "CHANGED",
                                "confidentialityImpact": "LOW",
                                "integrityImpact": "LOW",
                                "availabilityImpact": "NONE",
                                "baseScore": 6.4,
                                "baseSeverity": "MEDIUM"
                            },
                            "exploitabilityScore": 3.1,
                            "impactScore": 2.7
                        }
                    ]
                },
                "references": [
                    {
                        "url": "https://plugins.trac.wordpress.org/changeset?sfp_email=&sfph_mail=&reponame=&old=3045122%40unlimited-elements-for-elementor&new=3045122%40unlimited-elements-for-elementor&sfp_email=&sfph_mail=",
                        "source": "security@wordfence.com"
                    },
                    {
                        "url": "https://www.wordfence.com/threat-intel/vulnerabilities/id/47853750-0bf1-4df3-9c56-c6852543cfad?source=cve",
                        "source": "security@wordfence.com"
                    }
                ]
            }
        }
    ]
}

MOCK_FORMATTED_RESPONSE = {
    "CVE-2024-0367": {
        "cvss_score": 6.4,
        "released_date": "2024-03-30T05:15:34.243",
        "modified_date": "2024-04-01T01:12:59.077",
        "status": "Awaiting Analysis",
        "tags": []
    }
}

def test_parse_nist_html():
    assert parse_nist_html(html=MOCK_NIST_HTML_RESPONSE, cve=MOCK_CVE) == '4.3'

# def test_get_content_for_output():
    # for i in range(MOCK_DB_DATA['totalResults']):
        # assert get_content_for_output(MOCK_DB_DATA, i)
# 

def test_format_nist_api_response():
    assert MOCK_FORMATTED_RESPONSE == format_nist_api_response(MOCK_NIST_RESPONSE)

def test_get_nist_api_cves():
    try:
        get_nist_api_cves()
        no_exception = True
    except Exception:
        no_exception = False

    assert no_exception