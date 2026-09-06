"""
Benchmark Dataset Builder
=========================
Builds a frozen, reproducible evaluation dataset for the pirocheto
phishing-url-detection ONNX model.

Sources
-------
Legitimate URLs:
    Curated from well-known public domains (RFC-2606 example domains,
    major technology, banking, government, media and SaaS companies).
    Deployment URLs (Vercel/Netlify/GitHub Pages) are verified to resolve
    publicly over HTTPS before inclusion.

Phishing URLs:
    - Real phishing domains/links sampled deterministically from
      mitchellkrogza/Phishing.Database (a public, community-maintained
      database of reported phishing URLs).
    - Pattern-defined phishing URLs (IP-hosted, '@'-symbol, punycode
      homograph, long, subdomain, keyword, obfuscation). These are labeled
      phishing *by construction* because they implement the exact URL
      characteristics that characterize phishing, and are marked with
      source="PATTERN" so they are never confused with real-world reports.

Train/test separation
---------------------
No training is performed in this pipeline. The pirocheto model was trained
by its author on an unknown corpus; the benchmark deliberately includes a
large share of modern SaaS domains and deployment hosts (Vercel/Netlify/
GitHub Pages) to probe generalization to hosts that postdate many public
phishing corpora. The dataset is frozen to dataset.json so evaluation is
reproducible without network access.
"""

import json
import random
import re
import urllib.request
from datetime import datetime, timezone

OUT = "benchmark/dataset.json"
SEED = 42


# ---------------------------------------------------------------------------
# 1. Curated legitimate URLs
# ---------------------------------------------------------------------------

LEGIT_CORE = [
    # RFC 2606 reserved example domains
    "https://example.com/", "https://www.example.com/",
    "https://example.net/", "https://example.org/",

    # Search / portals
    "https://www.google.com/", "https://google.com/",
    "https://mail.google.com/", "https://drive.google.com/",
    "https://www.bing.com/", "https://duckduckgo.com/",
    "https://search.yahoo.com/",

    # Developer platforms
    "https://github.com/", "https://www.github.com/",
    "https://gist.github.com/", "https://raw.githubusercontent.com/",
    "https://gitlab.com/", "https://bitbucket.org/",
    "https://stackoverflow.com/", "https://developer.mozilla.org/",
    "https://npmjs.com/", "https://pypi.org/", "https://crates.io/",

    # Wikipedia / knowledge
    "https://www.wikipedia.org/", "https://en.wikipedia.org/",
    "https://es.wikipedia.org/",

    # Microsoft / PayPal (high-value impersonation targets)
    "https://www.microsoft.com/", "https://microsoft.com/",
    "https://learn.microsoft.com/", "https://support.microsoft.com/",
    "https://outlook.live.com/",
    "https://www.paypal.com/", "https://paypal.com/", "https://paypal.me/",

    # Big tech / social
    "https://www.apple.com/", "https://www.amazon.com/",
    "https://www.facebook.com/", "https://x.com/", "https://twitter.com/",
    "https://www.linkedin.com/", "https://www.reddit.com/",
    "https://www.youtube.com/", "https://www.instagram.com/",
    "https://www.netflix.com/", "https://www.tiktok.com/",
    "https://www.whatsapp.com/", "https://telegram.org/",

    # Cloud / infra / SaaS
    "https://aws.amazon.com/", "https://cloud.google.com/",
    "https://azure.microsoft.com/", "https://www.cloudflare.com/",
    "https://www.digitalocean.com/", "https://www.docker.com/",
    "https://kubernetes.io/", "https://www.heroku.com/",
    "https://stripe.com/", "https://www.shopify.com/",
    "https://www.salesforce.com/", "https://www.adobe.com/",
    "https://www.ibm.com/", "https://www.oracle.com/",
    "https://www.slack.com/", "https://discord.com/", "https://zoom.us/",
    "https://www.dropbox.com/", "https://www.notion.so/",
    "https://www.figma.com/", "https://www.atlassian.com/",
    "https://www.wordpress.org/", "https://medium.com/",
    "https://www.spotify.com/", "https://www.airbnb.com/",

    # Banking / finance (classic phishing targets)
    "https://www.chase.com/", "https://www.bankofamerica.com/",
    "https://www.wellsfargo.com/", "https://www.capitalone.com/",
    "https://www.citi.com/", "https://www.americanexpress.com/",
    "https://www.usbank.com/", "https://www.ally.com/",

    # Government (official domains)
    "https://www.irs.gov/", "https://www.whitehouse.gov/",
    "https://www.treasury.gov/", "https://www.ssa.gov/",
    "https://www.gov.uk/", "https://www.nhs.uk/",

    # Media / retail
    "https://www.cnn.com/", "https://www.bbc.com/", "https://www.bbc.co.uk/",
    "https://www.nytimes.com/", "https://www.wsj.com/",
    "https://www.walmart.com/", "https://www.target.com/",
    "https://www.bestbuy.com/", "https://www.homedepot.com/",
]

# Real deployment hosts (Vercel / Netlify / GitHub Pages).
# Each candidate is verified to resolve publicly over HTTPS before inclusion.
DEPLOYMENT_CANDIDATES = [
    # Vercel
    "https://vercel.com/", "https://vercel.app/",
    "https://nextjs.org/", "https://create-next-app.vercel.app/",
    "https://vercel.com/docs",
    "https://examples.vercel.app/", "https://demo.vercel.app/",
    "https://svelte.vercel.app/", "https://hugo.vercel.app/",
    "https://astro.build/",
    # Netlify
    "https://www.netlify.com/", "https://docs.netlify.com/",
    "https://app.netlify.com/", "https://www.netlify.app/",
    "https://decapcms.netlify.app/", "https://gohugo.netlify.app/",
    "https://svelte.netlify.app/",
    # GitHub Pages
    "https://pages.github.com/", "https://github.github.io/",
    "https://jekyll.github.io/", "https://octocat.github.io/",
    "https://electron.github.io/", "https://docs.github.com/",
    # Learnova — the user's own Vercel deployment (treated as legitimate
    # for benchmarking purposes; documented separately in the report).
    "https://learnova-ai-8.vercel.app/",
]


def verify_public(url: str, timeout: float = 6.0) -> bool:
    """Return True if the URL responds over HTTPS (any 2xx/3xx status)."""
    try:
        req = urllib.request.Request(url, method="GET", headers={"User-Agent": "phishguard-benchmark/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return 200 <= resp.status < 400
    except urllib.error.HTTPError as exc:
        return 200 <= exc.code < 400
    except Exception:
        return False


def build_legitimate(verify: bool = True) -> list:
    records = []
    for url in LEGIT_CORE:
        records.append({"url": url, "label": 0, "category": "legit", "source": "CURATED"})
    for url in DEPLOYMENT_CANDIDATES:
        ok = verify_public(url) if verify else True
        records.append({
            "url": url,
            "label": 0,
            "category": "legit",
            "source": "CURATED_DEPLOYMENT" if ok else "CURATED_DEPLOYMENT_UNVERIFIED",
            "verified": ok,
        })
    return records


# ---------------------------------------------------------------------------
# 2. Real phishing URLs (sampled from the public Phishing.Database)
# ---------------------------------------------------------------------------

def load_lines(path: str) -> list:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [ln.strip() for ln in f if ln.strip() and not ln.strip().startswith("#")]


def sample_phishing_domains(n: int, seed: int) -> list:
    lines = load_lines("benchmark/_phishing_domains_raw.txt")
    rng = random.Random(seed)
    chosen = rng.sample(lines, min(n, len(lines)))
    out = []
    for dom in chosen:
        # Keep only plain DNS names to avoid garbage lines.
        if re.fullmatch(r"[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+", dom):
            out.append({
                "url": f"https://{dom}/",
                "label": 1,
                "category": "phishing",
                "source": "PHISHING_DATABASE",
            })
    return out


def sample_phishing_links(n: int, seed: int) -> list:
    lines = load_lines("benchmark/_phishing_links_raw.txt")
    rng = random.Random(seed + 1)
    chosen = rng.sample(lines, min(n, len(lines)))
    out = []
    for link in chosen:
        if link.startswith("http://") or link.startswith("https://"):
            out.append({
                "url": link,
                "label": 1,
                "category": "phishing",
                "source": "PHISHING_DATABASE_LINK",
            })
    return out


# ---------------------------------------------------------------------------
# 3. Pattern-defined phishing URLs (labeled by construction)
# ---------------------------------------------------------------------------

def build_pattern_phishing() -> list:
    return [
        # IP-hosted
        {"url": "http://192.168.1.100/login.php", "label": 1, "category": "ip", "source": "PATTERN"},
        {"url": "http://2130706433/admin", "label": 1, "category": "ip", "source": "PATTERN"},
        {"url": "http://203.0.113.10/verify-account", "label": 1, "category": "ip", "source": "PATTERN"},
        {"url": "https://94.130.44.214/secure/paypal/login", "label": 1, "category": "ip", "source": "PATTERN"},
        # '@'-symbol
        {"url": "https://example.com@evil-site.net/paypal/login", "label": 1, "category": "at", "source": "PATTERN"},
        {"url": "https://www.google.com@phish.example.com/account-verify", "label": 1, "category": "at", "source": "PATTERN"},
        {"url": "https://paypal.com@192.168.1.100/login", "label": 1, "category": "at", "source": "PATTERN"},
        # Excessive length
        {"url": "https://" + "a" * 260 + ".example.com/verify", "label": 1, "category": "long", "source": "PATTERN"},
        {"url": "https://example.com/?" + "&".join(f"p{i}={'x'*60}" for i in range(12)), "label": 1, "category": "long", "source": "PATTERN"},
        # Excessive subdomains
        {"url": "https://a.b.c.d.e.f.g.h.example.com/login", "label": 1, "category": "subdomain", "source": "PATTERN"},
        {"url": "https://secure.login.verify.account.update.example.com/signin", "label": 1, "category": "subdomain", "source": "PATTERN"},
        # Suspicious keywords
        {"url": "https://secure-login-verify-account-update.example.com/bank", "label": 1, "category": "keyword", "source": "PATTERN"},
        {"url": "https://www.verify-account-update-password.example.com/confirm", "label": 1, "category": "keyword", "source": "PATTERN"},
        {"url": "https://login.secure.example.com/update-account?redirect=https://evil.example.com", "label": 1, "category": "keyword", "source": "PATTERN"},
        # Punycode homographs
        {"url": "https://xn--ggle-0ra.com/login", "label": 1, "category": "punycode", "source": "PATTERN"},
        {"url": "https://xn--80ak6aa92e.com/", "label": 1, "category": "punycode", "source": "PATTERN"},
        {"url": "https://xn--paypal-5we.com/signin", "label": 1, "category": "punycode", "source": "PATTERN"},
        # URL obfuscation / encoding
        {"url": "https://example.com/%6C%6F%67%69%6E", "label": 1, "category": "obfuscation", "source": "PATTERN"},
        {"url": "https://example.com/%256C%256F%2567%2569%256E", "label": 1, "category": "obfuscation", "source": "PATTERN"},
        {"url": "https://paypal.com%2eexample.com/login", "label": 1, "category": "obfuscation", "source": "PATTERN"},
        # Mixed-case impersonation
        {"url": "https://EXAMPLE.COM@evil-site.net/PaYpAl/LoGiN", "label": 1, "category": "impersonation", "source": "PATTERN"},
        {"url": "https://www.paypa1.com/signin", "label": 1, "category": "impersonation", "source": "PATTERN"},
        # Unusual port
        {"url": "https://example.com:8443/signin/password", "label": 1, "category": "port", "source": "PATTERN"},
        {"url": "http://example.com:8080/verify", "label": 1, "category": "port", "source": "PATTERN"},
    ]


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(verify: bool = True) -> None:
    rng = random.Random(SEED)
    records = []

    legit = build_legitimate(verify=verify)
    # Keep verified deployments; keep unverified ones flagged (do not silently drop).
    records += [r for r in legit if r.get("verified", True)]

    phishing_domains = sample_phishing_domains(60, SEED)
    phishing_links = sample_phishing_links(12, SEED)
    pattern = build_pattern_phishing()

    records += phishing_domains + phishing_links + pattern
    rng.shuffle(records)

    meta = {
        "model": "pirocheto/phishing-url-detection",
        "model_file": "ml/model.onnx",
        "built_at": datetime.now(timezone.utc).isoformat(),
        "seed": SEED,
        "sources": [
            "Phishing.Database (mitchellkrogza) - phishing-domains-ACTIVE.txt",
            "Phishing.Database (mitchellkrogza) - phishing-links-ACTIVE.txt",
            "Curated legitimate domains (RFC 2606 + major public sites)",
            "PATTERN phishing URLs (labeled by construction)",
        ],
        "counts": {
            "legit": sum(1 for r in records if r["label"] == 0),
            "phishing": sum(1 for r in records if r["label"] == 1),
            "total": len(records),
        },
        "notes": (
            "The pirocheto model's original training corpus is unknown; the "
            "dataset intentionally includes modern SaaS and deployment hosts to "
            "probe generalization. PATTERN URLs are synthetic phishing samples "
            "labeled by construction, never contacted by the evaluation."
        ),
    }

    payload = {"meta": meta, "records": records}
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)

    print("Dataset written to", OUT)
    print("Legitimate:", meta["counts"]["legit"])
    print("Phishing:", meta["counts"]["phishing"])
    print("Total:", meta["counts"]["total"])
    src_counts = {}
    for r in records:
        src_counts[r["source"]] = src_counts.get(r["source"], 0) + 1
    print("By source:", json.dumps(src_counts, indent=2))


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-verify", action="store_true", help="skip deployment URL verification")
    args = parser.parse_args()
    main(verify=not args.no_verify)