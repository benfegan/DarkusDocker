# ORIGINAL CREATOR: Luca Garofalo (Lucksi)
# AUTHOR: Luca Garofalo (Lucksi)
# Copyright (C) 2023-2025
# License: GNU General Public License v3.0

import os
import re
import sys
import json
import base64
import hashlib
import argparse
from time import sleep
from html import escape as html_escape

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from bs4 import BeautifulSoup as soup


# =========================
# Config & Utilities
# =========================

class Utils:
    YELLOW = "\033[0;93m"
    RED    = "\033[31m"
    GREEN  = "\033[32m"
    BLUE   = "\033[94m"
    WHITE  = "\033[97m"

    @staticmethod
    def Clear_Screen():
        os.system("cls" if os.name == "nt" else "clear")

    @staticmethod
    def ensure_dir(path: str):
        os.makedirs(path, exist_ok=True)


class Engine:
    # ---- Environment-driven config (container/Kasm friendly)
    _socks_host = os.environ.get("TOR_SOCKS_HOST", "127.0.0.1")
    _socks_port = os.environ.get("TOR_SOCKS_PORT", "9050")
    _retries    = int(os.environ.get("REQ_RETRIES", "3"))
    _timeout    = int(os.environ.get("REQ_TIMEOUT_SECS", "30"))

    NON_INTERACTIVE = os.environ.get("NON_INTERACTIVE", "0") == "1"
    AGREED          = os.environ.get("AGREEMENT_ACCEPTED", "0") == "1"
    DEFAULT_ENCODE  = os.environ.get("ENCODE_REPORT", "0") == "1"
    DEFAULT_IMAGES  = int(os.environ.get("INCLUDE_IMAGES", "2"))  # 1 yes, 2 no

    proxy = {
        "http":  f"socks5h://{_socks_host}:{_socks_port}",
        "https": f"socks5h://{_socks_host}:{_socks_port}",
    }

    headers = {
        # Fix: proper header key
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
        "Connection": "close",
    }

    # Robust session with retries/backoff
    session = requests.Session()
    adapter = HTTPAdapter(
        max_retries=Retry(
            total=_retries,
            backoff_factor=1.0,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=False,  # retry any
            raise_on_status=False,
        )
    )
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    count = 1  # used in HTML report numbering


# ---------- Small helpers for richer output

RE_EMAIL = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.I)
RE_BTC   = re.compile(r"\b(bc1[0-9A-Za-z]{25,39}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
RE_XMR   = re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b")
RE_PGP   = re.compile(r"-----BEGIN PGP PUBLIC KEY BLOCK-----")

def extract_iocs(text: str | None):
    text = text or ""
    return {
        "emails": list(set(RE_EMAIL.findall(text))),
        "btc": list(set(RE_BTC.findall(text))),
        "xmr": list(set(RE_XMR.findall(text))),
        "pgp": bool(RE_PGP.search(text)),
    }

def write_json_line(path: str, obj: dict):
    with open(path, "a", encoding="utf-8") as jf:
        jf.write(json.dumps(obj, ensure_ascii=False) + "\n")


# =========================
# Core features
# =========================

class EngineOps:

    @staticmethod
    def Agreement():
        Utils.Clear_Screen()
        print(Utils.BLUE + "[I]" + Utils.WHITE + " Checking Usage Agreement")

        # Non-interactive acceptance
        if Engine.AGREED:
            try:
                with open("Agreement.txt", "w", encoding="utf-8") as f:
                    f.write("Agreement Accepted")
            except Exception:
                pass

        content = ""
        if os.path.exists("Agreement.txt"):
            try:
                with open("Agreement.txt", "r", newline=None, encoding="utf-8") as f:
                    content = f.read().strip()
            except Exception:
                content = ""

        if content == "Agreement Accepted":
            print(Utils.YELLOW + "[v]" + Utils.WHITE + " Usage Agreement found\n")
            sleep(0.5)
            return

        # Show banner (if available)
        Utils.Clear_Screen()
        try:
            with open("Banner/Banner.txt", "r", newline=None, encoding="utf-8") as f:
                for line in f:
                    print(Utils.RED + line.rstrip("\n"))
                    sleep(0.03)
        except Exception:
            pass

        if Engine.NON_INTERACTIVE:
            # In headless mode without AGREEMENT_ACCEPTED, bail out safely
            print(Utils.RED + "\n[!] Agreement not accepted and interactive mode is off. Exiting.\n")
            sys.exit(1)

        try:
            choice = str(input(
                Utils.WHITE + "\nThis tool is intended for research/education only. "
                "I do not assume liability for misuse.\n\n"
                "Press " + Utils.GREEN + "(Y)" + Utils.WHITE + " to accept or "
                + Utils.RED + "(N)" + Utils.WHITE + " to decline.\n\n"
                + Utils.RED + "[:DARKUS:]" + Utils.WHITE + "--> "
            ))
            if choice.lower() == "y":
                with open("Agreement.txt", "w", encoding="utf-8") as f:
                    f.write("Agreement Accepted")
                Utils.Clear_Screen()
                print(Utils.YELLOW + "[v]" + Utils.WHITE + " Agreement Accepted\n")
                sleep(0.5)
                return
            else:
                print(Utils.RED + "Agreement refused. Exiting.\n")
                sys.exit(1)
        except (ValueError, KeyboardInterrupt):
            print("\n")
            sys.exit(1)

    @staticmethod
    def Banner():
        Utils.Clear_Screen()
        try:
            with open("Banner/Banner.txt", "r", newline=None, encoding="utf-8") as f:
                for line in f:
                    print(Utils.RED + line.rstrip("\n"))
                    sleep(0.02)
        except Exception:
            print(Utils.RED + "DARKUS / NUCLUS")
        print(Utils.WHITE + "\nAn Onion Website Searcher\t  Coded by Lucksi / Nuclus hardened")
        print(Utils.RED + "----------------------------------------------------")

    @staticmethod
    def HashCheck(url: str):
        """Check MD5(url) against banned lists."""
        report = "output/Banned.txt"
        Utils.ensure_dir(os.path.dirname(report))
        md5url = hashlib.md5(url.encode('utf-8')).hexdigest()
        print(Utils.GREEN + "\n[+]" + Utils.WHITE + f" Url Hashed: {Utils.GREEN}{md5url}{Utils.WHITE}")

        endpoints = [
            "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/blacklist/banned/",
            "https://ahmia.fi/blacklist/banned/",
        ]
        banned = False
        for endpoint in endpoints:
            try:
                r = Engine.session.get(endpoint, proxies=Engine.proxy,
                                       headers=Engine.headers, timeout=Engine._timeout)
                if r.ok and md5url in r.text:
                    banned = True
                    break
            except Exception:
                continue

        if banned:
            print(Utils.RED + "[!]" + Utils.WHITE + f" Url appears on a banned list: {Utils.GREEN}{url}{Utils.WHITE}")
            with open(report, "a", encoding="utf-8") as f:
                f.write(url + "\r\n")
        else:
            print(Utils.YELLOW + "[v]" + Utils.WHITE + f" Url not found on banned list: {Utils.GREEN}{url}{Utils.WHITE}")

    @staticmethod
    def HtmlReport_open(report_txt: str):
        """Create/initialize an HTML report and return its path (kept open later)."""
        content = """<!-- Report created with Darkus/Nuclus -->
<html>
<head>
  <meta name="viewport" content="width=device-width, initial-scale=0.9">
  <title>Darkus Report</title>
  <style>
    body{ background:#000; color:#fff; font-family: system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;}
    h3{ font-size: 22px; font-weight: bold; margin: 10px 0;}
    .results{ display:block; border: 2px solid #999; border-radius: 14px; background:#111; padding:12px; margin-bottom:12px;}
    a{ color:#2779F6; text-decoration:none;}
    .meta{ color:#bbb; font-size: 12px; }
  </style>
</head>
<body>
  <h3>Onion Links found</h3>
  <div class='meta'>Report generated by <a href='https://github.com/Lucksi/Darkus' target='_blank' rel='noopener'>Darkus</a> (Nuclus-hardened)</div>
  <div id='container'>
"""
        htmlrep = report_txt.replace(".txt", ".html")
        with open(htmlrep, "w", encoding="utf-8") as f:
            f.write(content)
        return htmlrep

    @staticmethod
    def HtmlReport_append(html_report: str, idx: int, title: str, url: str, description: str, timestamp: str | None, md5url: str, image_url: str | None = None):
        title_e = html_escape(title or "")
        desc_e  = html_escape(description or "")
        url_e   = html_escape(url or "")
        img_e   = html_escape(image_url or "") if image_url else None
        ts_e    = html_escape(timestamp or "") if timestamp else ""

        with open(html_report, "a", encoding="utf-8") as f:
            f.write("<div class='results'>\n")
            f.write(f"<h3>({idx}) {title_e}</h3>\n")
            f.write(f"<div>Url: <a href='{url_e}' target='_blank' rel='noopener'>{url_e}</a></div>\n")
            if img_e:
                f.write(f"<div>Image: <a href='{img_e}' target='_blank' rel='noopener'>{img_e}</a></div>\n")
            if desc_e:
                f.write(f"<div>Description: {desc_e}</div>\n")
            if ts_e:
                f.write(f"<div>Timestamp: {ts_e}</div>\n")
            f.write(f"<div>MD5-Url: <code>{md5url}</code></div>\n")
            f.write("</div>\n")

    @staticmethod
    def HtmlReport_close(html_report: str):
        with open(html_report, "a", encoding="utf-8") as f:
            f.write("\n</div>\n</body>\n</html>")

    @staticmethod
    def maybe_encode_report(report_txt: str, name: str, force_encode: bool | None = None):
        """Optionally base64-encode the TXT report into .Dk and remove original."""
        if force_encode is None:
            if Engine.NON_INTERACTIVE:
                do_encode = Engine.DEFAULT_ENCODE
            else:
                try:
                    do_encode = int(input(
                        Utils.BLUE + "\n[?]" + Utils.WHITE +
                        f" Do you want to encode the {name} report? (1) Yes (2) No"
                        + Utils.RED + "\n\n[:DARKUS:]" + Utils.WHITE + "--> "
                    )) == 1
                except Exception:
                    do_encode = False
        else:
            do_encode = force_encode

        if not do_encode:
            print(Utils.GREEN + "\n[+]" + Utils.WHITE + f" Report saved in: {Utils.GREEN}{report_txt}{Utils.WHITE}")
            return

        encoded_file = report_txt.replace(".txt", ".Dk")
        with open(report_txt, "r", encoding="utf-8") as f:
            reader = f.read()
        print(Utils.GREEN + "\n[+]" + Utils.WHITE + " Encoding report...")
        sleep(0.5)
        encoded_bytes = base64.b64encode(reader.encode("utf-8"))
        final_str = encoded_bytes.decode("utf-8")
        with open(encoded_file, "w", encoding="ascii") as f:
            f.write(final_str)
        os.remove(report_txt)
        print(Utils.YELLOW + "[v]" + Utils.WHITE + f" Report Encoded: {Utils.GREEN}{os.path.basename(encoded_file)}{Utils.WHITE}")
        print(Utils.GREEN + "\n[+]" + Utils.WHITE + f" Report saved in: {Utils.GREEN}{encoded_file}{Utils.WHITE}")

    @staticmethod
    def _fetch_html(url: str) -> soup | None:
        try:
            r = Engine.session.get(url, proxies=Engine.proxy, headers=Engine.headers, timeout=Engine._timeout)
            if not r.ok:
                return None
            return soup(r.text, "lxml")
        except Exception:
            return None

    # -------------------------
    # Search Engines
    # -------------------------

    @staticmethod
    def search_ahmia(parameter: str, report_txt: str, out_console: bool, html_report: str):
        name = "Ahmia"
        i = 0
        json_report = report_txt.replace(".txt", ".ndjson")
        with open(report_txt, "a", encoding="utf-8") as f:
            f.write(name + " onion-links\r\n\n")

        url = f"https://ahmia.fi/search/?q={requests.utils.quote(parameter)}"
        print(Utils.GREEN + "\n[+]" + Utils.WHITE + f" Searching Ahmia for: {Utils.GREEN}{parameter}{Utils.WHITE}")
        parser = EngineOps._fetch_html(url)
        if not parser:
            print(Utils.RED + "[!]" + Utils.WHITE + " Failed to fetch results from Ahmia")
            return

        results = parser.find_all("li", class_="result")
        for link in results:
            try:
                title = (link.find("h4") or {}).get_text("", strip=True)
                raw_href = link.find("a")["href"]
                # Ahmia uses redirect_url=...; keep original
                url_real = raw_href.split("redirect_url=")[-1].strip()
                description = (link.find("p") or {}).get_text("\n", strip=True)
                ts_tag = link.find("span", class_="lastSeen")
                timestamp = ts_tag.get("data-timestamp", "").strip() if ts_tag else None
                md5url = hashlib.md5(url_real.encode('utf-8')).hexdigest()

                if out_console:
                    print(Utils.GREEN + "[+]" + Utils.WHITE + f" Title: {Utils.GREEN}{title}{Utils.WHITE}")
                    print(Utils.YELLOW + "[v]" + Utils.WHITE + f" Url: {Utils.GREEN}{url_real}{Utils.WHITE}")
                    print(Utils.YELLOW + "[v]" + Utils.WHITE + f" Description: {Utils.GREEN}{description}{Utils.WHITE}")
                    if timestamp:
                        print(Utils.YELLOW + "[v]" + Utils.WHITE + f" Timestamp: {Utils.GREEN}{timestamp}{Utils.WHITE}")
                    print(Utils.YELLOW + "[v]" + Utils.WHITE + f" MD5-url: {Utils.BLUE}{md5url}{Utils.WHITE}\n")

                with open(report_txt, "a", encoding="utf-8") as f:
                    f.write(f"Title: {title}\r\nUrl: {url_real}\r\nDescription: {description}\r\n")
                    f.write(f"Timestamp: {timestamp or 'None'}\r\nMD5-Url: {md5url}\r\n\n")

                EngineOps.HtmlReport_append(html_report, Engine.count, title, url_real, description, timestamp, md5url)
                Engine.count += 1
                i += 1

                # IOC enrichment
                ioc = extract_iocs(description)
                write_json_line(json_report, {
                    "engine": name, "title": title, "url": url_real,
                    "description": description, "timestamp": timestamp, "md5": md5url, "ioc": ioc
                })

                # Optional safety list check
                EngineOps.HashCheck(url_real)
            except Exception:
                continue

        with open(report_txt, "a", encoding="utf-8") as f:
            f.write(f"Total Onion {name} Site Found: {i}\r\n")
        print(Utils.BLUE + "[I]" + Utils.WHITE + f" Total {Utils.GREEN}{name}{Utils.WHITE} Onion Sites Found: {Utils.GREEN}{i}{Utils.WHITE}")

    @staticmethod
    def search_torch(parameter: str, report_txt: str, out_console: bool, html_report: str, include_images: int):
        """
        Torch classic search & optional image search.
        """
        name = "Torch"
        i = 0
        json_report = report_txt.replace(".txt", ".ndjson")
        with open(report_txt, "a", encoding="utf-8") as f:
            f.write(name + " onion-links\r\n\n")

        # .onion from provided snippet (may rotate over time)
        base = "http://torchdeedp3i2jigzjdmfpn5ttjhthh5wbmda2rr3jvqjg5p77c54dqd.onion"
        url = f"{base}/search?query={requests.utils.quote(parameter)}&action=search"
        print(Utils.GREEN + "\n[+]" + Utils.WHITE + f" Searching Torch for: {Utils.GREEN}{parameter}{Utils.WHITE}")

        parser = EngineOps._fetch_html(url)
        if parser:
            blocks = parser.find_all("div", class_="result mb-3")
            for link in blocks:
                try:
                    title = (link.find("h5") or {}).get_text("", strip=True)
                    url_real = link.find("a")["href"]
                    description = (link.find("p") or {}).get_text("\n", strip=True)
                    md5url = hashlib.md5(url_real.encode('utf-8')).hexdigest()

                    if out_console:
                        print(Utils.GREEN + "[+]" + Utils.WHITE + f" Title: {Utils.GREEN}{title}{Utils.WHITE}")
                        print(Utils.YELLOW + "[v]" + Utils.WHITE + f" Url: {Utils.GREEN}{url_real}{Utils.WHITE}")
                        print(Utils.YELLOW + "[v]" + Utils.WHITE + f" Description: {Utils.GREEN}{description}{Utils.WHITE}")
                        print(Utils.YELLOW + "[v]" + Utils.WHITE + f" MD5-url: {Utils.BLUE}{md5url}{Utils.WHITE}\n")

                    with open(report_txt, "a", encoding="utf-8") as f:
                        f.write(f"Title: {title}\r\nUrl: {url_real}\r\nDescription: {description}\r\n")
                        f.write(f"MD5-Url: {md5url}\r\n\n")

                    EngineOps.HtmlReport_append(html_report, Engine.count, title, url_real, description, None, md5url)
                    Engine.count += 1
                    i += 1

                    ioc = extract_iocs(description)
                    write_json_line(json_report, {
                        "engine": name, "title": title, "url": url_real,
                        "description": description, "timestamp": None, "md5": md5url, "ioc": ioc
                    })

                    EngineOps.HashCheck(url_real)
                except Exception:
                    continue

        # Optional image search
        if include_images == 1:
            name_img = "Torch-Images"
            with open(report_txt.replace(".txt", "_image.txt"), "a", encoding="utf-8") as f:
                f.write(name_img + " onion-links\r\n\n")
            img_url = f"{base}/images?query={requests.utils.quote(parameter)}"
            print(Utils.GREEN + "\n[+]" + Utils.WHITE + f" Searching Torch Images for: {Utils.GREEN}{parameter}{Utils.WHITE}")
            p2 = EngineOps._fetch_html(img_url)
            if p2:
                blocks = p2.find_all("div", class_="imagehold")
                for b in blocks:
                    anchors = b.find_all("a")
                    for a in anchors:
                        try:
                            title = (a.find("img") or {})["alt"].strip()
                            url_real = a["href"]
                            image = (a.find("img") or {})["src"]
                            md5url = hashlib.md5(url_real.encode('utf-8')).hexdigest()

                            if out_console:
                                print(Utils.GREEN + "[+]" + Utils.WHITE + f" Title: {Utils.GREEN}{title}{Utils.WHITE}")
                                print(Utils.YELLOW + "[v]" + Utils.WHITE + f" Url: {Utils.GREEN}{url_real}{Utils.WHITE}")
                                print(Utils.YELLOW + "[v]" + Utils.WHITE + f" Image-Url: {Utils.GREEN}{image}{Utils.WHITE}")
                                print(Utils.YELLOW + "[v]" + Utils.WHITE + f" MD5-url: {Utils.BLUE}{md5url}{Utils.WHITE}\n")

                            with open(report_txt.replace(".txt", "_image.txt"), "a", encoding="utf-8") as f:
                                f.write(f"Title: {title}\r\nUrl: {url_real}\r\nImage-Url: {image}\r\n")
                                f.write(f"MD5-Url: {md5url}\r\n\n")

                            EngineOps.HtmlReport_append(html_report, Engine.count, title, url_real, "", None, md5url, image_url=image)
                            Engine.count += 1

                            ioc = extract_iocs(title)
                            write_json_line(report_txt.replace(".txt", ".ndjson"), {
                                "engine": name_img, "title": title, "url": url_real,
                                "image": image, "timestamp": None, "md5": md5url, "ioc": ioc
                            })

                            EngineOps.HashCheck(url_real)
                        except Exception:
                            continue

        with open(report_txt, "a", encoding="utf-8") as f:
            f.write(f"Total Onion {name} Site Found: {i}\r\n")
        print(Utils.BLUE + "[I]" + Utils.WHITE + f" Total {Utils.GREEN}{name}{Utils.WHITE} Onion Sites Found: {Utils.GREEN}{i}{Utils.WHITE}")

    @staticmethod
    def search_notevil(parameter: str, report_txt: str, out_console: bool, html_report: str):
        """
        NotEvil (endpoints rotate frequently). Use best-effort parsing.
        """
        name = "notevil"
        i = 0
        json_report = report_txt.replace(".txt", ".ndjson")
        with open(report_txt, "a", encoding="utf-8") as f:
            f.write(name + " onion-links\r\n\n")

        # Known pattern (may be stale; still safe to attempt)
        candidates = [
            "http://hss3uro2hsxfogfq.onion/?q=",
        ]
        parser = None
        for base in candidates:
            url = f"{base}{requests.utils.quote(parameter)}"
            print(Utils.GREEN + "\n[+]" + Utils.WHITE + f" Searching notevil for: {Utils.GREEN}{parameter}{Utils.WHITE}")
            parser = EngineOps._fetch_html(url)
            if parser:
                break

        if not parser:
            print(Utils.RED + "[!]" + Utils.WHITE + " Failed to fetch results from notevil")
            return

        rows = parser.find_all("div", class_="row")
        for link in rows:
            try:
                anchors = link.find_all("a")
                if len(anchors) < 3:
                    continue
                title = anchors[2].get_text("", strip=True)
                url_real = anchors[2]["href"]
                descr_tag = link.find("span")
                description = descr_tag.get_text("\n", strip=True) if descr_tag else ""
                md5url = hashlib.md5(url_real.encode('utf-8')).hexdigest()

                if out_console:
                    print(Utils.GREEN + "[+]" + Utils.WHITE + f" Title: {Utils.GREEN}{title}{Utils.WHITE}")
                    print(Utils.YELLOW + "[v]" + Utils.WHITE + f" Url: {Utils.GREEN}{url_real}{Utils.WHITE}")
                    print(Utils.YELLOW + "[v]" + Utils.WHITE + f" Description: {Utils.GREEN}{description}{Utils.WHITE}")
                    print(Utils.YELLOW + "[v]" + Utils.WHITE + f" MD5-url: {Utils.BLUE}{md5url}{Utils.WHITE}\n")

                with open(report_txt, "a", encoding="utf-8") as f:
                    f.write(f"Title: {title}\r\nUrl: {url_real}\r\nDescription: {description}\r\n")
                    f.write(f"MD5-Url: {md5url}\r\n\n")

                EngineOps.HtmlReport_append(html_report, Engine.count, title, url_real, description, None, md5url)
                Engine.count += 1
                i += 1

                ioc = extract_iocs(description)
                write_json_line(json_report, {
                    "engine": name, "title": title, "url": url_real,
                    "description": description, "timestamp": None, "md5": md5url, "ioc": ioc
                })

                EngineOps.HashCheck(url_real)
            except Exception:
                continue

        with open(report_txt, "a", encoding="utf-8") as f:
            f.write(f"Total Onion {name} Site Found: {i}\r\n")
        print(Utils.BLUE + "[I]" + Utils.WHITE + f" Total {Utils.GREEN}{name}{Utils.WHITE} Onion Sites Found: {Utils.GREEN}{i}{Utils.WHITE}")


# =========================
# CLI / Main
# =========================

def build_arg_parser():
    p = argparse.ArgumentParser(
        description="Darkus / Nuclus-hardened dark web OSINT searcher (Tor required).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    p.add_argument("engine", nargs="?", default=None,
                   help="Search engine: ahmia | torch | notevil | all")
    p.add_argument("query", nargs="?", default=None, help="Search query / keywords")
    p.add_argument("--output-dir", default="output", help="Output directory")
    p.add_argument("--no-html", action="store_true", help="Disable HTML report generation")
    p.add_argument("--encode", action="store_true", help="Force encode final TXT report to .Dk")
    p.add_argument("--images", type=int, choices=[1, 2], default=None,
                   help="Torch image search: 1 Yes, 2 No")
    p.add_argument("--no-console-results", action="store_true",
                   help="Do not print each result to console")
    return p


def interactive_prompt() -> tuple[str, str, int, bool]:
    """Prompt user for engine, query, images preference, and console output."""
    print(Utils.WHITE + "\nChoose engine: " + Utils.GREEN + "[ahmia/torch/notevil/all]" + Utils.WHITE)
    try:
        engine = str(input(Utils.RED + "[:DARKUS:]" + Utils.WHITE + " engine --> ")).strip().lower()
    except KeyboardInterrupt:
        print("\n"); sys.exit(1)
    if engine not in ("ahmia", "torch", "notevil", "all"):
        engine = "all"

    try:
        query = str(input(Utils.RED + "[:DARKUS:]" + Utils.WHITE + " query  --> ")).strip()
    except KeyboardInterrupt:
        print("\n"); sys.exit(1)
    if not query:
        print(Utils.RED + "[!] No query provided. Exiting.")
        sys.exit(1)

    if engine in ("torch", "all"):
        if Engine.NON_INTERACTIVE:
            images = Engine.DEFAULT_IMAGES
        else:
            try:
                images = int(input(Utils.GREEN + "\n[+]" + Utils.WHITE +
                                   " Do you want to search images? (1) Yes (2) No"
                                   + Utils.RED + "\n\n[:DARKUS:]" + Utils.WHITE + "--> "))
            except Exception:
                images = 2
            if images not in (1, 2):
                images = 2
    else:
        images = 2

    out_console = True
    return engine, query, images, out_console


def main():
    # Accept alias: if someone types `db ...` we ignore the first token
    argv = sys.argv
    if len(argv) > 1 and argv[1].lower() == "db":
        argv = [argv[0]] + argv[2:]

    # EULA / Banner
    EngineOps.Agreement()
    EngineOps.Banner()

    # Parse CLI
    parser = build_arg_parser()
    args = parser.parse_args(argv[1:])

    if Engine.NON_INTERACTIVE and (args.engine is None or args.query is None):
        print(Utils.RED + "[!] NON_INTERACTIVE is set but engine/query missing. "
              "Usage: python Main.py all \"keyword\"")
        sys.exit(2)

    if args.engine is None or args.query is None:
        engine, query, images, out_console = interactive_prompt()
    else:
        engine = (args.engine or "all").lower()
        query = args.query
        images = args.images if args.images in (1, 2) else (Engine.DEFAULT_IMAGES if engine in ("torch", "all") else 2)
        out_console = not args.no_console_results

    # Prepare outputs
    output_dir = args.output_dir
    Utils.ensure_dir(output_dir)
    base_name = re.sub(r"[^A-Za-z0-9._-]+", "_", query.strip())[:80] or "report"
    report_txt = os.path.join(output_dir, f"{base_name}.txt")

    # Initialize HTML
    html_report = None
    if not args.no_html:
        html_report = EngineOps.HtmlReport_open(report_txt)

    # Run engines
    if engine in ("ahmia", "all"):
        EngineOps.search_ahmia(query, report_txt, out_console, html_report or report_txt.replace(".txt", ".html"))
    if engine in ("torch", "all"):
        EngineOps.search_torch(query, report_txt, out_console, html_report or report_txt.replace(".txt", ".html"), images)
    if engine in ("notevil", "all"):
        EngineOps.search_notevil(query, report_txt, out_console, html_report or report_txt.replace(".txt", ".html"))

    # Close HTML
    if html_report:
        EngineOps.HtmlReport_close(html_report)

    # Maybe encode final TXT
    EngineOps.maybe_encode_report(report_txt, name="final", force_encode=True if args.encode else None)

    print(Utils.GREEN + "\n[+]" + Utils.WHITE + f" Done. See: {Utils.GREEN}{report_txt}{Utils.WHITE} "
          f"and sidecar {Utils.GREEN}{report_txt.replace('.txt', '.ndjson')}{Utils.WHITE}")
    if html_report:
        print(Utils.GREEN + "[+]" + Utils.WHITE + f" HTML: {Utils.GREEN}{html_report}{Utils.WHITE}")


if __name__ == "__main__":
    main()
