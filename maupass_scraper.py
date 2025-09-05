import argparse
import os
import re
import sys
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import requests
import psycopg2
from selenium import webdriver
from selenium.common.exceptions import NoSuchElementException, TimeoutException
from selenium.webdriver import ChromeOptions
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait
from webdriver_manager.chrome import ChromeDriverManager
from dotenv import load_dotenv


DEFAULT_LOGIN_URL = (
    "https://maupass.govmu.org/Account/Login/?returnUrl=https%3A//supremecourt.govmu.org/maupass/login"
)
DEFAULT_WEBHOOK_URL = (
    "https://n8n.islandai.co/webhook/6a705dfe-98a3-4aec-a7b5-d4fc06e71718"
)
# Force the correct list type (Act & Regulation)
DEFAULT_ACTS_URL = "https://supremecourt.govmu.org/act-group-lists?name=&type=act_regulation&page=0"


def create_driver(headless: bool) -> webdriver.Chrome:
    options = ChromeOptions()
    if headless:
        options.add_argument("--headless=new")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-gpu")
    options.add_argument("--window-size=1366,900")

    service = ChromeService(ChromeDriverManager().install())
    driver = webdriver.Chrome(service=service, options=options)
    driver.set_page_load_timeout(60)
    return driver


def wait_for_any(driver: webdriver.Chrome, locators: List[tuple], timeout: int = 15):
    return WebDriverWait(driver, timeout).until(
        lambda d: next((d.find_element(*loc) for loc in locators if _exists(d, *loc)), None)
    )


def _exists(driver: webdriver.Chrome, by: By, selector: str) -> bool:
    try:
        driver.find_element(by, selector)
        return True
    except NoSuchElementException:
        return False


def click_if_present(driver: webdriver.Chrome, locators: List[tuple]) -> bool:
    for by, selector in locators:
        try:
            elem = driver.find_element(by, selector)
            if elem.is_displayed() and elem.is_enabled():
                elem.click()
                return True
        except NoSuchElementException:
            continue
    return False


def safe_click(driver: webdriver.Chrome, locator: tuple, timeout: int = 15) -> None:
    print(f"[safe_click] Waiting to click {locator}…")
    WebDriverWait(driver, timeout).until(EC.element_to_be_clickable(locator)).click()
    print(f"[safe_click] Clicked {locator}.")


def safe_send_keys(driver: webdriver.Chrome, locator: tuple, text: str, timeout: int = 15) -> None:
    print(f"[safe_send_keys] Waiting for {locator}…")
    elem = WebDriverWait(driver, timeout).until(EC.visibility_of_element_located(locator))
    elem.clear()
    elem.send_keys(text)
    print(f"[safe_send_keys] Sent keys to {locator}.")


def fetch_2fa_code(webhook_url: str, timeout: int = 15) -> str:
    # The user specified POST; fall back to GET if POST fails.
    try:
        print(f"[2FA] Requesting code via POST: {webhook_url}")
        resp = requests.post(webhook_url, timeout=timeout)
        resp.raise_for_status()
        body = resp.text.strip()
    except Exception:
        print("[2FA] POST failed; retrying with GET…")
        resp = requests.get(webhook_url, timeout=timeout)
        resp.raise_for_status()
        body = resp.text.strip()

    # Extract digits; typical TOTP is 6 digits
    digits = re.findall(r"\d+", body)
    if not digits:
        raise RuntimeError(f"No numeric code found in webhook response: {body!r}")
    code = max(digits, key=len)
    print(f"[2FA] Received code: {code}")
    return code


def submit_send_security_code_if_needed(driver: webdriver.Chrome, overall_timeout: int = 30) -> None:
    if "/Account/SendSecurityCode" not in driver.current_url:
        return

    # Try clicking a visible submit button on this page
    print("[2FA] On SendSecurityCode page; requesting security code…")
    candidates: List[tuple] = [
        (By.CSS_SELECTOR, "form button[type='submit']"),
        (By.CSS_SELECTOR, "form input[type='submit']"),
        (By.XPATH, "//button[contains(., 'Send') and @type='submit']"),
        (By.XPATH, "//button[contains(., 'Submit')]")
    ]

    clicked = click_if_present(driver, candidates)
    if not clicked:
        # As a fallback, press Enter on the first input in the form
        try:
            print("[2FA] Submit button not found; pressing Enter on first input…")
            first_input = driver.find_element(By.CSS_SELECTOR, "form input, form button")
            first_input.send_keys(Keys.ENTER)
        except NoSuchElementException:
            pass

    # Wait briefly for transition towards the Code page
    print("[2FA] Waiting for code entry page…")
    WebDriverWait(driver, overall_timeout).until(
        lambda d: ("/Account/VerifySecurityCode" in d.current_url) or _exists(d, By.ID, "Code")
    )


def fill_and_submit_code(driver: webdriver.Chrome, code: str, timeout: int = 30) -> None:
    print("[2FA] Filling code…")
    code_input = WebDriverWait(driver, timeout).until(
        EC.visibility_of_element_located((By.ID, "Code"))
    )
    code_input.clear()
    code_input.send_keys(code)

    # Try to submit using the containing form's submit button
    try:
        form = code_input.find_element(By.XPATH, "./ancestor::form")
        submit = None
        for by, selector in [
            (By.CSS_SELECTOR, "button[type='submit']"),
            (By.CSS_SELECTOR, "input[type='submit']"),
        ]:
            try:
                submit = form.find_element(by, selector)
                break
            except NoSuchElementException:
                continue
        if submit and submit.is_enabled():
            print("[2FA] Clicking submit…")
            submit.click()
        else:
            print("[2FA] Pressing Enter to submit…")
            code_input.send_keys(Keys.ENTER)
    except NoSuchElementException:
        print("[2FA] No submit button found; pressing Enter…")
        code_input.send_keys(Keys.ENTER)


def perform_login(login_url: str, username: str, password: str, webhook_url: str, headless: bool, post_2fa_wait_seconds: int, pre_fetch_2fa_delay_seconds: int) -> None:
    driver = create_driver(headless=headless)
    try:
        print("Opening login page…")
        driver.get(login_url)
        print(f"Loaded URL: {driver.current_url}")

        # If the page defaults to MauPass App, ensure Password Login tab is active
        click_if_present(
            driver,
            [
                (By.XPATH, "//button[contains(., 'Password Login')]"),
                (By.XPATH, "//a[contains(., 'Password Login')]")
            ],
        )

        print("Filling credentials…")
        safe_send_keys(driver, (By.ID, "userEmail-id"), username)
        safe_send_keys(driver, (By.ID, "plainTextPassword"), password)

        print("Submitting login form…")
        safe_click(driver, (By.ID, "kt_login_signin_submit"))

        # Wait for either SendSecurityCode page or direct Code entry page
        try:
            WebDriverWait(driver, 30).until(
                lambda d: (
                    "/Account/SendSecurityCode" in d.current_url
                    or _exists(d, By.ID, "Code")
                )
            )
        except TimeoutException:
            raise TimeoutException(
                "Timed out waiting for 2FA step. Check credentials or page flow."
            )

        # If SendSecurityCode page is shown, click submit to request the code
        submit_send_security_code_if_needed(driver)

        # Give backend time to generate and deliver the latest code
        if pre_fetch_2fa_delay_seconds and pre_fetch_2fa_delay_seconds > 0:
            print(f"[2FA] Waiting {pre_fetch_2fa_delay_seconds}s before fetching code…")
            time.sleep(pre_fetch_2fa_delay_seconds)

        print("Fetching 2FA code from webhook…")
        code = fetch_2fa_code(webhook_url)
        print(f"Received code: {code}")

        print("Submitting 2FA code…")
        fill_and_submit_code(driver, code)

        # Final wait: successful redirect to the protected area (returnUrl domain)
        try:
            WebDriverWait(driver, 30).until(
                lambda d: (
                    "supremecourt.govmu.org" in (d.current_url or "")
                    or "maupass.govmu.org" in (d.current_url or "") and "VerifySecurityCode" not in d.current_url
                )
            )
        except TimeoutException:
            print(
                "Warning: Did not observe a clear post-2FA redirect. The code may still have been accepted."
            )

        print("Login and 2FA flow completed.")

        if not headless and post_2fa_wait_seconds and post_2fa_wait_seconds > 0:
            print(f"Waiting {post_2fa_wait_seconds}s so you can observe the page…")
            time.sleep(post_2fa_wait_seconds)
    finally:
        # Small delay to ensure output is flushed
        time.sleep(0.2)
        driver.quit()


def login_and_return_driver(
    login_url: str,
    username: str,
    password: str,
    webhook_url: str,
    headless: bool,
    post_2fa_wait_seconds: int,
    pre_fetch_2fa_delay_seconds: int,
) -> webdriver.Chrome:
    driver = create_driver(headless=headless)
    print("Opening login page…")
    driver.get(login_url)
    print(f"Loaded URL: {driver.current_url}")

    click_if_present(
        driver,
        [
            (By.XPATH, "//button[contains(., 'Password Login')]") ,
            (By.XPATH, "//a[contains(., 'Password Login')]")
        ],
    )

    print("Filling credentials…")
    safe_send_keys(driver, (By.ID, "userEmail-id"), username)
    safe_send_keys(driver, (By.ID, "plainTextPassword"), password)

    print("Submitting login form…")
    safe_click(driver, (By.ID, "kt_login_signin_submit"))

    WebDriverWait(driver, 30).until(
        lambda d: (
            "/Account/SendSecurityCode" in d.current_url
            or _exists(d, By.ID, "Code")
        )
    )

    submit_send_security_code_if_needed(driver)

    if pre_fetch_2fa_delay_seconds and pre_fetch_2fa_delay_seconds > 0:
        print(f"[2FA] Waiting {pre_fetch_2fa_delay_seconds}s before fetching code…")
        time.sleep(pre_fetch_2fa_delay_seconds)

    print("Fetching 2FA code from webhook…")
    code = fetch_2fa_code(webhook_url)
    print(f"Received code: {code}")

    print("Submitting 2FA code…")
    fill_and_submit_code(driver, code)

    try:
        WebDriverWait(driver, 30).until(
            lambda d: (
                "supremecourt.govmu.org" in (d.current_url or "")
                or "maupass.govmu.org" in (d.current_url or "") and "VerifySecurityCode" not in d.current_url
            )
        )
    except TimeoutException:
        print("Warning: Did not observe a clear post-2FA redirect. The code may still have been accepted.")

    print("Login and 2FA flow completed.")

    if not headless and post_2fa_wait_seconds and post_2fa_wait_seconds > 0:
        print(f"Waiting {post_2fa_wait_seconds}s so you can observe the page…")
        time.sleep(post_2fa_wait_seconds)

    return driver


def build_requests_session_from_driver(driver: webdriver.Chrome) -> requests.Session:
    session = requests.Session()
    for cookie in driver.get_cookies():
        session.cookies.set(cookie["name"], cookie["value"], domain=cookie.get("domain"))
    return session


def navigate_to_acts_list(driver: webdriver.Chrome, acts_url: str) -> None:
    print(f"[NAV] Navigating to acts list: {acts_url}")
    # Ensure we have the type=act_regulation query param
    if "type=act_regulation" not in acts_url:
        sep = '&' if '?' in acts_url else '?'
        acts_url = f"{acts_url}{sep}type=act_regulation"
    driver.get(acts_url)
    WebDriverWait(driver, 30).until(
        EC.presence_of_element_located((By.CSS_SELECTOR, "table.views-view-table"))
    )
    print(f"[NAV] Landed on: {driver.current_url}")


def collect_group_rows(driver: webdriver.Chrome) -> List[Tuple[str, str]]:
    # Narrow to the name column links to avoid picking up unrelated links
    rows = driver.find_elements(By.CSS_SELECTOR, "table.views-view-table tbody tr td.views-field-name a")
    groups: List[Tuple[str, str]] = []
    for a in rows:
        try:
            name = a.text.strip()
            href = a.get_attribute("href")
            if name and href:
                groups.append((name, href))
        except Exception:
            continue
    print(f"[SCRAPE] Found {len(groups)} rows on list page")
    return groups


def go_next_page(driver: webdriver.Chrome) -> bool:
    try:
        next_link = driver.find_element(By.CSS_SELECTOR, "li.pager__item--next a")
        driver.execute_script("arguments[0].click();", next_link)
        WebDriverWait(driver, 30).until(
            EC.presence_of_element_located((By.CSS_SELECTOR, "table.views-view-table"))
        )
        return True
    except NoSuchElementException:
        return False


def get_latest_act_metadata(driver: webdriver.Chrome) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    try:
        table = driver.find_element(By.CSS_SELECTOR, "table.table-bordered")
        first_row = table.find_element(By.CSS_SELECTOR, "tbody tr")
        title_link = first_row.find_element(By.CSS_SELECTOR, "td:nth-child(1) a")
        title = title_link.text.strip()
        act_detail_url = title_link.get_attribute("href")
        try:
            doc_number = first_row.find_element(By.CSS_SELECTOR, "td:nth-child(2)").text.strip()
        except NoSuchElementException:
            doc_number = None
        return title, doc_number, act_detail_url
    except NoSuchElementException:
        return None, None, None


def find_pdf_url_on_act_page(driver: webdriver.Chrome) -> Optional[str]:
    print("[PDF] Trying to locate PDF URL on page…")
    candidates = [
        (By.CSS_SELECTOR, "a[href$='.pdf']"),
        (By.XPATH, "//a[contains(translate(., 'PDF', 'pdf'),'pdf') and contains(@href,'.pdf')]")
    ]
    for by, sel in candidates:
        try:
            a = driver.find_element(by, sel)
            href = a.get_attribute("href") or ""
            # If the anchor points to viewer.html?file=..., extract the file
            if "viewer.html" in href and "file=" in href:
                from urllib.parse import urlparse, parse_qs, unquote
                q = parse_qs(urlparse(href).query)
                file_vals = q.get("file", [])
                if file_vals and file_vals[0]:
                    resolved = unquote(file_vals[0])
                    print(f"[PDF] Found viewer anchor → file= param: {resolved}")
                    return resolved
            if href:
                print(f"[PDF] Found anchor href: {href}")
                return href
        except NoSuchElementException:
            continue
    # Try common embed tags
    for by, sel in [
        (By.CSS_SELECTOR, "iframe[src*='.pdf']"),
        (By.CSS_SELECTOR, "embed[src*='.pdf']"),
        (By.CSS_SELECTOR, "object[data*='.pdf']"),
    ]:
        try:
            el = driver.find_element(by, sel)
            href = el.get_attribute("src") or el.get_attribute("data")
            if href and ".pdf" in href:
                print(f"[PDF] Found embedded src/data: {href}")
                return href
        except NoSuchElementException:
            continue
    # Fallback: some pages include a file query param with the PDF URL
    try:
        from urllib.parse import urlparse, parse_qs, unquote
        # First, check current URL
        parsed = urlparse(driver.current_url)
        q = parse_qs(parsed.query)
        file_param = q.get("file", [])
        if file_param and file_param[0]:
            resolved = unquote(file_param[0])
            print(f"[PDF] Resolved from current URL file= param: {resolved}")
            return resolved
        # Also check any iframe srcs (viewer may be nested)
        iframes = driver.find_elements(By.CSS_SELECTOR, "iframe[src]")
        for f in iframes:
            src = f.get_attribute("src") or ""
            p = urlparse(src)
            qs = parse_qs(p.query)
            fp = qs.get("file", [])
            if fp and fp[0]:
                resolved = unquote(fp[0])
                print(f"[PDF] Resolved from iframe file= param: {resolved}")
                return resolved
    except Exception:
        pass
    return None


def download_pdf_text(session: requests.Session, pdf_url: str, referer: Optional[str] = None) -> str:
    print(f"[PDF] Downloading PDF candidate: {pdf_url}")
    # If passed a viewer URL by mistake, try to extract the file param
    if "viewer.html" in pdf_url and "file=" in pdf_url:
        try:
            from urllib.parse import urlparse, parse_qs, unquote
            q = parse_qs(urlparse(pdf_url).query)
            file_vals = q.get("file", [])
            if file_vals and file_vals[0]:
                pdf_url = unquote(file_vals[0])
                print(f"[PDF] Extracted file param from viewer URL → {pdf_url}")
        except Exception:
            pass
    headers = {}
    if referer:
        headers["Referer"] = referer
    headers["Accept"] = "application/pdf,*/*;q=0.8"
    resp = session.get(pdf_url, timeout=60, allow_redirects=True, headers=headers)
    resp.raise_for_status()
    ctype = resp.headers.get("content-type", "").lower()
    print(f"[PDF] Response status={resp.status_code}, content-type={ctype}, bytes={len(resp.content)}")
    if "pdf" not in ctype and (len(resp.content) >= 3 and resp.content[:3] in (b"\xEF\xBB\xBF", b"<!")):
        snippet = resp.text[:120].replace("\n", " ")
        raise RuntimeError(f"Expected PDF but got HTML. Head: {snippet}…")
    from pypdf import PdfReader
    import io

    with io.BytesIO(resp.content) as bio:
        reader = PdfReader(bio)
        texts: List[str] = []
        for page in reader.pages:
            try:
                texts.append(page.extract_text() or "")
            except Exception:
                continue
        return "\n".join(texts).strip()


def _is_missing_table_error(status_code: int, body_text: str) -> bool:
    if status_code in {400, 404, 406}:
        lowered = (body_text or "").lower()
        if "relation" in lowered and "does not exist" in lowered:
            return True
        # PostgREST may return empty {} for 404 when table missing or RLS hides it
        if status_code == 404 and (not lowered or lowered.strip() == '{}'):
            return True
    return False


def ensure_supabase_table_exists(db_url: str, table: str) -> None:
    if not db_url or not table:
        return
    # Very basic validation of table name to avoid SQL injection in identifier
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", table):
        raise ValueError(f"Unsafe table name: {table}")

    ddl = f"""
    create extension if not exists pgcrypto;
    create table if not exists public.{table} (
      id uuid primary key default gen_random_uuid(),
      act_group_name text not null,
      latest_act_title text not null,
      document_number text,
      group_url text not null,
      act_detail_url text not null,
      pdf_url text,
      pdf_text text,
      scraped_at timestamptz not null default now(),
      created_at timestamptz not null default now()
    );
    create unique index if not exists {table}_act_detail_url_uidx on public.{table} (act_detail_url);
    """
    conn = psycopg2.connect(db_url)
    try:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute(ddl)
    finally:
        conn.close()


def upsert_supabase(
    supabase_url: str,
    supabase_key: str,
    table: str,
    record: Dict[str, object],
    supabase_db_url: Optional[str] = None,
) -> None:
    if not supabase_url or not supabase_key or not table:
        print("Supabase config not provided; skipping upload.")
        return
    endpoint = f"{supabase_url.rstrip('/')}/rest/v1/{table}"
    headers = {
        "apikey": supabase_key,
        "Authorization": f"Bearer {supabase_key}",
        "Content-Type": "application/json",
        "Prefer": "return=representation",
    }
    safe_key = f"***{supabase_key[-4:]}" if len(supabase_key) > 8 else "***"
    print(f"[SB] POST {endpoint} (table={table}) key={safe_key}")
    r = requests.post(endpoint, headers=headers, json=[record], timeout=60)
    print(f"[SB] Response status={r.status_code} body_len={len(r.text)}")
    if r.ok:
        print("Supabase insert OK")
        return

    if supabase_db_url and _is_missing_table_error(r.status_code, r.text):
        print("Table missing; creating it now…")
        try:
            ensure_supabase_table_exists(supabase_db_url, table)
            # retry once
            r2 = requests.post(endpoint, headers=headers, json=[record], timeout=60)
            print(f"[SB] Retry status={r2.status_code} body_len={len(r2.text)}")
            if r2.ok:
                print("Supabase insert OK after table creation")
                return
            else:
                print(f"Insert still failing after table creation: {r2.status_code} - {r2.text}")
        except Exception as exc:
            print(f"Failed to create table: {exc}")
    else:
        print(f"Supabase insert failed: {r.status_code} - {r.text}")


def scrape_acts(
    driver: webdriver.Chrome,
    acts_url: str,
    page_limit: Optional[int],
    supabase_url: Optional[str],
    supabase_key: Optional[str],
    supabase_table: Optional[str],
    per_item_pause_seconds: int,
    supabase_db_url: Optional[str],
) -> None:
    base = f"{urlparse(acts_url).scheme}://{urlparse(acts_url).netloc}"
    session = build_requests_session_from_driver(driver)
    navigate_to_acts_list(driver, acts_url)

    pages_done = 0
    while True:
        groups = collect_group_rows(driver)
        group_items = list(groups)
        for group_name, group_href in group_items:
            print(f"[Group] {group_name} -> {group_href}")
            driver.get(group_href)
            WebDriverWait(driver, 30).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, "table.table-bordered"))
            )
            title, doc_number, act_detail_url = get_latest_act_metadata(driver)
            if not title or not act_detail_url:
                print("No act rows found; skipping group")
                driver.back(); WebDriverWait(driver, 30).until(EC.presence_of_element_located((By.CSS_SELECTOR, "table.views-view-table")))
                continue

            print(f"[Latest Act] {title} | {doc_number} -> {act_detail_url}")
            driver.get(act_detail_url)
            WebDriverWait(driver, 30).until(EC.presence_of_element_located((By.TAG_NAME, "body")))
            pdf_url = find_pdf_url_on_act_page(driver)
            pdf_text = ""
            if pdf_url:
                if pdf_url.startswith("/"):
                    pdf_url = urljoin(base, pdf_url)
                try:
                    # pass current page as referer to satisfy CORS/proxy rules
                    pdf_text = download_pdf_text(session, pdf_url, referer=driver.current_url)
                except Exception as exc:
                    print(f"PDF download failed: {exc}")
            else:
                print("PDF link not found on act page")

            record: Dict[str, object] = {
                "act_group_name": group_name,
                "latest_act_title": title,
                "document_number": doc_number,
                "group_url": group_href,
                "act_detail_url": act_detail_url,
                "pdf_url": pdf_url,
                "pdf_text": pdf_text,
                "scraped_at": datetime.utcnow().isoformat() + "Z",
            }
            upsert_supabase(
                supabase_url or "",
                supabase_key or "",
                supabase_table or "",
                record,
                supabase_db_url or None,
            )

            if per_item_pause_seconds and per_item_pause_seconds > 0:
                time.sleep(per_item_pause_seconds)

            driver.back()
            driver.back()
            WebDriverWait(driver, 30).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, "table.views-view-table"))
            )

        pages_done += 1
        if page_limit is not None and pages_done >= page_limit:
            break
        moved = go_next_page(driver)
        if not moved:
            break


def main(argv: Optional[List[str]] = None) -> int:
    # Load environment variables from .env if present
    load_dotenv()
    parser = argparse.ArgumentParser(description="Automate MauPass login with 2FA.")
    parser.add_argument("--username", required=False, help="MauPass username or email")
    parser.add_argument("--password", required=False, help="MauPass password")
    parser.add_argument(
        "--login-url",
        default=os.getenv("MAUPASS_LOGIN_URL", DEFAULT_LOGIN_URL),
        help="Login URL to start the flow.",
    )
    parser.add_argument(
        "--webhook-url",
        default=os.getenv("MAUPASS_WEBHOOK_URL", DEFAULT_WEBHOOK_URL),
        help="Webhook endpoint that returns the current 2FA code (POST preferred).",
    )
    parser.add_argument(
        "--post-2fa-wait",
        type=int,
        default=None,
        help="Seconds to wait after 2FA completes (headed mode only).",
    )
    parser.add_argument(
        "--pre-fetch-2fa-delay",
        type=int,
        default=None,
        help="Seconds to wait after requesting security code before fetching webhook.",
    )
    parser.add_argument(
        "--headless",
        action="store_true",
        help="Run Chrome in headless mode.",
    )
    # Scraping and Supabase options
    parser.add_argument(
        "--acts-url",
        default=os.getenv("MAUPASS_ACTS_URL", DEFAULT_ACTS_URL),
        help="Acts list URL to scrape after login.",
    )
    parser.add_argument("--page-limit", type=int, default=int(os.getenv("MAUPASS_PAGE_LIMIT", "0") or 0), help="Max pages to scrape (0=all)")
    parser.add_argument("--per-item-pause", type=int, default=int(os.getenv("MAUPASS_PER_ITEM_PAUSE_SECS", "0") or 0), help="Pause seconds between items")
    parser.add_argument("--supabase-url", default=os.getenv("SUPABASE_URL", ""))
    parser.add_argument("--supabase-key", default=os.getenv("SUPABASE_ANON_KEY", ""))
    parser.add_argument("--supabase-table", default=os.getenv("SUPABASE_TABLE", ""))
    parser.add_argument("--supabase-db-url", default=os.getenv("SUPABASE_DB_URL", ""), help="Direct Postgres URL for creating table when missing")

    args = parser.parse_args(argv)

    # Resolve values: CLI takes precedence, then env, then defaults where applicable
    username = args.username or os.getenv("MAUPASS_USERNAME")
    password = args.password or os.getenv("MAUPASS_PASSWORD")
    login_url = args.login_url
    webhook_url = args.webhook_url
    acts_url = args.acts_url
    page_limit = None if args.page_limit == 0 else args.page_limit
    per_item_pause = args.per_item_pause
    supabase_url = args.supabase_url
    supabase_key = args.supabase_key
    supabase_table = args.supabase_table
    supabase_db_url = args.supabase_db_url
    def _env_flag(name: str) -> Optional[bool]:
        raw = os.getenv(name)
        if raw is None:
            return None
        return raw.strip().lower() in {"1", "true", "yes", "on"}

    env_headless = _env_flag("MAUPASS_HEADLESS")
    headless = bool(args.headless or (env_headless is True))

    # Post-2FA wait seconds: CLI overrides env, default to 8s
    env_wait_raw = os.getenv("MAUPASS_POST_2FA_WAIT_SECS")
    env_wait = None
    if env_wait_raw:
        try:
            env_wait = int(env_wait_raw)
        except ValueError:
            print(f"Invalid MAUPASS_POST_2FA_WAIT_SECS value: {env_wait_raw}")
            env_wait = None
    if args.post_2fa_wait is not None:
        post_2fa_wait_seconds = args.post_2fa_wait
    elif env_wait is not None:
        post_2fa_wait_seconds = env_wait
    else:
        post_2fa_wait_seconds = 8

    if not username or not password:
        print("Error: Missing credentials. Provide --username/--password or set MAUPASS_USERNAME/MAUPASS_PASSWORD in .env.")
        return 1

    # Pre-fetch 2FA delay: CLI overrides env, default 2s
    env_pre_raw = os.getenv("MAUPASS_PRE_FETCH_2FA_DELAY_SECS")
    env_pre = None
    if env_pre_raw:
        try:
            env_pre = int(env_pre_raw)
        except ValueError:
            print(f"Invalid MAUPASS_PRE_FETCH_2FA_DELAY_SECS value: {env_pre_raw}")
            env_pre = None
    if args.pre_fetch_2fa_delay is not None:
        pre_fetch_2fa_delay_seconds = args.pre_fetch_2fa_delay
    elif env_pre is not None:
        pre_fetch_2fa_delay_seconds = env_pre
    else:
        pre_fetch_2fa_delay_seconds = 2

    try:
        driver = login_and_return_driver(
            login_url=login_url,
            username=username,
            password=password,
            webhook_url=webhook_url,
            headless=headless,
            post_2fa_wait_seconds=post_2fa_wait_seconds,
            pre_fetch_2fa_delay_seconds=pre_fetch_2fa_delay_seconds,
        )
        try:
            scrape_acts(
                driver=driver,
                acts_url=acts_url,
                page_limit=page_limit,
                supabase_url=supabase_url,
                supabase_key=supabase_key,
                supabase_table=supabase_table,
                per_item_pause_seconds=per_item_pause,
                supabase_db_url=supabase_db_url,
            )
        finally:
            driver.quit()
    except Exception as exc:
        print(f"Error: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())


