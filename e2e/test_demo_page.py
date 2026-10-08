"""Critical paths of the demo page (grill-decisions Q51), with the API faked so no quota is used."""

import json

import pytest

pytest.importorskip("playwright.sync_api")
from playwright.sync_api import Page, Route, expect  # noqa: E402

API = "http://127.0.0.1:8000"  # what the page calls when served from 127.0.0.1
HEALTH = {"status": "ok", "model": "groq/qwen/qwen3.8-27b", "attack_version": "19.2"}
PASSAGE = "T1059.001 PowerShell — Detection\nMonitor PowerShell launched with encoded commands."
ANSWER = {
    "status": "answered", "refused_by": None, "refusal_reason": "",
    "claims": [{"text": "Monitor PowerShell launched with encoded commands.",
                "passage_ids": ["T1059.001:detection"]}],
    "substitutions": {"T1086": "T1059.001"}, "top_cosine": 0.61, "relevance_threshold": 0.44,
    "hits": [{"id": "T1059.001:detection", "rank": 1, "kind": "Detection", "dense_rank": 4,
              "bm25_rank": 26, "cosine": 0.56, "text": PASSAGE}],
    "model": "groq/qwen/qwen3.8-27b", "attack_version": "19.2", "elapsed_ms": 2400, "remaining_today": 49,
}


CORS = {"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "GET, POST",
        "Access-Control-Allow-Headers": "Content-Type"}


def fake_api(page: Page, ask_status: int = 200, ask_body: dict | None = None) -> None:
    def health(route: Route) -> None:
        route.fulfill(json=HEALTH, headers=CORS)

    def ask(route: Route) -> None:
        if route.request.method == "OPTIONS":  # the browser's CORS preflight for a JSON POST
            route.fulfill(status=204, headers=CORS)
            return
        route.fulfill(status=ask_status, body=json.dumps(ask_body if ask_body is not None else ANSWER),
                      content_type="application/json", headers=CORS)

    page.route(f"{API}/health", health)
    page.route(f"{API}/ask", ask)


def test_recorded_examples_and_figures_render(page: Page, site_url: str) -> None:
    fake_api(page)
    page.goto(site_url)
    expect(page.locator("#example .q")).not_to_be_empty()
    expect(page.locator("#example .sources li").first).to_be_visible()
    expect(page.locator("#figures .figure")).to_have_count(4)


def test_each_example_says_why_it_is_there_and_labels_its_parts(page: Page, site_url: str) -> None:
    # Visitors couldn't tell what an example proved, or where the question ended and the
    # sources began (Q59)
    fake_api(page)
    page.goto(site_url)
    expect(page.locator(".picker .group").first).to_contain_text("Should answer")
    example = page.locator("#example")
    expect(example.locator(".why")).to_contain_text("Risk")
    expect(example.locator(".why")).to_contain_text("Shows")
    expect(example.locator(".part-label .name")).to_have_text(["Question", "Answer", "Sources"])


def test_live_answer_shows_citations_sources_and_the_revoked_id_note(page: Page, site_url: str) -> None:
    fake_api(page)
    page.goto(site_url)
    expect(page.locator("#status")).to_have_attribute("data-state", "ready")
    expect(page.locator("#status-text")).to_contain_text("qwen3.8-27b via Groq")
    page.fill("#question", "How do I detect T1086?")
    page.click("#ask-button")
    answer = page.locator("#answer")
    expect(answer.locator(".note")).to_contain_text("T1086 was replaced by T1059.001")
    expect(answer.locator(".prose sup button")).to_have_text("1")
    answer.locator(".prose sup button").click()
    expect(answer.locator(".sources li").first.locator(".passage")).to_be_visible()
    expect(answer.locator(".meta")).to_contain_text("49 live questions left today")
    expect(answer.locator(".part-label .name")).to_have_text(["Question", "Answer", "Sources"])
    expect(answer.locator(".why")).to_have_count(0)  # live answers have no recorded rationale


def test_refusal_names_the_gate(page: Page, site_url: str) -> None:
    fake_api(page, ask_body={**ANSWER, "status": "refused", "refused_by": "relevance",
                             "refusal_reason": "", "claims": [], "top_cosine": 0.37})
    page.goto(site_url)
    page.fill("#question", "How do I bake bread?")
    page.click("#ask-button")
    expect(page.locator("#answer .refusal")).to_contain_text("Not answered")
    expect(page.locator("#answer .gate")).to_contain_text("Stopped before the model")
    # the gate refused without a model call, so the footer must not credit the model
    expect(page.locator("#answer .meta")).to_contain_text("without calling the model")
    expect(page.locator("#answer .meta")).not_to_contain_text("qwen")


def test_daily_limit_pauses_live_questions_but_keeps_examples(page: Page, site_url: str) -> None:
    fake_api(page, ask_status=503, ask_body={"error": "daily_limit",
                                             "message": "Today's live questions are used up."})
    page.goto(site_url)
    page.fill("#question", "Mitigations for T1543.002")
    page.click("#ask-button")
    expect(page.locator("#answer .message")).to_contain_text("used up")
    expect(page.locator("#status")).to_have_attribute("data-state", "paused")
    expect(page.locator("#example .q")).not_to_be_empty()


def test_hourly_limit_message_is_shown(page: Page, site_url: str) -> None:
    fake_api(page, ask_status=429, ask_body={"error": "rate_limited",
                                             "message": "That's the hourly limit for live questions."})
    page.goto(site_url)
    page.fill("#question", "What is T1059?")
    page.click("#ask-button")
    expect(page.locator("#answer .message")).to_contain_text("hourly limit")


def test_no_horizontal_scroll_at_phone_width(page: Page, site_url: str) -> None:
    fake_api(page)
    page.set_viewport_size({"width": 360, "height": 780})
    page.goto(site_url)
    expect(page.locator("#example .q")).not_to_be_empty()
    page.locator("#example .sources .src").first.click()
    overflow = page.evaluate("document.documentElement.scrollWidth - document.documentElement.clientWidth")
    assert overflow <= 0


def test_question_area_keeps_the_side_gutter_at_phone_width(page: Page, site_url: str) -> None:
    # `.hero` padding once overrode `.wrap`'s side padding: the heading and the question box
    # touched the screen edges while every other section kept its gutter
    fake_api(page)
    page.set_viewport_size({"width": 360, "height": 780})
    page.goto(site_url)
    for selector in ("h1", "#question", "#ask-button"):
        box = page.locator(selector).bounding_box()
        assert box["x"] >= 16 and box["x"] + box["width"] <= 360 - 16, selector


def test_question_area_lines_up_with_the_sections_below_on_desktop(page: Page, site_url: str) -> None:
    # Without .wrap's side padding the hero's right column started 40px left of every section's
    fake_api(page)
    page.set_viewport_size({"width": 1100, "height": 800})
    page.goto(site_url)
    expect(page.locator("#example .q")).not_to_be_empty()
    left = {s: page.locator(s).bounding_box()["x"] for s in (".hero h1", "#question", "#picker", "#example")}
    assert len(set(left.values())) == 1, left
