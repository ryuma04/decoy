from app import narrate as narr


def test_lure_page_fallback():
    res = narr.generate_lure_page("/admin/staff-report", site="Aetees Bakehouse")
    assert "title" in res
    assert "body_html" in res
    assert "Aetees Bakehouse" in res["title"]
    assert "<script" not in res["body_html"]
    assert "href=" not in res["body_html"]



import pytest


@pytest.mark.parametrize("body", [
    "<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<a href='https://evil.test'>x</a>",
    "<iframe src='/x'></iframe>", "<a href='javascript:alert(1)'>x</a>", "<p>contact rahul.k@gmail.com</p>",
])
def test_lure_guard_rejects_unsafe(body):
    with pytest.raises(narr.LLMError):
        narr.guard_lure_page("Staff report", body)


def test_lure_guard_allows_plain_html_and_escapes_title():
    title, body = narr.guard_lure_page("<b>Q3</b> report", "<table><tr><td>Orders</td><td>412</td></tr></table>")
    assert title == "&lt;b&gt;Q3&lt;/b&gt; report" and body.startswith("<table>")


def test_fallback_escapes_path():
    res = narr.generate_lure_page("/admin/<img src=x onerror=1>", cfg=narr.Config("openai_compat", "", "", ""))
    assert "<img" not in res["body_html"]
