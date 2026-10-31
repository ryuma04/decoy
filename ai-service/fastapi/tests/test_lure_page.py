from app import narrate as narr


def test_lure_page_fallback():
    res = narr.generate_lure_page("/admin/staff-report", site="Aetees Bakehouse")
    assert "title" in res
    assert "body_html" in res
    assert "Aetees Bakehouse" in res["title"]
    assert "<script" not in res["body_html"]
    assert "href=" not in res["body_html"]

