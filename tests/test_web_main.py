from attack_qa.web.main import DEFAULT_ORIGIN, settings_from_env


def test_defaults_allow_only_the_demo_site_and_use_groq():
    s = settings_from_env({})
    assert s.allowed_origins == (DEFAULT_ORIGIN,) == ("https://rag.marklu.page",)
    assert s.llm == "groq"


def test_extra_origins_for_local_development_are_comma_separated():
    s = settings_from_env({"ALLOWED_ORIGINS": "https://rag.marklu.page, http://127.0.0.1:8766",
                           "DEMO_LLM": "openrouter"})
    assert s.allowed_origins == ("https://rag.marklu.page", "http://127.0.0.1:8766")
    assert s.llm == "openrouter"


def test_a_wildcard_origin_is_refused():
    import pytest
    with pytest.raises(ValueError, match="wildcard"):
        settings_from_env({"ALLOWED_ORIGINS": "*"})
