import pytest

from attack_qa.clean import clean_text, convert_attack_links


class TestConvertAttackLinks:
    def test_sub_technique_link_uses_dotted_id(self) -> None:
        text = "[Visual Basic](https://attack.mitre.org/techniques/T1059/005)"
        assert convert_attack_links(text) == "Visual Basic (T1059.005)"

    def test_technique_link(self) -> None:
        text = "[Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059)"
        assert convert_attack_links(text) == "Command and Scripting Interpreter (T1059)"

    def test_software_link(self) -> None:
        text = "[Empire](https://attack.mitre.org/software/S0363)"
        assert convert_attack_links(text) == "Empire (S0363)"

    def test_tactic_link(self) -> None:
        text = "[Execution](https://attack.mitre.org/tactics/TA0002)"
        assert convert_attack_links(text) == "Execution (TA0002)"

    def test_several_links_in_a_sentence(self) -> None:
        text = (
            "Tools like [Empire](https://attack.mitre.org/software/S0363) and "
            "[PowerSploit](https://attack.mitre.org/software/S0194) run "
            "[PowerShell](https://attack.mitre.org/techniques/T1059/001)."
        )
        assert convert_attack_links(text) == (
            "Tools like Empire (S0363) and PowerSploit (S0194) run PowerShell (T1059.001)."
        )

    def test_text_without_links_is_unchanged(self) -> None:
        text = "Adversaries may abuse [brackets] and (parentheses) in prose."
        assert convert_attack_links(text) == text

    def test_does_not_mutate_input(self) -> None:
        text = "[Empire](https://attack.mitre.org/software/S0363)"
        convert_attack_links(text)
        assert text == "[Empire](https://attack.mitre.org/software/S0363)"


class TestCleanText:
    def test_removes_citations(self) -> None:
        text = "environment.(Citation: TechNet PowerShell) Adversaries can use it."
        assert clean_text(text) == "environment. Adversaries can use it."

    def test_removes_back_to_back_citations(self) -> None:
        text = "Seen in the wild.(Citation: ClearSky 2020)(Citation: McAfee 2020)"
        assert clean_text(text) == "Seen in the wild."

    def test_keeps_code_content_without_tags(self) -> None:
        text = "Examples include the <code>Start-Process</code> cmdlet."
        assert clean_text(text) == "Examples include the Start-Process cmdlet."

    def test_keeps_placeholders_inside_paths(self) -> None:
        text = r"Files in <code>C:\Users\<username>\AppData</code> are checked."
        assert clean_text(text) == r"Files in C:\Users\<username>\AppData are checked."

    def test_collapses_spaces_left_by_removals(self) -> None:
        text = "One  (Citation: A)  two"
        assert clean_text(text) == "One two"

    @pytest.mark.parametrize(
        "raw, expected",
        [
            (
                "[Rundll32](https://attack.mitre.org/techniques/T1218/011)(Citation: X) is abused.",
                "Rundll32 (T1218.011) is abused.",
            ),
            ("", ""),
        ],
    )
    def test_end_to_end(self, raw: str, expected: str) -> None:
        assert clean_text(raw) == expected
