from kali_mcp.core.output import limit_output_pair, sanitize_output, truncate_text


def test_sanitize_output_removes_ansi_and_progress_frames():
    raw = "\x1b[32mfound\x1b[0m\r\n[====>  ] 40%\r\n[=====> ] 80%\r\nspinner |\n"
    assert sanitize_output(raw) == "found\nspinner |"


def test_truncate_text_keeps_head_and_tail():
    limited = truncate_text("abcdefghij", 8)
    assert limited.truncated
    assert len(limited.text) == 8
    assert limited.text.startswith("abc")
    assert limited.text.endswith("j")


def test_limit_output_pair_reserves_space_for_stderr():
    stdout, stderr, truncated = limit_output_pair("A" * 1000, "B" * 500, 1000)
    assert truncated
    assert len(stdout) + len(stderr) <= 1000
    assert stdout.startswith("A")
    assert stderr.endswith("B")
