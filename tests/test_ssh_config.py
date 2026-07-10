"""Tests for :mod:`bw_forge_ctl.ssh_config`."""

from pathlib import Path

from bw_forge_ctl.ssh_config import (
    SshConfigStanza,
    add_stanza,
    find_stanza_index,
    format_stanza,
    generate_git_stanza,
    list_stanzas,
    make_stanza,
    parse_config,
    read_config,
    remove_stanza,
    write_config,
)

SAMPLE_CONFIG = """# Global comment
# Another comment

Host github.skp1964-dev.com
    HostName github.com
    User git
    IdentityFile ~/.ssh/id_ed25519-skp1964.dev@outlook.com
    AddKeysToAgent yes
    IdentitiesOnly yes

Host gitlab.skpproj01.com
    HostName gitlab.com
    User git
    IdentityFile ~/.ssh/id_ed25519-skpdev19640101@gmail.com
    IdentitiesOnly yes

Host github.com
    HostName github.com
    User git
    IdentityFile ~/.ssh/id_ed25519-default@example.com
    AddKeysToAgent yes
    IdentitiesOnly yes
"""


# --------------------------------------------------------------------------- #
# parse_config
# --------------------------------------------------------------------------- #


class TestParseConfig:
    def test_empty_string(self):
        preamble, stanzas = parse_config("")
        assert preamble == ""
        assert stanzas == []

    def test_comments_only(self):
        text = "# just comments\n# still comments\n"
        preamble, stanzas = parse_config(text)
        assert preamble == text
        assert stanzas == []

    def test_single_stanza(self):
        text = "Host foo\n    HostName example.com\n"
        preamble, stanzas = parse_config(text)
        assert preamble == ""
        assert len(stanzas) == 1
        assert stanzas[0].hosts == ["foo"]
        assert stanzas[0].options == [("HostName", "example.com")]

    def test_preamble_and_stanza(self):
        text = "# global\n\nHost foo\n    HostName x.com\n"
        preamble, stanzas = parse_config(text)
        assert "# global\n\n" in preamble
        assert len(stanzas) == 1
        assert stanzas[0].hosts == ["foo"]

    def test_multiple_stanzas(self):
        preamble, stanzas = parse_config(SAMPLE_CONFIG)
        assert "Global comment" in preamble
        assert len(stanzas) == 3
        assert stanzas[0].hosts == ["github.skp1964-dev.com"]
        assert stanzas[1].hosts == ["gitlab.skpproj01.com"]
        assert stanzas[2].hosts == ["github.com"]

    def test_host_with_multiple_patterns(self):
        text = "Host foo bar\n    HostName x.com\n"
        preamble, stanzas = parse_config(text)
        assert len(stanzas) == 1
        assert stanzas[0].hosts == ["foo", "bar"]

    def test_case_insensitive_host_directive(self):
        text = "HOST foo\n    HostName x.com\n"
        preamble, stanzas = parse_config(text)
        assert len(stanzas) == 1
        assert stanzas[0].hosts == ["foo"]

    def test_raw_preserved(self):
        _, stanzas = parse_config(SAMPLE_CONFIG)
        assert "github.skp1964-dev.com" in stanzas[0].raw
        assert "skpproj01.com" in stanzas[1].raw


# --------------------------------------------------------------------------- #
# find_stanza_index
# --------------------------------------------------------------------------- #


class TestFindStanzaIndex:
    def test_finds_by_host(self):
        _, stanzas = parse_config(SAMPLE_CONFIG)
        idx = find_stanza_index(stanzas, "github.skp1964-dev.com")
        assert idx == 0

    def test_case_insensitive(self):
        _, stanzas = parse_config(SAMPLE_CONFIG)
        idx = find_stanza_index(stanzas, "GITHUB.SKP1964-DEV.COM")
        assert idx == 0

    def test_not_found(self):
        _, stanzas = parse_config(SAMPLE_CONFIG)
        idx = find_stanza_index(stanzas, "nonexistent.host.com")
        assert idx is None

    def test_empty_list(self):
        assert find_stanza_index([], "foo") is None


# --------------------------------------------------------------------------- #
# make_stanza / generate_git_stanza
# --------------------------------------------------------------------------- #


class TestMakeStanza:
    def test_minimal(self):
        s = make_stanza("test.host", "example.com", user="git")
        assert s.hosts == ["test.host"]
        assert ("HostName", "example.com") in s.options
        assert ("User", "git") in s.options
        assert s.modified is True

    def test_with_identity_file(self):
        s = make_stanza("h", "e.com", identity_file="mykey")
        assert ("IdentityFile", "~/.ssh/mykey") in s.options

    def test_with_absolute_identity_path(self):
        s = make_stanza("h", "e.com", identity_file="/home/u/.ssh/key")
        assert ("IdentityFile", "/home/u/.ssh/key") in s.options

    def test_default_options(self):
        s = make_stanza("h", "e.com")
        opts = dict(s.options)
        assert opts.get("HostName") == "e.com"
        assert opts.get("User") == "git"
        assert opts.get("AddKeysToAgent") == "yes"
        assert opts.get("IdentitiesOnly") == "yes"
        assert "ForwardAgent" not in opts

    def test_forward_agent(self):
        s = make_stanza("h", "e.com", forward_agent=True)
        assert ("ForwardAgent", "yes") in s.options

    def test_no_add_keys_to_agent(self):
        s = make_stanza("h", "e.com", add_keys_to_agent=False)
        opts = dict(s.options)
        assert "AddKeysToAgent" not in opts

    def test_no_identities_only(self):
        s = make_stanza("h", "e.com", identities_only=False)
        opts = dict(s.options)
        assert "IdentitiesOnly" not in opts

    def test_with_comment(self):
        s = make_stanza("h", "e.com", comment="test: my-account")
        assert "# test: my-account\n" in s.raw


class TestGenerateGitStanza:
    def test_github(self):
        s = generate_git_stanza("github", "skp1964-dev", "id_ed25519-dev@outlook.com")
        assert s.hosts == ["github.skp1964-dev.com"]
        assert ("HostName", "github.com") in s.options
        assert ("IdentityFile", "~/.ssh/id_ed25519-dev@outlook.com") in s.options

    def test_gitlab(self):
        s = generate_git_stanza("gitlab", "skp64prj", "id_ed25519-skp64prj@gmail.com")
        assert s.hosts == ["gitlab.skp64prj.com"]
        assert ("HostName", "gitlab.com") in s.options

    def test_includes_comment(self):
        s = generate_git_stanza("github", "my-acct", "mykey")
        assert "# github: my-acct" in s.raw

    def test_add_keys_to_agent_default(self):
        s = generate_git_stanza("github", "a", "k")
        assert ("AddKeysToAgent", "yes") in s.options


# --------------------------------------------------------------------------- #
# format_stanza
# --------------------------------------------------------------------------- #


class TestFormatStanza:
    def test_unmodified_returns_raw(self):
        s = SshConfigStanza(
            hosts=["foo"],
            options=[("HostName", "x.com")],
            raw="Host foo\n    HostName x.com\n",
            modified=False,
        )
        assert format_stanza(s) == "Host foo\n    HostName x.com\n"

    def test_modified_regenerates(self):
        s = make_stanza("foo", "x.com")
        formatted = format_stanza(s)
        assert "Host foo" in formatted
        assert "HostName x.com" in formatted

    def test_modified_preserves_comment(self):
        s = make_stanza("foo", "x.com", comment="my comment")
        formatted = format_stanza(s)
        assert "# my comment\n" in formatted
        assert "Host foo" in formatted


# --------------------------------------------------------------------------- #
# read_config / write_config / add_stanza / remove_stanza
# --------------------------------------------------------------------------- #


class TestReadWriteConfig:
    def test_read_nonexistent(self, tmp_path):
        p = tmp_path / "nope" / "config"
        pre, stanzas = read_config(str(p))
        assert pre == ""
        assert stanzas == []

    def test_write_and_read_back(self, tmp_path):
        p = str(tmp_path / "config")
        s1 = make_stanza("host-a", "a.example.com")
        s2 = make_stanza("host-b", "b.example.com")
        write_config("", [s1, s2], path=p)

        pre, stanzas = read_config(p)
        assert pre == ""
        assert len(stanzas) == 2
        assert stanzas[0].hosts == ["host-a"]
        assert stanzas[1].hosts == ["host-b"]

    def test_write_with_preamble(self, tmp_path):
        p = str(tmp_path / "config")
        s = make_stanza("h", "e.com")
        write_config("# preamble\n", [s], path=p)

        pre, stanzas = read_config(p)
        assert "preamble" in pre
        assert len(stanzas) == 1


class TestAddStanza:
    def test_adds_new_stanza(self, tmp_path):
        p = str(tmp_path / "config")
        s = make_stanza("new.host", "x.com")
        added = add_stanza(s, path=p)
        assert added is True

        _, stanzas = read_config(p)
        assert len(stanzas) == 1
        assert stanzas[0].hosts == ["new.host"]

    def test_updates_existing_stanza(self, tmp_path):
        p = str(tmp_path / "config")
        s1 = make_stanza("my.host", "old.com")
        add_stanza(s1, path=p)

        s2 = make_stanza("my.host", "new.com")
        added = add_stanza(s2, path=p)
        assert added is False

        _, stanzas = read_config(p)
        assert len(stanzas) == 1
        opts = dict(stanzas[0].options)
        assert opts["HostName"] == "new.com"

    def test_add_preserves_other_stanzas(self, tmp_path):
        p = str(tmp_path / "config")
        s1 = make_stanza("host-a", "a.com")
        s2 = make_stanza("host-b", "b.com")
        write_config("", [s1, s2], path=p)

        s3 = make_stanza("host-c", "c.com")
        add_stanza(s3, path=p)

        _, stanzas = read_config(p)
        assert len(stanzas) == 3
        assert [s.hosts[0] for s in stanzas] == ["host-a", "host-b", "host-c"]


class TestRemoveStanza:
    def test_removes_existing(self, tmp_path):
        p = str(tmp_path / "config")
        s = make_stanza("gone.host", "x.com")
        add_stanza(s, path=p)
        assert remove_stanza("gone.host", path=p) is True

        _, stanzas = read_config(p)
        assert len(stanzas) == 0

    def test_remove_nonexistent(self, tmp_path):
        p = str(tmp_path / "config")
        assert remove_stanza("nope", path=p) is False

    def test_remove_preserves_other_stanzas(self, tmp_path):
        p = str(tmp_path / "config")
        s1 = make_stanza("host-a", "a.com")
        s2 = make_stanza("host-b", "b.com")
        write_config("", [s1, s2], path=p)

        remove_stanza("host-a", path=p)
        _, stanzas = read_config(p)
        assert len(stanzas) == 1
        assert stanzas[0].hosts == ["host-b"]


class TestListStanzas:
    def test_returns_all_stanzas(self, tmp_path):
        p = str(tmp_path / "config")
        s1 = make_stanza("a.host", "a.com")
        s2 = make_stanza("b.host", "b.com")
        write_config("", [s1, s2], path=p)

        stanzas = list_stanzas(path=p)
        assert len(stanzas) == 2

    def test_empty_file(self, tmp_path):
        p = str(tmp_path / "config")
        Path(p).write_text("")
        assert list_stanzas(path=p) == []


# --------------------------------------------------------------------------- #
# Roundtrip with real-world config
# --------------------------------------------------------------------------- #


class TestRoundtrip:
    def test_preserves_preamble_and_stanzas(self, tmp_path):
        p = str(tmp_path / "config")
        p_obj = Path(p)
        p_obj.write_text(SAMPLE_CONFIG)

        pre, stanzas = read_config(p)
        assert "Global comment" in pre
        assert len(stanzas) == 3

        write_config(pre, stanzas, path=p)
        result = p_obj.read_text()
        assert "Global comment" in result
        assert "github.skp1964-dev.com" in result
        assert "gitlab.skpproj01.com" in result
        assert "github.com" in result
        assert "id_ed25519-skp1964.dev@outlook.com" in result

    def test_add_and_remove_roundtrip(self, tmp_path):
        p = str(tmp_path / "config")
        p_obj = Path(p)
        p_obj.write_text(SAMPLE_CONFIG)

        s = make_stanza("new.acct", "example.com", comment="new account")
        add_stanza(s, path=p)

        pre, stanzas = read_config(p)
        assert len(stanzas) == 4
        assert stanzas[-1].hosts == ["new.acct"]

        remove_stanza("new.acct", path=p)
        _, stanzas = read_config(p)
        assert len(stanzas) == 3


class TestGitAcctInstallHook:
    def test_install_ssh_config_stanza(self, tmp_path):
        from bw_forge_ctl.gitacct import install_ssh_config_stanza

        p = str(tmp_path / "config")
        added = install_ssh_config_stanza(
            "github", "test-user", "id_ed25519-test@example.com",
            ssh_config_path=p,
        )
        assert added is True

        _, stanzas = read_config(p)
        assert len(stanzas) == 1
        assert stanzas[0].hosts == ["github.test-user.com"]
        opts = dict(stanzas[0].options)
        assert opts["IdentityFile"] == "~/.ssh/id_ed25519-test@example.com"
        assert opts["AddKeysToAgent"] == "yes"

    def test_install_updates_existing(self, tmp_path):
        from bw_forge_ctl.gitacct import install_ssh_config_stanza

        p = str(tmp_path / "config")
        install_ssh_config_stanza("github", "u1", "old-key", ssh_config_path=p)
        added = install_ssh_config_stanza("github", "u1", "new-key", ssh_config_path=p)
        assert added is False

        _, stanzas = read_config(p)
        assert len(stanzas) == 1
        opts = dict(stanzas[0].options)
        assert opts["IdentityFile"] == "~/.ssh/new-key"
