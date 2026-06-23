from mcpscanner_web.noise import NOISE_PATTERNS, is_noise


def test_patterns_constant_nonempty():
    assert isinstance(NOISE_PATTERNS, list)
    assert "**/*.md" in NOISE_PATTERNS


def test_test_files_are_noise():
    assert is_noise("src/foo_test.py")
    assert is_noise("pkg/foo.test.js")
    assert is_noise("a/tests/b/c.py")
    assert is_noise("x/__tests__/y.js")
    assert is_noise("a/b.spec.ts")
    assert is_noise("snaps/__toolsnaps__/x.json")
    assert is_noise("comp/Button.snap")


def test_lock_and_manifest_noise():
    assert is_noise("yarn.lock")
    assert is_noise("sub/package-lock.json")
    assert is_noise("go.sum")
    assert is_noise("uv.lock")
    assert is_noise("anything.lock")


def test_vcs_generated_docs_ci_scripts():
    assert is_noise(".git/objects/ab/cd")
    assert is_noise("pkg/generated/types.go")
    assert is_noise("a/b.gen.ts")
    assert is_noise("dist/bundle.js")
    assert is_noise("build/out.o")
    assert is_noise("docs/guide.md")
    assert is_noise("README.md")
    assert is_noise(".github/workflows/ci.yml")
    assert is_noise("script/setup")
    assert is_noise("tools/run.sh")


def test_real_source_is_not_noise():
    assert not is_noise("src/server.py")
    assert not is_noise("mcpscanner/core/scanner.py")
    assert not is_noise("app/handlers/auth.go")


def test_classification_is_case_insensitive_and_slash_normalized():
    assert is_noise("SRC\\FOO_TEST.PY".replace("\\", "/"))
    assert is_noise("DOCS/GUIDE.MD")
