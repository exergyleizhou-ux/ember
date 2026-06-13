"""
单元测试: scanner.OpenAPI.load — 端点分类是扫描器的地基,
分错类会导致整轮扫描打错端点。这里固定它的分类规则。
"""

import textwrap

import pytest


@pytest.fixture()
def spec_file(tmp_path):
    """写一个最小 openapi.yaml,覆盖四种安全语义。"""
    spec = textwrap.dedent(
        """
        openapi: 3.0.0
        info: {title: t, version: '1'}
        security:
          - bearerAuth: []
        paths:
          /auth/login:
            post:
              security: []          # 明确公开
              responses: {'200': {description: ok}}
          /datasets:
            get:
              responses: {'200': {description: ok}}   # 无 security → 继承全局 JWT
          /admin/users:
            get:
              responses: {'200': {description: ok}}   # /admin/ → admin
          /orders:
            post:
              responses: {'200': {description: ok}}   # JWT + 已知限流
        """
    )
    path = tmp_path / "openapi.yaml"
    path.write_text(spec)
    return str(path)


def test_public_endpoint_classified_public(scanner_mod, spec_file):
    public, jwt, admin, rated = scanner_mod.OpenAPI.load(spec_file)
    public_paths = {e["path"] for e in public}
    assert "/auth/login" in public_paths


def test_inherited_security_is_jwt(scanner_mod, spec_file):
    public, jwt, admin, rated = scanner_mod.OpenAPI.load(spec_file)
    jwt_paths = {e["path"] for e in jwt}
    # 缺省 security 应继承全局 bearerAuth,被归为 JWT 而非公开
    assert "/datasets" in jwt_paths
    assert "/datasets" not in {e["path"] for e in public}


def test_admin_endpoint_classified_admin(scanner_mod, spec_file):
    public, jwt, admin, rated = scanner_mod.OpenAPI.load(spec_file)
    assert "/admin/users" in {e["path"] for e in admin}


def test_known_rate_limited_endpoint_flagged(scanner_mod, spec_file):
    public, jwt, admin, rated = scanner_mod.OpenAPI.load(spec_file)
    rated_paths = {e["path"] for e in rated}
    # /auth/login 与 /orders 都在 RATE_LIMITS 里,应进入限流组
    assert "/orders" in rated_paths
    assert "/auth/login" in rated_paths
    # 限流元数据应被挂上
    orders = next(e for e in rated if e["path"] == "/orders")
    assert orders["rate_limit"]["limit"] == 20
