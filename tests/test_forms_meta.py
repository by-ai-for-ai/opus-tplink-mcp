from mcp_tplink_router.forms import stable


def test_stable_ignores_uci_meta_renumbering():
    """Live: after a remove the router renumbered the surviving row's .name (cfg0a5c3d -> cfg085c3d)."""
    before = {"mac": "02-00-5E-00-53-BF", ".name": "cfg0a5c3d", ".anonymous": True, ".type": "black_list", "name": "x"}
    after = dict(before, **{".name": "cfg085c3d"})
    path = "access_control?form=black_list"
    assert stable(path, before) == stable(path, after)
    assert stable(path, before) != stable(path, dict(after, name="y"))
