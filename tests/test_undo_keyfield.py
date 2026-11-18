"""Undo of an insert must still find the row when the router normalises a stored field."""
from mcp_tplink_router import catalog, forms


def test_find_rows_by_key_when_fields_normalised():
    path = "access_control?form=white_list"
    ep = catalog.get(path)
    assert ep is not None and ep.key_field == "mac"
    sent = {"mac": "02-00-00-00-00-06", "name": "claudetest", "deviceType": "other", "host": "NON_HOST"}
    stored = [{"mac": "02-00-00-00-00-06", "name": "claudetest", "deviceType": "Mobile", "host": "NON_HOST"},
              {"mac": "00-00-5E-00-53-78", "name": "Kid phone", "deviceType": "Mobile", "host": "NON_HOST"}]
    assert forms.find_matching(stored, sent, path) == []
    assert forms.find_rows(stored, "mac", sent["mac"]) == [0]
