"""Every response the tests get from the API is checked against the OpenAPI document (D21):
its status must be one the operation documents, and a JSON body must match the schema
documented for it. A request that succeeds must also use only documented parameters."""
import json
import os

import flask
from flask.testing import FlaskClient
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
with open(os.path.join(ROOT, "threatbridge", "openapi.json"), encoding="utf-8") as fh:
    OPENAPI = json.load(fh)
_REGISTRY = Registry().with_resource("urn:openapi", Resource.from_contents(OPENAPI, DRAFT202012))


def schema_error(instance, pointer):
    """The first way `instance` fails the schema at `pointer` in the document, or None."""
    validator = Draft202012Validator({"$ref": f"urn:openapi#{pointer}"}, registry=_REGISTRY)
    error = next(iter(validator.iter_errors(instance)), None)
    return error and f"{error.message} at {'/'.join(map(str, error.absolute_path)) or 'the top'}"


def _pointer(*parts):
    return "".join("/" + str(p).replace("~", "~0").replace("/", "~1") for p in parts)


def resolve(node, pointer):
    """(node, its pointer), following a $ref within the document."""
    while "$ref" in node:
        pointer = node["$ref"][1:]
        node = OPENAPI
        for part in pointer.split("/")[1:]:
            node = node[part.replace("~1", "/").replace("~0", "~")]
    return node, pointer


CALLED = set()   # (METHOD, path, status) of every API response checked


def check_response(resp, body=None):
    """`body`: the JSON sent, if any."""
    request = resp.request
    path, method = request.path, request.method.lower()
    if path == "/" or path.startswith("/static/"):          # the map itself, not the API
        return
    CALLED.add((method.upper(), path, resp.status_code))
    operation = OPENAPI["paths"].get(path, {}).get(method)
    if operation is None and method != "get" and resp.status_code == 403:
        return                  # any write without the header is refused first, served or not
    assert operation, f"{method.upper()} {path} is not in openapi.json"
    status = str(resp.status_code)
    assert status in operation["responses"], f"{method.upper()} {path}: status {status} is not documented"
    documented, at = resolve(operation["responses"][status], _pointer("paths", path, method, "responses", status))
    content = documented.get("content", {})
    if resp.mimetype == "application/json":
        assert "application/json" in content, f"{method.upper()} {path} {status}: JSON is not documented"
        error = schema_error(resp.get_json(), at + _pointer("content", "application/json", "schema"))
        assert error is None, f"{method.upper()} {path} {status}: {error}"
    else:
        assert resp.mimetype in content, f"{method.upper()} {path} {status}: {resp.mimetype} is not documented"
    if resp.status_code < 300:
        check_request(request, body, operation, path, method)


def check_request(request, body, operation, path, method):
    params = [resolve(p, "")[0] for p in operation.get("parameters", [])]
    documented = {p["name"] for p in params if p["in"] == "query"}
    assert set(request.args) <= documented, f"{method.upper()} {path}: undocumented {set(request.args) - documented}"
    if body is not None:
        error = schema_error(body, _pointer("paths", path, method, "requestBody", "content", "application/json",
                                            "schema"))
        assert error is None, f"{method.upper()} {path} request: {error}"


class CheckedClient(FlaskClient):
    def open(self, *args, **kwargs):
        resp = super().open(*args, **kwargs)
        body = kwargs.get("json")
        if body is None and isinstance(kwargs.get("data"), (str, bytes)):
            try:
                body = json.loads(kwargs["data"])
            except ValueError:
                pass
        check_response(resp, body)
        return resp


flask.Flask.test_client_class = CheckedClient
