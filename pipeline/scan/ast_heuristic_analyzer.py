"""Narrow Flask IDOR candidate discovery, not an authorization proof.

Recognizes literal @app/@blueprint .route/.get/.post/.put/.patch/.delete rules,
ID-like path parameters used directly (or in an expression) in get/query/execute/
filter/filter_by calls, including dictionary get used by the local fixture.
Recognizes inline deny guards comparing that ID, or a fetched resource's owner,
with common identity names, session/current_user/g.user, or token-derived aliases.
A fetched-resource guard must precede further use of that resource. A bare compare,
logging-only branch, nested helper, or guard after a response is not sufficient.

No type inference, interprocedural analysis, SQL parsing, general control-flow
proof, alias analysis for resource IDs, or support for other frameworks. Decorator,
middleware, helper-based checks, query-scoped ownership, complex branch/loop guards,
and unconventional identity/owner names can produce false positives. Name-based
identity and storage recognition can be wrong. Public resources may be flagged.
Only simple straight-line handlers and top-level deny guards are recognized.
"""

import ast
from dataclasses import dataclass
from pathlib import Path
import re
import tokenize

try:
    from .common import ScanError, repo_directory, run_cli
except ImportError:
    from common import ScanError, repo_directory, run_cli


@dataclass(frozen=True)
class HeuristicFinding:
    file: str
    line: int
    function_name: str
    heuristic_id: str
    confidence: str
    reason: str


ROUTES = {"route", "get", "post", "put", "patch", "delete", "head", "options"}
LOOKUPS = {"execute", "executemany", "query", "get", "get_or_404", "filter", "filter_by"}
IDENTITIES = {"current_user", "user_id", "authenticated_user", "authenticated_user_id", "auth_user", "uid"}
OWNERS = {"owner", "owner_id", "user_id", "created_by", "author_id"}
SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__"}


def walk_local(node):
    """Walk an expression/statement without treating nested function bodies as inline."""
    yield node
    for child in ast.iter_child_nodes(node):
        if not isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            yield from walk_local(child)


def uses(node, names):
    return any(isinstance(n, ast.Name) and n.id in names for n in walk_local(node))


def authenticated(node, aliases, route_ids):
    for n in walk_local(node):
        if isinstance(n, ast.Name) and n.id in (IDENTITIES | aliases) - route_ids:
            return True
        if isinstance(n, ast.Subscript) and isinstance(n.value, ast.Name) and n.value.id == "session":
            return True
        if isinstance(n, ast.Attribute):
            text = ast.unparse(n)
            if text in {"g.user", "request.authorization"} or text.startswith(("g.user.", "request.authorization.")):
                return True
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute):
            if ast.unparse(n.func) in {"session.get", "request.headers.get"}:
                keys = [a.value.lower() for a in n.args if isinstance(a, ast.Constant) and isinstance(a.value, str)]
                if any(k in {"authorization", "user_id", "uid", "user", "x-auth-token"} for k in keys):
                    return True
    return False


def route_parameters(function):
    params = set()
    arguments = {a.arg for a in function.args.posonlyargs + function.args.args + function.args.kwonlyargs}
    for decorator in function.decorator_list:
        if not (isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute)
                and decorator.func.attr in ROUTES):
            continue
        paths = list(decorator.args[:1]) + [k.value for k in decorator.keywords if k.arg == "rule"]
        for path in paths:
            if isinstance(path, ast.Constant) and isinstance(path.value, str):
                for name in re.findall(r"<(?:[^<>:]+:)?([A-Za-z_]\w*)>", path.value):
                    if name in arguments and (name.lower() in {"id", "pk", "uuid"} or
                                             name.lower().endswith(("_id", "_pk", "_uuid"))):
                        params.add(name)
    return params


def owner_of(node, resources):
    if isinstance(node, ast.Attribute):
        return node.attr in OWNERS and uses(node.value, resources)
    if isinstance(node, ast.Subscript):
        return (isinstance(node.slice, ast.Constant) and node.slice.value in OWNERS
                and uses(node.value, resources))
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "get":
        return (uses(node.func.value, resources) and bool(node.args) and
                isinstance(node.args[0], ast.Constant) and node.args[0].value in OWNERS)
    return False


def rejects(body):
    # Require an unconditional first-statement rejection. Arbitrary returns may leak data.
    if not body:
        return False
    first = body[0]
    if isinstance(first, ast.Raise):
        return True
    if isinstance(first, ast.Expr) and isinstance(first.value, ast.Call):
        call = first.value
        return (ast.unparse(call.func) in {"abort", "flask.abort"} and bool(call.args)
                and isinstance(call.args[0], ast.Constant) and call.args[0].value in {401, 403, 404})
    if isinstance(first, ast.Return) and isinstance(first.value, ast.Tuple):
        values = first.value.elts
        payload = values[0] if values else None
        if isinstance(payload, ast.Call) and ast.unparse(payload.func) in {'jsonify', 'flask.jsonify'}:
            payload = payload.args[0] if len(payload.args) == 1 and not payload.keywords else None
        try:
            ast.literal_eval(payload)
            static_payload = True
        except (ValueError, TypeError):
            static_payload = False
        return (len(values) >= 2 and static_payload
                and isinstance(values[1], ast.Constant) and values[1].value in {401, 403, 404})
    return False


def assigned_lookup(value, call):
    while isinstance(value, ast.Call) and isinstance(value.func, ast.Attribute):
        if value is call:
            return True
        if value.func.attr not in {'fetchone', 'first', 'one', 'one_or_none'}:
            break
        value = value.func.value
    return False


def ownership_guard(statement, ids, resources, aliases, route_ids):
    if not isinstance(statement, ast.If) or not isinstance(statement.test, ast.Compare):
        return False
    test = statement.test
    if len(test.ops) != 1:
        return False
    left, right = test.left, test.comparators[0]
    related = lambda n: (isinstance(n, ast.Name) and n.id in ids) or owner_of(n, resources)
    pair = ((related(left) and authenticated(right, aliases, route_ids)) or
            (related(right) and authenticated(left, aliases, route_ids)))
    if not pair:
        return False
    return ((isinstance(test.ops[0], ast.NotEq) and rejects(statement.body)) or
            (isinstance(test.ops[0], ast.Eq) and rejects(statement.orelse)))


def analyze_function(function, filename):
    route_ids = route_parameters(function)
    if not route_ids:
        return []
    aliases = set()
    prechecked = set()
    pending = []
    for statement in function.body:
        # Only guards seen in straight-line order before lookup/use can suppress a candidate.
        for parameter in route_ids:
            if ownership_guard(statement, {parameter}, set(), aliases, route_ids):
                prechecked.add(parameter)
        for entry in pending:
            if not entry["used"] and ownership_guard(statement, set(), entry["resources"], aliases, route_ids):
                entry["guarded"] = True
            if uses(statement, entry["resources"]):
                # Missing-resource checks are allowed between a fetch and its ownership check.
                none_test = (isinstance(statement, ast.If) and isinstance(statement.test, ast.Compare) and
                                 len(statement.test.ops) == 1 and
                                 isinstance(statement.test.ops[0], ast.Is) and
                                 isinstance(statement.test.comparators[0], ast.Constant) and
                                 statement.test.comparators[0].value is None)
                falsey_test = (isinstance(statement, ast.If) and isinstance(statement.test, ast.UnaryOp)
                               and isinstance(statement.test.op, ast.Not)
                               and isinstance(statement.test.operand, ast.Name)
                               and statement.test.operand.id in entry['resources'])
                missing_check = ((none_test or falsey_test) and rejects(statement.body) and not statement.orelse)
                if not missing_check:
                    entry["used"] = True
        calls = [n for n in walk_local(statement) if isinstance(n, ast.Call)
                 and isinstance(n.func, ast.Attribute) and n.func.attr in LOOKUPS]
        for call in calls:
            arguments = call.args + [k.value for k in call.keywords]
            for parameter in sorted(route_ids):
                if not any(uses(arg, {parameter}) for arg in arguments) or parameter in prechecked:
                    continue
                resources = set()
                if isinstance(statement, (ast.Assign, ast.AnnAssign)) and assigned_lookup(statement.value, call):
                    targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                    resources = {t.id for t in targets if isinstance(t, ast.Name)}
                pending.append({"parameter": parameter, "call": call, "resources": resources,
                                "guarded": False, "used": False})
        if isinstance(statement, (ast.Assign, ast.AnnAssign)) and statement.value is not None:
            targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
            for target in targets:
                if isinstance(target, ast.Name):
                    if authenticated(statement.value, aliases, route_ids):
                        aliases.add(target.id)
                    else:
                        aliases.discard(target.id)
                    prechecked.discard(target.id)
        # Comparisons inside branching/loops aren't promoted to globally valid guards.
        if isinstance(statement, (ast.If, ast.For, ast.While, ast.Try, ast.With, ast.Match)):
            assigned = {n.id for n in walk_local(statement) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)}
            prechecked.difference_update(assigned)
        if isinstance(statement, (ast.Return, ast.Raise)):
            break
    return [HeuristicFinding(filename, item["call"].lineno, function.name, "IDOR-AST-01", "MEDIUM",
                             f"Flask route parameter '{item['parameter']}' reaches {ast.unparse(item['call'].func)}() "
                             f"at line {item['call'].lineno}. No recognized inline ownership deny guard compares "
                             "the parameter with an authenticated identity before lookup, or the fetched resource's "
                             "owner with that identity before further use. Authentication alone does not establish "
                             "ownership. This is a static candidate, not a confirmed IDOR.")
            for item in pending if not item["guarded"]]


def scan(repo_path, timeout=180):
    repo = repo_directory(repo_path)
    findings = []
    for path in sorted(repo.rglob("*.py")):
        relative = path.relative_to(repo)
        if any(part in SKIP_DIRS for part in relative.parts) or path.is_symlink():
            continue
        try:
            with tokenize.open(path) as handle:
                tree = ast.parse(handle.read(), filename=str(relative))
        except (SyntaxError, UnicodeError, OSError) as exc:
            raise ScanError(f"Cannot parse {relative}: {exc}") from exc
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                findings.extend(analyze_function(node, str(relative)))
    return findings


if __name__ == "__main__":
    raise SystemExit(run_cli(__doc__, scan))
