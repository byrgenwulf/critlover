# SYNTHETIC FIXTURE — fake code to exercise critlover's greppers; not a real app, not exploitable.
#
# It declares two routes — a GUARDED read-only GET and an UNGUARDED, state-changing
# POST — plus one deserialization sink and one code-exec sink, purely so that
# sink-grep.sh and authz-census.sh have deterministic matches to assert on.
# Nothing here is imported, served, or executed by the test suite.

import pickle

from fastapi import Depends, FastAPI

app = FastAPI()


def get_current_user(token: str = ""):
    """Stand-in auth dependency — never actually invoked."""
    return {"token": token}


@app.get("/items")
def list_items(user=Depends(get_current_user)):
    # GUARDED read-only route: Depends(get_current_user) is the auth gate.
    return {"items": []}


# UNGUARDED, state-changing route — intentionally has NO auth gate (synthetic).
@app.post("/items")
def create_item(request_body: bytes):
    obj = pickle.loads(request_body)   # deserialization sink (deser class)
    value = eval("1 + 1")              # code-exec sink (exec class)
    return {"ok": True, "obj": obj, "value": value}


# State-changing route whose ONLY dependency is a non-auth helper (get_db).
# A bare Depends(get_db) is NOT an auth guard, so ONLY_NONE=1 must still surface this.
@app.post("/transfer")
def transfer(db=Depends(get_db)):
    return {"ok": True}
