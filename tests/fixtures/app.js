// SYNTHETIC FIXTURE — fake JS to exercise critlover's greppers; not a real app, not exploitable.
// Exists only so sink-grep.sh (JS coverage) and authz-census.sh (express) have deterministic matches.
const cp = require("child_process");
cp.exec(userInput);                                        // exec sink (js: child_process)
const o = require("node-serialize").unserialize(reqBody);  // deser sink (js: node-serialize)
const v = eval(req.body.x);                                // exec sink (js: eval)

const r = express.Router();
r.post("/pay", handler);     // route declared on a NON-framework var name (r), with a path-string arg
app.use(authMiddleware);     // global middleware mount
