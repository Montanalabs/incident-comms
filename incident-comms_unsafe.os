#! VULNERABLE incident-comms — feeds the untrusted input straight to the tool, no extraction.
#! check -> UNSAFE: tainted data cannot reach a capability.
grant publishStatus irreversible

let raw = fetch<web>
commit { publishStatus(raw) }  # tainted -> tool: REJECTED
