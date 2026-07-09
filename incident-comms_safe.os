#! Incident-comms gate — untrusted a status update can only ever become one of a fixed set of decisions over a
#! closed type, never a tool argument. An injected instruction cannot be represented in the
#! closed type, so it is rejected at the trust boundary (and re-clamped at run time by extract).
#! @requires publishStatus — the incident-comms gate sink
#! @effect io
#! @irreversible
#! @taint bridge — extract<Decision> turns the tainted input into a trusted decision
grant publishStatus irreversible

type StatusKind = Investigating | Identified | Resolved
type Decision = PublishStatus(StatusKind) | HoldStatus

let raw = fetch<web>  # UNTRUSTED a status update — tainted
quarantined { let d = extract<Decision>(raw) }  # only a fixed Decision (payloads too) crosses
commit { publishStatus(d) }  # act on the trusted decision only
