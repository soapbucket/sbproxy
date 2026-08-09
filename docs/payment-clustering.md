# Payment clustering

*Last modified: 2026-08-09*

A node that configures both `proxy.payments` and `proxy.cluster` refuses to
start. That refusal is the largest limitation on settlement: payments run on
one node, against one SQLite file, with the availability and backup story a
single file implies. This page records what would have to be true to lift it,
why the cluster mesh is not the substrate to lift it on, and what is.

## The refusal

`PaymentsRuntimeCandidate::build` checks for clustering before it creates a
directory or opens a database, so a node that cannot serve settlement
correctly does not leave a half-built ledger behind. The error names three
consequences: a challenge issued on one node cannot be redeemed on another,
replay protection stops at the node boundary so the same payment can settle
once per node, and a node lost before its worker drains leaves settlements no
other node will reconcile.

The first and third cost availability. The second costs money, and it is why
the check exists.

## What any design has to preserve

Six properties hold settlement together today. Five of them belong to the code
and survive any store you put underneath:

- The dispatch stamp is committed in its own transaction immediately before a
  provider write leaves the process, so a dropped timeout leaves the attempt
  ambiguous rather than losing the fact of the dispatch. A dispatched attempt
  with no recorded response can only move to `NeedsReconciliation`.
- Exactly one status authorizes the origin. `load_access_receipt` returns
  `None` for every state except `Succeeded`, and the request path re-reads the
  intent from durable storage at the decision boundary before it allows
  anything.
- Amounts are integer micros. Nothing rounds.
- No admin surface can mark a payment paid. Only a provider proving settlement
  can.
- The recovery worker cannot reach the settlement call at all. It is
  restricted to a provider status query.

The sixth belongs to the store, and it is the whole problem: one durable
single-serve nonce ledger, burned in a single `BEGIN IMMEDIATE` transaction
with `INSERT ON CONFLICT DO NOTHING`, where the affected row count is what
decides fresh from replayed.

A seventh property is bounded only in part, and the part that is not bounded
is deliberate. Nothing resolves an intent that sits in `NeedsReconciliation`
except a provider actually answering. The challenge expiry sweep only touches
`Pending` intents and skips any intent with a dispatched, unanswered attempt,
so a payment whose provider never answers waits for the recovery worker
however long that takes. That is the correct call: the wall clock passing a
challenge's expiry says nothing about whether funds moved, and resolving the
intent on a timer would send a payer whose money may already be gone back for
a second invoice.

What bounds the damage instead is scope, and scope has a hole in it. The guard
that withholds a fresh challenge matches on a derived payer key, so a stuck
payment normally withholds the route from the payer it stranded rather than
from everyone. An intent minted with no payer scope has no such key, and it
withholds the route from every caller on that route on the mere possibility
that one of them is the stranded payer. Those rows, and only those, now age
out. Past a grace window beyond the challenge expiry they move to
`IntentStatus::Stranded`, which releases the route gate and nothing else: the
attempt stays on the reconciliation queue, the failure category stays
`ambiguous`, no receipt is written, and the state authorizes no origin access.
The quote token signs its `exp` from the same column the deadline is measured
from, so past that instant no holder can redeem the intent however the funds
eventually land. A stranded intent still answers `Unavailable`, never
`challenge_expired`, which is what keeps the second invoice from being issued.

Distributing settlement means moving the nonce ledger onto something shared
without weakening it, and it means inheriting the reconciliation state as it
is, including the payer-scoped rows that no deadline touches. Clustering makes
that state worse in one specific way, which the plan below has to answer:
today the operator knows which node holds the stuck intent, because there is
one. On a cluster they will not.

## What has to be globally unique, and where

Three things are candidates, and they are not equivalent.

**The payment proof.** `consumed_payment_proofs` has a primary key of
`(tenant_id, proof_digest)`, and `payment_intents` carries a partial unique
index on `(tenant_id, reserved_proof_digest)`. Together they bind one proof to
one intent forever. This is double *charge* protection, and it is the older
half of the design.

**The quote nonce.** `served_quote_nonces` has `nonce` as its primary key.
This is double *serve* protection, and it is the newer half. It exists
because the request path used to burn nonces into an in-process set, which
meant a client re-presenting an already-settled quote token was served again
after a restart, once per restart, having paid exactly once.

**The intent row.** `payment_intents` is unique on
`(tenant_id, request_idempotency_key)`. This is not a serialization point in
the same sense. It makes a client retry address the same row instead of
minting a second challenge, and losing it costs a duplicate challenge rather
than a duplicate charge.

So there are two serialization points, not one, and they sit at different
places in the request. The proof reservation happens inside `authorize`,
before the provider write. The nonce burn happens after the settlement has
committed, after the intent has been re-read and confirmed `Succeeded`, and
immediately before the origin is called. Nothing else stands between the burn
and the response.

Both are a unique index in one SQLite file today, and both are burned in the
same transaction as the state they authorize. That colocation is the property
worth protecting, more than the index itself. Two facts about one payment
cannot end up in two files, so restoring a backup, moving `state_path`, or
losing a volume takes both or neither.

## The mesh is the wrong substrate, and it says so

The obvious move is to put those two points on the cluster's replicated state
substrate. It is already there, it is already durable, and it already has
quorum-checked writes with a deterministic conflict-resolution protocol. It is
the wrong answer, and the mesh documentation reaches the same conclusion
independently: `mesh-replication.md` describes what it provides as
"quorum-checked eventual consistency," adds that "it is not a consensus system,
it does not serialize concurrent writers (the deterministic merge picks one),"
and says that "strict atomic semantics (reservations, compare-and-swap
budgets) remain the job of a shared backend."

That is exactly the shape of what settlement needs, and the reasons are worth
stating precisely rather than by reference.

**Conflict resolution discards a write.** Records are last-writer-wins
registers ordered by logical version, then timestamp, then node id. Two
coordinators that write the same key at the same logical version converge on
one winner and the other value is gone. The surviving record carries a
`conflict_detected` flag, which tells you afterward that something was lost
without telling you what. For a session store that is fine. For a nonce burn,
the loser has already served a response.

**There is no atomic compare-and-set.** The substrate's own documentation for
`put_versioned` says the fan-out "acknowledges applies, not victories, so
callers verify the winner with a follow-up `get_versioned`." The mesh keystore
builds a CAS on top of that by writing and then reading back, and claims a
false `Applied` is impossible. That claim holds while the membership view is
stable. It stops holding at exactly the moment a payment system cares about.

**Membership is gossip, and the ring shrinks under partition.** A key's
replica set is the first `replication_factor` distinct nodes on the consistent
hash ring, and the ring is maintained by the failure detector. After three
consecutive probe failures a peer is evicted from the ring outright. During a
partition, each side evicts the other, each side's ring contains only its own
members, and a quorum computed over that shrunken replica set succeeds on both
sides. Both sides then read back and both see themselves as the winner. There
is no epoch, no fencing token, and no requirement that a write reach a
majority of the *configured* cluster rather than a majority of whatever the
local view currently contains.

**Nothing above it is a consensus primitive either.** The leader election is
the lexicographically smallest live node id, and the code says so: it "is NOT
a strong consensus primitive." Under a partition it elects one leader per side.
The split-brain detector fires when `alive < expected_min_nodes / 2`, which is
less than half rather than less than a majority, so a five node cluster split
three and two leaves both sides believing they are healthy. The isolation
observer that state operations actually consult is a static `min_peers`
threshold that knows nothing about the true cluster size.

The mesh is a well-built AP system. Every one of these choices is defensible
for what it was built for, which is cache state, session state, and key
records where a revocation fence makes the one dangerous transition absorbing.
A nonce burn is not a monotone lattice problem. Convergence on "this nonce was
burned" is not the guarantee anyone needs, because both nodes have already
served by the time the merge runs. What is needed is mutual exclusion, and
this substrate does not provide it.

Building consensus into the mesh to get there is real work, it is the kind of
work that is wrong in ways nobody notices for months, and the industry it
would be reinventing settled on a different answer decades ago.

## The partition posture is refuse, which means CP

Under partition, a payments node either refuses to settle or settles and
reconciles afterward. Reconciling afterward means a window in which the same
payment can serve twice, and no amount of later repair unserves a response.
The answer is refuse.

That makes distributed settlement a CP subsystem inside a proxy whose other
clustered features are AP, and operators should hear it in those terms:

- A node that cannot reach the shared store returns `503` with a `Retry-After`
  on paid routes. It does not fall back to a local ledger, because a local
  ledger is the double-serve bug with extra steps.
- The shared store becomes a hard dependency for paid traffic on every node
  that serves it. Its availability is the ceiling on paid-route availability.
  Unpaid routes are unaffected.
- Adding nodes buys throughput and rolling restarts. It does not buy
  independence from the store, and it should not be sold as buying more
  nines on the paid path than the store itself has.
- The failure mode is visible and boring: paid requests fail with a retryable
  status while the store is unreachable, then resume. That is the trade being
  bought, and it is the right one.

## The store

Four options, judged on whether they can hold the two serialization points.

**Keep SQLite, share the file.** A network filesystem under a SQLite database
with WAL is a well-documented way to corrupt it. Not viable.

**Front SQLite with a coordinator node.** One node owns the file and the
others proxy settlement calls to it. This preserves every invariant exactly,
because the same code runs against the same file. It also reinvents leader
election, failover, and fencing, and gets the availability story of a single
node plus a new hop. It is worse than the status quo in the way that matters:
the failure mode is now a distributed one, and the thing it protects is
unchanged.

**Redis.** Already a workspace dependency, already used by the cache, the
mesh, and the keystore. `SET NX` and `SADD` are genuine atomic
conditional-inserts, so both serialization points can be expressed. The
problem is everything around them. The settlement store is a relational
contract with foreign keys, partial unique indexes, multi-row transactions,
and compare-and-set transitions on leased rows. Rebuilding that on Redis means
Lua scripts standing in for transactions, and it means accepting that
Redis-with-replication can lose an acknowledged write on failover unless you
run it in a mode most deployments do not. A payment ledger is the wrong first
customer for that.

**Postgres.** Every guarantee the SQLite implementation leans on has a direct
equivalent: `BEGIN` at the isolation level of your choice, `INSERT ... ON
CONFLICT DO NOTHING` with the same affected-row semantics, partial unique
indexes, foreign keys, and synchronous commit. The schema ports nearly
unchanged. Serialization stays inside the database, which is where payment
systems have kept it for as long as there have been payment systems. It is
also the only option under which the nonce burn and the settlement it
authorizes stay in one transaction against one system, which is the property
this design is trying not to lose.

It is also the direction the code already assumed. The nonce ledger trait's
own documentation explains its `Unknown` result by describing what happens
"in Postgres-backed deployments," and its pre-registration hook exists so that
"persistence backends can stamp the route, rail, and currency dimensions on
the audit row." No such backend was ever written, but the seam was shaped for
one.

**The recommendation is Postgres**, and the argument for it is mostly an
argument against novelty. Nothing about charging for a request is a research
problem. The interesting parts of settlement are already written and already
proven, and they are the parts that hold whatever store sits underneath. The
remaining work is porting a schema and a set of transactions onto a database
that does transactions. Bespoke consensus in the mesh would be more
impressive, take an order of magnitude longer, and be harder to convince
anyone of, including ourselves.

The cost is honest and worth stating: `tokio-postgres` or `sqlx` is a new
direct dependency in a workspace that currently has none, with its own
attribution and supply-chain review, and a Postgres instance becomes a
deployment prerequisite for clustered payments. Single-node payments keep
SQLite and gain nothing and lose nothing.

## Two things block a pluggable store today

The seam looks closer than it is.

`SettlementStore` is already a trait and the service already holds
`Arc<dyn SettlementStore>`, so a second implementation appears to be a matter
of writing one. It is not, because the trait is not the whole durable
contract. The nonce burn is an inherent method on the concrete SQLite type,
and the request path's nonce ledger holds that concrete type rather than the
trait object. A configuration that selected a non-SQLite backend today would
produce a settlement store with no way to build a nonce ledger at all, and the
two available workarounds are to drop single serve or to substitute an
in-memory set. The second one is the exact defect the durable ledger was
introduced to fix, reintroduced structurally instead of accidentally.

So the first change is not a config field. It is moving the nonce burn onto
`SettlementStore`, so that the trait is the complete durable contract and no
backend can exist that has settlement without single serve. There are two
implementors today, one of them a test double, so the change is small. It
changes no behavior and lifts nothing.

The second blocker is that the nonce ledger trait is synchronous, by design,
because the crawl-pricing path that defined it runs on the proxy's sync hot
path. The burn takes the SQLite connection directly and never awaits while
holding it. One indexed insert on an open WAL connection is a reasonable thing
to do synchronously. A network round trip to Postgres is not, and doing it on
a Pingora worker thread would stall that worker for every settled redemption.
Making that trait async reaches into the module registry and the policy
enforcement path, which is its own piece of work and should not be smuggled in
under a store change.

Neither blocker is hard. Both are invisible from the outside, and both have to
land before a backend selector is anything other than a way to configure a
regression.

## The config surface, when it arrives

One selector on the payments block, as an enum tagged on `backend` so each
variant carries only the fields it uses. `proxy.olp.revocation_store` already
has exactly this shape, and it is the closest existing model:

```yaml
proxy:
  payments:
    store:
      backend: postgres        # sqlite (default) | postgres
      dsn: "secret://primary/payments-postgres"
```

`state_path` becomes the `sqlite` variant's field and keeps its meaning, so a
document that sets `proxy.payments.state_path` today has to move one line.
That is a schema break on a stable field, which argues for keeping
`state_path` where it is and letting the `sqlite` variant carry no fields at
all. Decide it when the code lands; the shape of the argument does not change
either way.

Three rules the surface should hold, each matching something the configuration
already does elsewhere:

- Consistency levels are not operator-configurable. There is one correct
  setting for a payment ledger, and a knob there is a way to configure a
  double charge. The mesh keystore made this call already and pinned quorum
  rather than inheriting the operator's choice.
- The cluster refusal is relaxed by backend, not removed. `proxy.cluster` plus
  `backend: sqlite` keeps refusing with the same message. The check belongs in
  the config compiler as well as at runtime, so `sbproxy validate` rejects the
  combination without booting anything. That is how the mesh keystore backend
  validates its own dependency on `proxy.cluster.replication`.
- A backend that is configured but not compiled fails at startup and names the
  cargo feature, exactly as a configured rail with no registered adapter does.

Two gates fire on any new field here. The committed JSON schema at
`schemas/sb-config.schema.json` is regenerated and diffed byte for byte, and
the config-reader scan requires every schema key to have a non-test reader or
a reviewed override.

## Staged plan

Each stage is independently mergeable and independently useless to attack,
because the refusal stays until the last one.

1. **Complete the trait.** Move the nonce burn onto `SettlementStore` and make
   the request-path ledger hold the trait object. No config change, no
   behavior change. Test: a store handed over as a trait object still refuses
   a second burn of the same nonce across a reopen.
2. **Make the ledger async.** Convert the nonce store trait and its callers,
   including the crawl-pricing path. This is the riskiest stage and the one
   least related to payments, which is why it is on its own.
3. **Port the schema.** A Postgres implementation of `SettlementStore` behind
   its own cargo feature, with the existing store contract tests run against
   both backends from one suite. Not selectable from configuration yet.
4. **Prove exactly once under concurrency.** Two processes against one
   Postgres, racing the same proof digest and the same quote nonce, asserting
   one settle and one refusal for each. This is the stage that earns the
   right to the next one.
5. **Add the selector.** Configuration can choose the backend. The cluster
   refusal still fires for every backend.
6. **Relax the refusal, for shared backends only.** Plus the operator surface
   a shared ledger requires: a health probe on the store, a metric for
   refused-because-unreachable, and a way to list intents sitting in
   `NeedsReconciliation`. That last one is not optional once there is more
   than one node. Today an operator investigating a stuck payment knows which
   machine to look at. On a cluster, the intent belongs to the store and the
   node that dispatched it may be gone.

Stages one and two are worth doing whether or not the rest happens. They
remove a trap that is currently one plausible refactor away from
reintroducing a paid-response leak.

## When to revisit the mesh answer

Two things would change it.

**The mesh grows a real consensus log.** Not a merge fence, not a
write-then-verify CAS, and not a better failure detector. A replicated log
with terms, an elected leader that can be fenced, and a majority requirement
computed against configured membership rather than the current gossip view.
At that point the mesh could hold the two serialization points and the
external dependency goes away. Nothing about the current substrate is on that
path, and there is no reason to put it there for this feature alone.

**A payment rail arrives that does not need a local uniqueness point.** The
serialization points exist because the proxy has to decide, locally and
immediately, whether a credential has already been spent. A rail whose
provider answers that question authoritatively and idempotently on every call,
cheaply enough to sit in the request path, would move the decision off our
store. That is worth watching for and worth designing to when it shows up,
because a rail that owns its own uniqueness makes clustering nearly free.

Until one of those, distributed settlement is a shared transactional database
holding two unique indexes, and the honest version of this feature says so.

## Related

- [payment-settlement.md](payment-settlement.md) covers the settlement path
  that ships today, including the boundaries this page proposes to move.
- [402-challenge.md](402-challenge.md) has the exact bytes of every challenge,
  credential, and receipt.
- [mesh-replication.md](mesh-replication.md) documents the replicated cluster
  substrate and its own account of what it does not do.
- [key-management.md](key-management.md) shows the mesh backend for a
  different kind of sensitive record, and why revocation needed a merge fence
  to be safe there.
