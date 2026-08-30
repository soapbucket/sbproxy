# Break-glass emergency access

*Last modified: 2026-08-28*

A pre-staged, time-boxed, quorum-approved path into the key and credential
admin API, built to be expensive to use quietly and cheap to review afterwards.

A grant records that a named operator claimed emergency access to a named set
of records, that a quorum of other operators agreed, and that everything done
under it is attributable to one grant id. Self-approval is refused before the
roster is consulted, a TTL above the cap is refused rather than clamped, and an
unscoped request is refused outright. An expired grant does not close: it moves
to a review queue and stays there until a human signs off.

`sb.yml` walks the whole cycle: request, refused self-approval, quorum,
a tagged action, expiry, and the post-access review.

Grants live in process memory. A restart voids every active grant, which fails
safe, and a fleet does not share them. The console flow is deferred to the
admin-console work; the JSON routes are complete on their own.
