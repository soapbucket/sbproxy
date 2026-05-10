# Listing primitive

A minimal example of the repo-native `Listing` primitive (WOR-136).

The directory holds:

- `sb.yml` - the standard proxy config with a single origin.
- `listings/example.yaml` - one Listing manifest that publishes the
  origin as `example-api` and pins it to a short commit SHA.

See `docs/listings.md` in this repo for the full schema reference, the
three pinning modes (`pin`, `track-branch`, `tag`), the loader
behaviour, and the plan-validation rules.

Run:

```bash
make run CONFIG=examples/listing-primitive/sb.yml
```

The Listing is not on the data path in OSS today: it is the
foundation the future hosted-Catalog surface (WOR-135) and the
Listing-scoped agent-skills extension (WOR-196) build on.
