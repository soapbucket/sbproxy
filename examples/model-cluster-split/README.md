# Split-role managed-model cluster

This local topology separates one authority, one gateway, and two workers. It
uses encrypted gossip and mTLS typed-state transport. The gateway and authority
participate in placement without creating model engines; the two workers own
the replica assignments.

For a quick local fixture, create one CA-signed peer certificate with both
client and server usage, then copy it into each identity directory. Production
deployments should use `sbproxy cluster init`, one-time enrollment tokens, and a
unique node key per identity.

```bash
mkdir -p state/{authority,gateway,worker-a,worker-b}
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -keyout state/ca-key.pem -out state/ca.pem -subj '/CN=local-cluster-ca'
openssl req -newkey rsa:2048 -nodes \
  -keyout state/node-key.pem -out state/node.csr -subj '/CN=sbproxy-mesh'
printf '%s\n' \
  'subjectAltName=DNS:sbproxy-mesh' \
  'extendedKeyUsage=serverAuth,clientAuth' > state/node.ext
openssl x509 -req -days 1 -in state/node.csr \
  -CA state/ca.pem -CAkey state/ca-key.pem -CAcreateserial \
  -extfile state/node.ext -out state/node.pem
openssl rand -hex 32 > state/gossip.key
for node in authority gateway worker-a worker-b; do
  cp state/ca.pem state/node.pem state/node-key.pem state/gossip.key "state/${node}/"
done
```

Start the four configs in separate shells:

```bash
export SB_ADMIN_PASSWORD=local-admin
sbproxy -f examples/model-cluster-split/sb.yml
sbproxy -f examples/model-cluster-split/gateway.yml
sbproxy -f examples/model-cluster-split/worker-a.yml
sbproxy -f examples/model-cluster-split/worker-b.yml
```

Then inspect the gateway view:

```bash
export SB_ADMIN_URL=http://127.0.0.1:19091
export SB_ADMIN_USERNAME=admin SB_ADMIN_PASSWORD=local-admin
sbproxy cluster status --format json \
  | jq '{summary,nodes,unhealthy_nodes,deployments}'
```

Stop either worker. The roster keeps that identity, the unhealthy alert names
its stable reasons, and placement moves only the affected assignment. Restart
the worker to observe recovery.

This PR does not dispatch inference from the gateway to a remote worker. The
split topology demonstrates identity, membership, snapshot, directory,
placement, rollout, and admin state only. The distributed data-plane PR owns
authenticated request envelopes and remote streaming.
