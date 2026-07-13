# Split-role managed-model cluster

This local topology separates one authority, one gateway, and two workers. It
uses encrypted gossip and mTLS typed-state transport. The gateway and authority
participate in placement without creating model engines; the two workers own
the replica assignments.

Create the authority identity once. The local admin certificate below is signed
by the cluster CA only to make the enrollment HTTPS endpoint convenient on
`localhost`; it is separate from the authority's enrolled mesh certificate.

```bash
mkdir -p state
sbproxy cluster init \
  --dir state/authority \
  --cluster-id model-cluster-split \
  --node-id authority-a \
  --role authority \
  --label zone=control

openssl req -newkey rsa:2048 -nodes \
  -keyout state/authority/admin-key.pem \
  -out state/authority/admin.csr \
  -subj '/CN=localhost'
printf '%s\n' \
  'subjectAltName=DNS:localhost,IP:127.0.0.1' \
  'extendedKeyUsage=serverAuth' > state/authority/admin.ext
openssl x509 -req -days 1 \
  -in state/authority/admin.csr \
  -CA state/authority/ca.pem \
  -CAkey state/authority/ca-key.pem \
  -CAcreateserial \
  -extfile state/authority/admin.ext \
  -out state/authority/admin.pem
```

Start the authority first:

```bash
export SB_ADMIN_PASSWORD=local-admin
sbproxy -f examples/model-cluster-split/sb.yml
```

In another shell, enroll each remaining identity. Every token grants exactly
the role and labels installed into the signed identity, and every node keeps a
unique private key.

```bash
export SBPROXY_CLUSTER_TOKEN="$(sbproxy cluster token create \
  --dir state/authority --role gateway --label zone=edge)"
sbproxy cluster enroll \
  --url https://localhost:19090 \
  --ca-cert state/authority/ca.pem \
  --node-id gateway-a --role gateway --label zone=edge \
  --out state/gateway

export SBPROXY_CLUSTER_TOKEN="$(sbproxy cluster token create \
  --dir state/authority --role worker --label zone=local-a)"
sbproxy cluster enroll \
  --url https://localhost:19090 \
  --ca-cert state/authority/ca.pem \
  --node-id worker-a --role worker --label zone=local-a \
  --out state/worker-a

export SBPROXY_CLUSTER_TOKEN="$(sbproxy cluster token create \
  --dir state/authority --role worker --label zone=local-b)"
sbproxy cluster enroll \
  --url https://localhost:19090 \
  --ca-cert state/authority/ca.pem \
  --node-id worker-b --role worker --label zone=local-b \
  --out state/worker-b
unset SBPROXY_CLUSTER_TOKEN
```

Start the gateway and workers in three more shells:

```bash
export SB_ADMIN_PASSWORD=local-admin
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
its stable reasons even after routing membership GC, and placement moves only
the affected assignment. Restart the worker with the same enrolled state
directory to observe signed rejoin and recovery.

This PR does not dispatch inference from the gateway to a remote worker. The
split topology demonstrates identity, membership, snapshot, directory,
placement, rollout, and admin state only. The distributed data-plane PR owns
authenticated request envelopes and remote streaming.
