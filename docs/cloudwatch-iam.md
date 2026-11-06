# CloudWatch reader: IAM policy and validation checklist

Status: **implemented and tested only against fakes. It has never been run against real AWS.**
Section 4 is the manual checklist the owner should run against a **non-production** RDS
instance before trusting any alert that depends on it.

## 1. What it does

For a database with a `cloudwatch` block, Lockkeeper calls CloudWatch `GetMetricData` (one query,
one metric) once per minute at most:

| CloudWatch | Value |
|---|---|
| Namespace / metric | `AWS/RDS` / `FreeStorageSpace` (unit: bytes) |
| Dimension | `DBInstanceIdentifier` = `db_instance_id` |
| Statistic / period | `Minimum` / 60 s |
| Window | last 15 minutes, newest datapoint wins |

It emits `rds.free_storage_bytes` and, only when `disk_total_gb` is set (in GiB, as the RDS
console shows), `rds.free_storage_ratio` = free / (`disk_total_gb` x 2^30). From both it derives
`pg.slot.retained_wal_free_ratio` per replication slot (retained WAL / free storage).

If CloudWatch returns nothing, an error, or a newest datapoint older than 10 minutes, **no sample
is emitted** (never 0), the collection is marked incomplete (so a firing alert is not cleared) and
the reason is logged. The derived ratio then does not exist either; the absolute byte thresholds
keep guarding the disk.

```yaml
databases:
  rds-main:
    # ...
    disk_total_gb: 500                      # optional; enables rds.free_storage_ratio
    cloudwatch: { region: eu-west-1, db_instance_id: example-db }
```

Default rules (override under `alerts.rules`): `rds.free_storage_ratio` warning below 20% (5 min),
critical below 10% (2 min); `pg.slot.retained_wal_free_ratio` warning above 25%, critical above 50%.

## 2. Credentials

Lockkeeper takes **no** AWS credential setting and stores none. The AWS SDK for Go v2 default chain
is used: `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` (and `AWS_SESSION_TOKEN`), `AWS_PROFILE` and
the shared `~/.aws/config` / `credentials` files (including SSO), web identity, container
credentials, and the EC2 instance role. Prefer a role (instance profile, or SSO/assume-role) over
long-lived keys. The client is built lazily on first use, so `config validate` and `init` never
touch AWS.

## 3. Minimal IAM policy

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "LockkeeperReadRdsFreeStorage",
      "Effect": "Allow",
      "Action": "cloudwatch:GetMetricData",
      "Resource": "*"
    }
  ]
}
```

That is the only permission the reader needs. It does not need `rds:*`, `ec2:*`, `cloudwatch:ListMetrics`
or `cloudwatch:GetMetricStatistics`.

**Why `Resource: "*"`.** The CloudWatch permissions reference states that for the CloudWatch API
operations it lists, "you specify a wildcard character (\*) as the resource value in the policy's
`Resource` field", and lists `GetMetricData` among them
(<https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/permissions-reference-cw.html>, read
2026-11-06). So the policy cannot be narrowed to one instance by ARN. Consequence: the credential can read
every metric in the account/region. Mitigations: use a dedicated role/user with only this policy, keep
credentials out of the config file, and rotate them.

What I could and could not verify:

- Verified (page above): `GetMetricData` takes `*` as the resource; no resource-level ARN is documented.
  The same page mentions the `cloudwatch:ResourceArn` condition key only for the *ResourceMetricsConfiguration*
  actions, not for `GetMetricData`.
- Verified (RDS metrics reference, <https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/rds-metrics.html>):
  `FreeStorageSpace` is an instance-level `AWS/RDS` metric in bytes.
- Not verified: the Service Authorization Reference page for CloudWatch could not be rendered by my fetch
  tool, so I did not cross-check its "Resource types" column or whether a condition key such as
  `cloudwatch:namespace` can be applied to `GetMetricData`. Do not rely on a condition key without testing it
  (the policy simulator or a real call).
- Not verified: the publication frequency of `FreeStorageSpace` (RDS basic monitoring is commonly described
  as one datapoint per minute; the page I fetched does not state it). The 10-minute staleness limit and the
  once-a-minute fetch cache assume it. Check it in step 4.
- Not verified: pricing. `GetMetricData` is billed per metric requested (see
  <https://aws.amazon.com/cloudwatch/pricing/>); at most one request per minute per database keeps it small
  (about 43,000 metric requests per database per month), but check the current price yourself.

Scope notes: `FreeStorageSpace` describes the data volume. A DB instance with a dedicated log volume
publishes `FreeStorageSpaceLogVolume` separately (not read). Aurora does not use `FreeStorageSpace` the same
way. This reader targets RDS for PostgreSQL/MySQL instances.

## 4. Manual validation checklist (non-production RDS instance only)

Use a throwaway or staging instance; the reader is read-only, but validate where an alert cannot page anyone.
Never put access keys in the Lockkeeper config file.

1. Create a dedicated IAM user or role with only the policy in section 3. Export credentials in your
   shell (or use `AWS_PROFILE`).
2. Add the `cloudwatch` block (and `disk_total_gb` equal to the instance's allocated storage in GiB) to a
   copy of the config pointing at the non-production instance. Run `lockkeeper config validate`: it must pass
   without any AWS call.
3. Run `lockkeeper check --json --samples`. Expect `rds.free_storage_bytes`
   and `rds.free_storage_ratio`. Compare the value with the RDS console "Free storage space" (console units may
   differ from the bytes CloudWatch stores) and with `aws cloudwatch get-metric-data` for the same window.
   The ratio must be free / allocated. If free > `disk_total_gb` Lockkeeper reports an error and withholds the
   ratio (storage autoscaling or a wrong value).
4. Confirm the metric cadence: in the CloudWatch console, check that `FreeStorageSpace` has one datapoint per
   minute for this instance. If it is slower (for example 5 minutes), raise the limits in the code before
   relying on it.
5. Negative tests, each must give a clear error, **no** `rds.*` sample and `complete=false` (no zero):
   - wrong `db_instance_id` (expect "no FreeStorageSpace datapoints ... check db_instance_id and region");
   - wrong `region`;
   - credentials without the policy (expect `AccessDenied`) and no credentials at all (expect a credentials
     error; off EC2 the SDK may try the instance metadata service, which can take a few seconds but is bounded
     by a 10 s call timeout);
   - unset `AWS_PROFILE` pointing at a missing profile.
6. Confirm no secret leaks: run `lockkeeper monitor run` for a few minutes with a canary secret access key and
   `grep` the logs, the process arguments (`ps`) and the SQLite state file for the canary secret and the access
   key id. None may appear. (The automated tests prove this against a loopback fake only.)
7. Force the thresholds: temporarily override `rds.free_storage_ratio` (for example `warning: 0.99`) to see the
   alert fire and resolve through your notification channel. Restore the defaults afterwards.
8. With a Postgres slot present on the instance, confirm `pg.slot.retained_wal_free_ratio{slot=...}` appears and
   equals retained WAL / free storage.
9. Network: if Lockkeeper runs in a private subnet, CloudWatch needs an outbound path (NAT or an interface VPC
   endpoint for `monitoring`). Confirm the call succeeds from the real deployment host.
10. Record what you observed (SDK version `aws-sdk-go-v2/service/cloudwatch v1.75.5`, date, instance class) in
    the project notes before enabling it for production alerts.
