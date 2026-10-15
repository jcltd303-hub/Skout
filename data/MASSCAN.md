# Masscan exclusions

`masscan-exclude.conf` preserves all 332 active IPv4 exclusion entries from
[`robertdavidgraham/masscan` at commit `8e6b3b0c07a81e8ea61d557c06134a21a6881614`](https://github.com/robertdavidgraham/masscan/blob/8e6b3b0c07a81e8ea61d557c06134a21a6881614/data/exclude.conf).
The upstream Git blob is `480eeb21a371a55ed94d5d5725c7a8755f4771a6`.
The newline-terminated active entries have SHA-256
`17b9d7e2ad8bf25cd6ed35d77e6ad2313e923b54b3fda529ca3c797b00ccfcd0`.
The entries comprise 321 CIDRs, eight inclusive ranges, and three individual IPs.
Upstream comments, including personal correspondence, are omitted. The upstream
GNU Affero General Public License v3 text is retained in `MASSCAN-LICENSE`.

Both Skout random target generators load this snapshot by default and add their
mandatory private, loopback, multicast, and reserved exclusions. The native
scanner embeds it at build time; the Termux Python generator reads the same
file relative to its own location. Neither fetches exclusions during a scan.
The collector does not apply this policy to explicit endpoint input, so local
inventory and loopback fixtures continue to work.

Additional exclusion files accept one IPv4 address, CIDR, or inclusive
`first-last` range per line. Blank lines and `#` comments are accepted. Custom
files add to the defaults. Invalid or unreadable files and exclusion sets that
cover all IPv4 addresses stop generation before network setup or endpoint
output. Overlapping/adjacent ranges are merged, and sampling selects directly
from the remaining address space.

To update the snapshot, fetch the upstream file at a reviewed commit, preserve
every nonempty address entry after stripping `#` comments, and update this
provenance record and the header. Run both language suites and verify their
merged exclusion sets agree before publishing.
