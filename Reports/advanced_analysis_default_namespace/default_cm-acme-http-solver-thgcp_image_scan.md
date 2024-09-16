2024-09-16T12:48:11+02:00	INFO	[db] Need to update DB
2024-09-16T12:48:11+02:00	INFO	[db] Downloading DB...	repository="ghcr.io/aquasecurity/trivy-db:2"
8.16 MiB / 53.25 MiB [---------------------------->_______________________________________________________________________________________________________________________________________________________________] 15.32% ? p/s ?14.06 MiB / 53.25 MiB [------------------------------------------------->_________________________________________________________________________________________________________________________________________] 26.41% ? p/s ?17.67 MiB / 53.25 MiB [-------------------------------------------------------------->____________________________________________________________________________________________________________________________] 33.19% ? p/s ?24.53 MiB / 53.25 MiB [-------------------------------------------------------------------------------->_____________________________________________________________________________________________] 46.07% 27.29 MiB p/s ETA 1s29.03 MiB / 53.25 MiB [---------------------------------------------------------------------------------------------->_______________________________________________________________________________] 54.52% 27.29 MiB p/s ETA 0s35.16 MiB / 53.25 MiB [------------------------------------------------------------------------------------------------------------------>___________________________________________________________] 66.03% 27.29 MiB p/s ETA 0s43.02 MiB / 53.25 MiB [-------------------------------------------------------------------------------------------------------------------------------------------->_________________________________] 80.78% 27.52 MiB p/s ETA 0s45.24 MiB / 53.25 MiB [--------------------------------------------------------------------------------------------------------------------------------------------------->__________________________] 84.95% 27.52 MiB p/s ETA 0s52.81 MiB / 53.25 MiB [---------------------------------------------------------------------------------------------------------------------------------------------------------------------------->_] 99.18% 27.52 MiB p/s ETA 0s53.25 MiB / 53.25 MiB [---------------------------------------------------------------------------------------------------------------------------------------------------------------------------->] 100.00% 26.84 MiB p/s ETA 0s53.25 MiB / 53.25 MiB [---------------------------------------------------------------------------------------------------------------------------------------------------------------------------->] 100.00% 26.84 MiB p/s ETA 0s53.25 MiB / 53.25 MiB [---------------------------------------------------------------------------------------------------------------------------------------------------------------------------->] 100.00% 26.84 MiB p/s ETA 0s53.25 MiB / 53.25 MiB [---------------------------------------------------------------------------------------------------------------------------------------------------------------------------->] 100.00% 25.11 MiB p/s ETA 0s53.25 MiB / 53.25 MiB [-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------] 100.00% 21.15 MiB p/s 2.7s2024-09-16T12:48:14+02:00	INFO	[vuln] Vulnerability scanning is enabled
2024-09-16T12:48:14+02:00	INFO	[secret] Secret scanning is enabled
2024-09-16T12:48:14+02:00	INFO	[secret] If your scanning is slow, please try '--scanners vuln' to disable secret scanning
2024-09-16T12:48:14+02:00	INFO	[secret] Please see also https://aquasecurity.github.io/trivy/v0.55/docs/scanner/secret#recommendation for faster secret detection
2024-09-16T12:48:16+02:00	INFO	Detected OS	family="debian" version="11.7"
2024-09-16T12:48:16+02:00	INFO	[debian] Detecting vulnerabilities...	os_version="11" pkg_num=3
2024-09-16T12:48:16+02:00	INFO	Number of language-specific files	num=1
2024-09-16T12:48:16+02:00	INFO	[gobinary] Detecting vulnerabilities...
2024-09-16T12:48:16+02:00	WARN	Using severities from other vendors for some vulnerabilities. Read https://aquasecurity.github.io/trivy/v0.55/docs/scanner/vulnerability#severity-selection for details.
{
  "SchemaVersion": 2,
  "CreatedAt": "2024-09-16T12:48:16.72909+02:00",
  "ArtifactName": "quay.io/jetstack/cert-manager-acmesolver:v1.12.3",
  "ArtifactType": "container_image",
  "Metadata": {
    "OS": {
      "Family": "debian",
      "Name": "11.7"
    },
    "ImageID": "sha256:f73c4f162bc2650f027fd9392ed378d4015301dd14764961bea495c96ded9949",
    "DiffIDs": [
      "sha256:e023e0e48e6e29e90e519f4dd356d058ff2bffbd16e28b802f3b8f93aa4ccb17",
      "sha256:6fbdf253bbc2490dcfede5bdb58ca0db63ee8aff565f6ea9f918f3bce9e2d5aa",
      "sha256:7bea6b893187b14fc0a759fe5f8972d1292a9c0554c87cbf485f0947c26b8a05",
      "sha256:ff5700ec54186528cbae40f54c24b1a34fb7c01527beaa1232868c16e2353f52",
      "sha256:d52f02c6501c9c4410568f0bf6ff30d30d8290f57794c308fe36ea78393afac2",
      "sha256:e624a5370eca2b8266e74d179326e2a8767d361db14d13edd9fb57e408731784",
      "sha256:1a73b54f556b477f0a8b939d13c504a3b4f4db71f7a09c63afbc10acb3de5849",
      "sha256:d2d7ec0f6756eb51cf1602c6f8ac4dd811d3d052661142e0110357bf0b581457",
      "sha256:4cb10dd2545bd173858450b80853b850e49608260f1a0789e0d0b39edf12f500",
      "sha256:b628230c51c7f48ef1625319af5a4dc0997450591fe9fb45b0fd7c9e743a69e5",
      "sha256:56434b4dcc4ec012fbc5e5e333110536182ad1e529dd0e810f2959cd57732005",
      "sha256:42fb792763b15e0b8c965672825f948236093e4d2331c95477dadf5868d766f7"
    ],
    "RepoTags": [
      "quay.io/jetstack/cert-manager-acmesolver:v1.12.3"
    ],
    "RepoDigests": [
      "quay.io/jetstack/cert-manager-acmesolver@sha256:1525a14642a0b891e38d33157253b04ad9efaac628d53ced4f3ff1dab8f5de49"
    ],
    "ImageConfig": {
      "architecture": "amd64",
      "created": "2023-07-26T12:06:40.320403297Z",
      "history": [
        {
          "created": "0001-01-01T00:00:00Z"
        },
        {
          "created": "0001-01-01T00:00:00Z"
        },
        {
          "created": "0001-01-01T00:00:00Z"
        },
        {
          "created": "0001-01-01T00:00:00Z"
        },
        {
          "created": "0001-01-01T00:00:00Z"
        },
        {
          "created": "0001-01-01T00:00:00Z"
        },
        {
          "created": "0001-01-01T00:00:00Z"
        },
        {
          "created": "0001-01-01T00:00:00Z"
        },
        {
          "created": "0001-01-01T00:00:00Z"
        },
        {
          "created": "2023-07-26T12:06:29.319369402Z",
          "created_by": "LABEL org.opencontainers.image.source=https://github.com/cert-manager/cert-manager",
          "comment": "buildkit.dockerfile.v0",
          "empty_layer": true
        },
        {
          "created": "2023-07-26T12:06:29.319369402Z",
          "created_by": "USER 1000",
          "comment": "buildkit.dockerfile.v0",
          "empty_layer": true
        },
        {
          "created": "2023-07-26T12:06:29.319369402Z",
          "created_by": "COPY acmesolver /app/cmd/acmesolver/acmesolver # buildkit",
          "comment": "buildkit.dockerfile.v0"
        },
        {
          "created": "2023-07-26T12:06:40.0540532Z",
          "created_by": "COPY cert-manager.license /licenses/LICENSE # buildkit",
          "comment": "buildkit.dockerfile.v0"
        },
        {
          "created": "2023-07-26T12:06:40.320403297Z",
          "created_by": "COPY cert-manager.licenses_notice /licenses/LICENSES # buildkit",
          "comment": "buildkit.dockerfile.v0"
        },
        {
          "created": "2023-07-26T12:06:40.320403297Z",
          "created_by": "ENTRYPOINT [\"/app/cmd/acmesolver/acmesolver\"]",
          "comment": "buildkit.dockerfile.v0",
          "empty_layer": true
        }
      ],
      "os": "linux",
      "rootfs": {
        "type": "layers",
        "diff_ids": [
          "sha256:e023e0e48e6e29e90e519f4dd356d058ff2bffbd16e28b802f3b8f93aa4ccb17",
          "sha256:6fbdf253bbc2490dcfede5bdb58ca0db63ee8aff565f6ea9f918f3bce9e2d5aa",
          "sha256:7bea6b893187b14fc0a759fe5f8972d1292a9c0554c87cbf485f0947c26b8a05",
          "sha256:ff5700ec54186528cbae40f54c24b1a34fb7c01527beaa1232868c16e2353f52",
          "sha256:d52f02c6501c9c4410568f0bf6ff30d30d8290f57794c308fe36ea78393afac2",
          "sha256:e624a5370eca2b8266e74d179326e2a8767d361db14d13edd9fb57e408731784",
          "sha256:1a73b54f556b477f0a8b939d13c504a3b4f4db71f7a09c63afbc10acb3de5849",
          "sha256:d2d7ec0f6756eb51cf1602c6f8ac4dd811d3d052661142e0110357bf0b581457",
          "sha256:4cb10dd2545bd173858450b80853b850e49608260f1a0789e0d0b39edf12f500",
          "sha256:b628230c51c7f48ef1625319af5a4dc0997450591fe9fb45b0fd7c9e743a69e5",
          "sha256:56434b4dcc4ec012fbc5e5e333110536182ad1e529dd0e810f2959cd57732005",
          "sha256:42fb792763b15e0b8c965672825f948236093e4d2331c95477dadf5868d766f7"
        ]
      },
      "config": {
        "Entrypoint": [
          "/app/cmd/acmesolver/acmesolver"
        ],
        "Env": [
          "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
          "SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt"
        ],
        "Labels": {
          "org.opencontainers.image.source": "https://github.com/cert-manager/cert-manager"
        },
        "User": "1000",
        "WorkingDir": "/"
      }
    }
  },
  "Results": [
    {
      "Target": "quay.io/jetstack/cert-manager-acmesolver:v1.12.3 (debian 11.7)",
      "Class": "os-pkgs",
      "Type": "debian"
    },
    {
      "Target": "app/cmd/acmesolver/acmesolver",
      "Class": "lang-pkgs",
      "Type": "gobinary",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2023-39325",
          "PkgName": "golang.org/x/net",
          "PkgIdentifier": {
            "PURL": "pkg:golang/golang.org/x/net@v0.10.0",
            "UID": "a0ebc39340d6f291"
          },
          "InstalledVersion": "v0.10.0",
          "FixedVersion": "0.17.0",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:1af0b9fc7854ee24c9d2c6a0bf240f0eda36f6d6745ceabead57db9d46154146",
            "DiffID": "sha256:b628230c51c7f48ef1625319af5a4dc0997450591fe9fb45b0fd7c9e743a69e5"
          },
          "SeveritySource": "ghsa",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-39325",
          "DataSource": {
            "ID": "ghsa",
            "Name": "GitHub Security Advisory Go",
            "URL": "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Ago"
          },
          "Title": "golang: net/http, x/net/http2: rapid stream resets can cause excessive work (CVE-2023-44487)",
          "Description": "A malicious HTTP/2 client which rapidly creates requests and immediately resets them can cause excessive server resource consumption. While the total number of requests is bounded by the http2.Server.MaxConcurrentStreams setting, resetting an in-progress request allows the attacker to create a new request while the existing one is still executing. With the fix applied, HTTP/2 servers now bound the number of simultaneously executing handler goroutines to the stream concurrency limit (MaxConcurrentStreams). New requests arriving when at the limit (which can only happen after the client has reset an existing, in-flight request) will be queued until a handler exits. If the request queue grows too large, the server will terminate the connection. This issue is also fixed in golang.org/x/net/http2 for users manually configuring HTTP/2. The default stream concurrency limit is 250 streams (requests) per HTTP/2 connection. This value may be adjusted using the golang.org/x/net/http2 package; see the Server.MaxConcurrentStreams setting and the ConfigureServer function.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-770"
          ],
          "VendorSeverity": {
            "alma": 2,
            "amazon": 3,
            "azure": 3,
            "bitnami": 3,
            "cbl-mariner": 3,
            "ghsa": 3,
            "nvd": 3,
            "oracle-oval": 2,
            "redhat": 3,
            "rocky": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "bitnami": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 7.5
            },
            "ghsa": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 7.5
            },
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 7.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 7.5
            }
          },
          "References": [
            "golang.org/x/net",
            "https://access.redhat.com/errata/RHSA-2023:6077",
            "https://access.redhat.com/security/cve/CVE-2023-39325",
            "https://access.redhat.com/security/cve/CVE-2023-44487",
            "https://access.redhat.com/security/vulnerabilities/RHSB-2023-003",
            "https://bugzilla.redhat.com/2242803",
            "https://bugzilla.redhat.com/2243296",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2242803",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2243296",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-39325",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-44487",
            "https://errata.almalinux.org/9/ALSA-2023-6077.html",
            "https://errata.rockylinux.org/RLSA-2023:6077",
            "https://github.com/golang/go/commit/24ae2d927285c697440fdde3ad7f26028354bcf3 [golang- 1.21]",
            "https://github.com/golang/go/commit/e175f27f58aa7b9cd4d79607ae65d2cd5baaee68 [golang-1.20]",
            "https://github.com/golang/go/issues/63417",
            "https://go.dev/cl/534215",
            "https://go.dev/cl/534235",
            "https://go.dev/issue/63417",
            "https://groups.google.com/g/golang-announce/c/iNNxDTCjZvo/m/UDd7VKQuAAAJ",
            "https://linux.oracle.com/cve/CVE-2023-39325.html",
            "https://linux.oracle.com/errata/ELSA-2023-5867.html",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/3OVW5V2DM5K5IC3H7O42YDUGNJ74J35O",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/3OVW5V2DM5K5IC3H7O42YDUGNJ74J35O/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/3SZN67IL7HMGMNAVLOTIXLIHUDXZK4LH",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/3SZN67IL7HMGMNAVLOTIXLIHUDXZK4LH/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/3WJ4QVX2AMUJ2F2S27POOAHRC4K3CHU4",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/3WJ4QVX2AMUJ2F2S27POOAHRC4K3CHU4/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/4BUK2ZIAGCULOOYDNH25JPU6JBES5NF2",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/4BUK2ZIAGCULOOYDNH25JPU6JBES5NF2/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/5RSKA2II6QTD4YUKUNDVJQSRYSFC4VFR",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/5RSKA2II6QTD4YUKUNDVJQSRYSFC4VFR/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/AVZDNSMVDAQJ64LJC5I5U5LDM5753647",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/AVZDNSMVDAQJ64LJC5I5U5LDM5753647/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/CHHITS4PUOZAKFIUBQAQZC7JWXMOYE4B",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/CHHITS4PUOZAKFIUBQAQZC7JWXMOYE4B/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/CLB4TW7KALB3EEQWNWCN7OUIWWVWWCG2",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/CLB4TW7KALB3EEQWNWCN7OUIWWVWWCG2/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/D2BBIDR2ZMB3X5BC7SR4SLQMHRMVPY6L",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/D2BBIDR2ZMB3X5BC7SR4SLQMHRMVPY6L/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ECRC75BQJP6FJN2L7KCKYZW4DSBD7QSD",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ECRC75BQJP6FJN2L7KCKYZW4DSBD7QSD/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FTMJ3NJIDAZFWJQQSP3L22MUFJ3UP2PT",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FTMJ3NJIDAZFWJQQSP3L22MUFJ3UP2PT/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/GSY7SXFFTPZFWDM6XELSDSHZLVW3AHK7",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/GSY7SXFFTPZFWDM6XELSDSHZLVW3AHK7/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/HZQIELEIRSZUYTFFH5KTH2YJ4IIQG2KE",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/HZQIELEIRSZUYTFFH5KTH2YJ4IIQG2KE/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/IPWCNYB5PQ5PCVZ4NJT6G56ZYFZ5QBU6",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/IPWCNYB5PQ5PCVZ4NJT6G56ZYFZ5QBU6/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/KEOTKBUPZXHE3F352JBYNTSNRXYLWD6P",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/KEOTKBUPZXHE3F352JBYNTSNRXYLWD6P/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/KSEGD2IWKNUO3DWY4KQGUQM5BISRWHQE",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/KSEGD2IWKNUO3DWY4KQGUQM5BISRWHQE/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/L5E5JSJBZLYXOTZWXHJKRVCIXIHVWKJ6",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/L5E5JSJBZLYXOTZWXHJKRVCIXIHVWKJ6/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/MZQYOOKHQDQ57LV2IAG6NRFOVXKHJJ3Z",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/MZQYOOKHQDQ57LV2IAG6NRFOVXKHJJ3Z/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/NG7IMPL55MVWU3LCI4JQJT3K2U5CHDV7",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/NG7IMPL55MVWU3LCI4JQJT3K2U5CHDV7/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ODBY7RVMGZCBSTWF2OZGIZS57FNFUL67",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ODBY7RVMGZCBSTWF2OZGIZS57FNFUL67/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/OXGWPQOJ3JNDW2XIYKIVJ7N7QUIFNM2Q",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/OXGWPQOJ3JNDW2XIYKIVJ7N7QUIFNM2Q/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/PJCUNGIQDUMZ4Z6HWVYIMR66A35F5S74",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/PJCUNGIQDUMZ4Z6HWVYIMR66A35F5S74/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/QF5QSYAOPDOWLY6DUHID56Q4HQFYB45I",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/QF5QSYAOPDOWLY6DUHID56Q4HQFYB45I/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/QXOU2JZUBEBP7GBKAYIJRPRBZSJCD7ST",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/QXOU2JZUBEBP7GBKAYIJRPRBZSJCD7ST/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/R3UETKPUB3V5JS5TLZOF3SMTGT5K5APS",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/R3UETKPUB3V5JS5TLZOF3SMTGT5K5APS/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/REMHVVIBDNKSRKNOTV7EQSB7CYQWOUOU",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/REMHVVIBDNKSRKNOTV7EQSB7CYQWOUOU/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/T7N5GV4CHH6WAGX3GFMDD3COEOVCZ4RI",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/T7N5GV4CHH6WAGX3GFMDD3COEOVCZ4RI/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ULQQONMSCQSH5Z5OWFFQHCGEZ3NL4DRJ",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ULQQONMSCQSH5Z5OWFFQHCGEZ3NL4DRJ/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/UTT7DG3QOF5ZNJLUGHDNLRUIN6OWZARP",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/UTT7DG3QOF5ZNJLUGHDNLRUIN6OWZARP/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/W2LZSWTV4NV4SNQARNXG5T6LRHP26EW2",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/W2LZSWTV4NV4SNQARNXG5T6LRHP26EW2/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/WCNCBYKZXLDFGAJUB7ZP5VLC3YTHJNVH",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/WCNCBYKZXLDFGAJUB7ZP5VLC3YTHJNVH/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/XFOIBB4YFICHDM7IBOP7PWXW3FX4HLL2",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/XFOIBB4YFICHDM7IBOP7PWXW3FX4HLL2/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/XTNLSL44Y5FB6JWADSZH6DCV4JJAAEQY",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/XTNLSL44Y5FB6JWADSZH6DCV4JJAAEQY/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/YJWHBLVZDM5KQSDFRBFRKU5KSSOLIRQ4",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/YJWHBLVZDM5KQSDFRBFRKU5KSSOLIRQ4/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/YRKEXKANQ7BKJW2YTAMP625LJUJZLJ4P",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/YRKEXKANQ7BKJW2YTAMP625LJUJZLJ4P/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ZSVEMQV5ROY5YW5QE3I57HT3ITWG5GCV",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ZSVEMQV5ROY5YW5QE3I57HT3ITWG5GCV/",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-39325",
            "https://pkg.go.dev/vuln/GO-2023-2102",
            "https://security.gentoo.org/glsa/202311-09",
            "https://security.netapp.com/advisory/ntap-20231110-0008",
            "https://security.netapp.com/advisory/ntap-20231110-0008/",
            "https://ubuntu.com/security/notices/USN-6574-1",
            "https://www.cisa.gov/news-events/alerts/2023/10/10/http2-rapid-reset-vulnerability-cve-2023-44487",
            "https://www.cve.org/CVERecord?id=CVE-2023-39325"
          ],
          "PublishedDate": "2023-10-11T22:15:09.88Z",
          "LastModifiedDate": "2024-04-28T04:15:09.877Z"
        },
        {
          "VulnerabilityID": "CVE-2023-3978",
          "PkgName": "golang.org/x/net",
          "PkgIdentifier": {
            "PURL": "pkg:golang/golang.org/x/net@v0.10.0",
            "UID": "a0ebc39340d6f291"
          },
          "InstalledVersion": "v0.10.0",
          "FixedVersion": "0.13.0",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:1af0b9fc7854ee24c9d2c6a0bf240f0eda36f6d6745ceabead57db9d46154146",
            "DiffID": "sha256:b628230c51c7f48ef1625319af5a4dc0997450591fe9fb45b0fd7c9e743a69e5"
          },
          "SeveritySource": "ghsa",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-3978",
          "DataSource": {
            "ID": "ghsa",
            "Name": "GitHub Security Advisory Go",
            "URL": "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Ago"
          },
          "Title": "golang.org/x/net/html: Cross site scripting",
          "Description": "Text nodes not in the HTML namespace are incorrectly literally rendered, causing text which should be escaped to not be. This could lead to an XSS attack.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-79"
          ],
          "VendorSeverity": {
            "alma": 2,
            "amazon": 2,
            "azure": 2,
            "cbl-mariner": 2,
            "ghsa": 2,
            "nvd": 2,
            "oracle-oval": 2,
            "redhat": 2
          },
          "CVSS": {
            "ghsa": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
              "V3Score": 6.1
            },
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
              "V3Score": 6.1
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
              "V3Score": 6.1
            }
          },
          "References": [
            "https://access.redhat.com/errata/RHSA-2023:6474",
            "https://access.redhat.com/security/cve/CVE-2023-3978",
            "https://bugzilla.redhat.com/2174485",
            "https://bugzilla.redhat.com/2178358",
            "https://bugzilla.redhat.com/2178488",
            "https://bugzilla.redhat.com/2178492",
            "https://bugzilla.redhat.com/2184481",
            "https://bugzilla.redhat.com/2184482",
            "https://bugzilla.redhat.com/2184483",
            "https://bugzilla.redhat.com/2184484",
            "https://bugzilla.redhat.com/2196026",
            "https://bugzilla.redhat.com/2196027",
            "https://bugzilla.redhat.com/2196029",
            "https://bugzilla.redhat.com/2222167",
            "https://bugzilla.redhat.com/2228689",
            "https://errata.almalinux.org/9/ALSA-2023-6474.html",
            "https://go.dev/cl/514896",
            "https://go.dev/issue/61615",
            "https://linux.oracle.com/cve/CVE-2023-3978.html",
            "https://linux.oracle.com/errata/ELSA-2023-6939.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-3978",
            "https://pkg.go.dev/vuln/GO-2023-1988",
            "https://www.cve.org/CVERecord?id=CVE-2023-3978"
          ],
          "PublishedDate": "2023-08-02T20:15:12.097Z",
          "LastModifiedDate": "2023-11-07T04:20:03.647Z"
        },
        {
          "VulnerabilityID": "CVE-2023-44487",
          "PkgName": "golang.org/x/net",
          "PkgIdentifier": {
            "PURL": "pkg:golang/golang.org/x/net@v0.10.0",
            "UID": "a0ebc39340d6f291"
          },
          "InstalledVersion": "v0.10.0",
          "FixedVersion": "0.17.0",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:1af0b9fc7854ee24c9d2c6a0bf240f0eda36f6d6745ceabead57db9d46154146",
            "DiffID": "sha256:b628230c51c7f48ef1625319af5a4dc0997450591fe9fb45b0fd7c9e743a69e5"
          },
          "SeveritySource": "ghsa",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-44487",
          "DataSource": {
            "ID": "ghsa",
            "Name": "GitHub Security Advisory Go",
            "URL": "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Ago"
          },
          "Title": "HTTP/2: Multiple HTTP/2 enabled web servers are vulnerable to a DDoS attack (Rapid Reset Attack)",
          "Description": "The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation can reset many streams quickly, as exploited in the wild in August through October 2023.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-400"
          ],
          "VendorSeverity": {
            "alma": 3,
            "amazon": 3,
            "azure": 3,
            "bitnami": 3,
            "cbl-mariner": 3,
            "ghsa": 2,
            "nvd": 3,
            "oracle-oval": 3,
            "photon": 3,
            "redhat": 3,
            "rocky": 3,
            "ubuntu": 3
          },
          "CVSS": {
            "bitnami": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 7.5
            },
            "ghsa": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
              "V3Score": 5.3
            },
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 7.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 7.5
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2023/10/13/4",
            "http://www.openwall.com/lists/oss-security/2023/10/13/9",
            "http://www.openwall.com/lists/oss-security/2023/10/18/4",
            "http://www.openwall.com/lists/oss-security/2023/10/18/8",
            "http://www.openwall.com/lists/oss-security/2023/10/19/6",
            "http://www.openwall.com/lists/oss-security/2023/10/20/8",
            "https://access.redhat.com/errata/RHSA-2023:6746",
            "https://access.redhat.com/security/cve/CVE-2023-44487",
            "https://access.redhat.com/security/cve/cve-2023-44487",
            "https://akka.io/security/akka-http-cve-2023-44487.html",
            "https://arstechnica.com/security/2023/10/how-ddosers-used-the-http-2-protocol-to-deliver-attacks-of-unprecedented-size",
            "https://arstechnica.com/security/2023/10/how-ddosers-used-the-http-2-protocol-to-deliver-attacks-of-unprecedented-size/",
            "https://aws.amazon.com/security/security-bulletins/AWS-2023-011",
            "https://aws.amazon.com/security/security-bulletins/AWS-2023-011/",
            "https://blog.cloudflare.com/technical-breakdown-http2-rapid-reset-ddos-attack",
            "https://blog.cloudflare.com/technical-breakdown-http2-rapid-reset-ddos-attack/",
            "https://blog.cloudflare.com/zero-day-rapid-reset-http2-record-breaking-ddos-attack",
            "https://blog.cloudflare.com/zero-day-rapid-reset-http2-record-breaking-ddos-attack/",
            "https://blog.litespeedtech.com/2023/10/11/rapid-reset-http-2-vulnerablilty",
            "https://blog.litespeedtech.com/2023/10/11/rapid-reset-http-2-vulnerablilty/",
            "https://blog.qualys.com/vulnerabilities-threat-research/2023/10/10/cve-2023-44487-http-2-rapid-reset-attack",
            "https://blog.vespa.ai/cve-2023-44487",
            "https://blog.vespa.ai/cve-2023-44487/",
            "https://bugzilla.proxmox.com/show_bug.cgi?id=4988",
            "https://bugzilla.redhat.com/2242803",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2242803",
            "https://bugzilla.suse.com/show_bug.cgi?id=1216123",
            "https://cgit.freebsd.org/ports/commit/?id=c64c329c2c1752f46b73e3e6ce9f4329be6629f9",
            "https://chaos.social/@icing/111210915918780532",
            "https://cloud.google.com/blog/products/identity-security/google-cloud-mitigated-largest-ddos-attack-peaking-above-398-million-rps",
            "https://cloud.google.com/blog/products/identity-security/google-cloud-mitigated-largest-ddos-attack-peaking-above-398-million-rps/",
            "https://cloud.google.com/blog/products/identity-security/how-it-works-the-novel-http2-rapid-reset-ddos-attack",
            "https://community.traefik.io/t/is-traefik-vulnerable-to-cve-2023-44487/20125",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-44487",
            "https://devblogs.microsoft.com/dotnet/october-2023-updates/",
            "https://discuss.hashicorp.com/t/hcsec-2023-32-vault-consul-and-boundary-affected-by-http-2-rapid-reset-denial-of-service-vulnerability-cve-2023-44487/59715",
            "https://edg.io/lp/blog/resets-leaks-ddos-and-the-tale-of-a-hidden-cve",
            "https://errata.almalinux.org/9/ALSA-2023-6746.html",
            "https://errata.rockylinux.org/RLSA-2023:5838",
            "https://forums.swift.org/t/swift-nio-http2-security-update-cve-2023-44487-http-2-dos/67764",
            "https://gist.github.com/adulau/7c2bfb8e9cdbe4b35a5e131c66a0c088",
            "https://github.com/Azure/AKS/issues/3947",
            "https://github.com/Kong/kong/discussions/11741",
            "https://github.com/advisories/GHSA-qppj-fm5r-hxr3",
            "https://github.com/advisories/GHSA-vx74-f528-fxqg",
            "https://github.com/advisories/GHSA-xpw8-rcwv-8f8p",
            "https://github.com/akka/akka-http/issues/4323",
            "https://github.com/akka/akka-http/pull/4324",
            "https://github.com/akka/akka-http/pull/4325",
            "https://github.com/alibaba/tengine/issues/1872",
            "https://github.com/apache/apisix/issues/10320",
            "https://github.com/apache/httpd-site/pull/10",
            "https://github.com/apache/httpd/blob/afcdbeebbff4b0c50ea26cdd16e178c0d1f24152/modules/http2/h2_mplx.c#L1101-L1113",
            "https://github.com/apache/tomcat/commit/944332bb15bd2f3bf76ec2caeb1ff0a58a3bc628",
            "https://github.com/apache/tomcat/tree/main/java/org/apache/coyote/http2",
            "https://github.com/apache/trafficserver/pull/10564",
            "https://github.com/apple/swift-nio-http2",
            "https://github.com/apple/swift-nio-http2/security/advisories/GHSA-qppj-fm5r-hxr3",
            "https://github.com/arkrwn/PoC/tree/main/CVE-2023-44487",
            "https://github.com/bcdannyboy/CVE-2023-44487",
            "https://github.com/caddyserver/caddy/issues/5877",
            "https://github.com/caddyserver/caddy/releases/tag/v2.7.5",
            "https://github.com/dotnet/announcements/issues/277",
            "https://github.com/dotnet/core/blob/e4613450ea0da7fd2fc6b61dfb2c1c1dec1ce9ec/release-notes/6.0/6.0.23/6.0.23.md?plain=1#L73",
            "https://github.com/eclipse/jetty.project/issues/10679",
            "https://github.com/envoyproxy/envoy/pull/30055",
            "https://github.com/etcd-io/etcd/issues/16740",
            "https://github.com/facebook/proxygen/pull/466",
            "https://github.com/golang/go/issues/63417",
            "https://github.com/grpc/grpc-go/pull/6703",
            "https://github.com/grpc/grpc-go/releases",
            "https://github.com/h2o/h2o/pull/3291",
            "https://github.com/h2o/h2o/security/advisories/GHSA-2m7v-gc89-fjqf",
            "https://github.com/haproxy/haproxy/issues/2312",
            "https://github.com/hyperium/hyper/issues/3337",
            "https://github.com/icing/mod_h2/blob/0a864782af0a942aa2ad4ed960a6b32cd35bcf0a/mod_http2/README.md?plain=1#L239-L244",
            "https://github.com/junkurihara/rust-rpxy/issues/97",
            "https://github.com/kazu-yamamoto/http2/commit/f61d41a502bd0f60eb24e1ce14edc7b6df6722a1",
            "https://github.com/kazu-yamamoto/http2/issues/93",
            "https://github.com/kubernetes/kubernetes/pull/121120",
            "https://github.com/line/armeria/pull/5232",
            "https://github.com/linkerd/website/pull/1695/commits/4b9c6836471bc8270ab48aae6fd2181bc73fd632",
            "https://github.com/micrictor/http2-rst-stream",
            "https://github.com/microsoft/CBL-Mariner/pull/6381",
            "https://github.com/netty/netty/commit/58f75f665aa81a8cbcf6ffa74820042a285c5e61",
            "https://github.com/nghttp2/nghttp2/pull/1961",
            "https://github.com/nghttp2/nghttp2/releases/tag/v1.57.0",
            "https://github.com/ninenines/cowboy/issues/1615",
            "https://github.com/nodejs/node/pull/50121",
            "https://github.com/openresty/openresty/issues/930",
            "https://github.com/opensearch-project/data-prepper/issues/3474",
            "https://github.com/oqtane/oqtane.framework/discussions/3367",
            "https://github.com/projectcontour/contour/pull/5826",
            "https://github.com/tempesta-tech/tempesta/issues/1986",
            "https://github.com/varnishcache/varnish-cache/issues/3996",
            "https://go.dev/cl/534215",
            "https://go.dev/cl/534235",
            "https://go.dev/issue/63417",
            "https://groups.google.com/g/golang-announce/c/iNNxDTCjZvo",
            "https://groups.google.com/g/golang-announce/c/iNNxDTCjZvo/m/UDd7VKQuAAAJ",
            "https://istio.io/latest/news/security/istio-security-2023-004",
            "https://istio.io/latest/news/security/istio-security-2023-004/",
            "https://linkerd.io/2023/10/12/linkerd-cve-2023-44487",
            "https://linkerd.io/2023/10/12/linkerd-cve-2023-44487/",
            "https://linux.oracle.com/cve/CVE-2023-44487.html",
            "https://linux.oracle.com/errata/ELSA-2024-1444.html",
            "https://lists.apache.org/thread/5py8h42mxfsn8l1wy6o41xwhsjlsd87q",
            "https://lists.debian.org/debian-lts-announce/2023/10/msg00020.html",
            "https://lists.debian.org/debian-lts-announce/2023/10/msg00023.html",
            "https://lists.debian.org/debian-lts-announce/2023/10/msg00024.html",
            "https://lists.debian.org/debian-lts-announce/2023/10/msg00045.html",
            "https://lists.debian.org/debian-lts-announce/2023/10/msg00047.html",
            "https://lists.debian.org/debian-lts-announce/2023/11/msg00001.html",
            "https://lists.debian.org/debian-lts-announce/2023/11/msg00012.html",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/2MBEPPC36UBVOZZNAXFHKLFGSLCMN5LI",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/2MBEPPC36UBVOZZNAXFHKLFGSLCMN5LI/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/3N4NJ7FR4X4FPZUGNTQAPSTVB2HB2Y4A",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/3N4NJ7FR4X4FPZUGNTQAPSTVB2HB2Y4A/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/BFQD3KUEMFBHPAPBGLWQC34L4OWL5HAZ",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/BFQD3KUEMFBHPAPBGLWQC34L4OWL5HAZ/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/CLB4TW7KALB3EEQWNWCN7OUIWWVWWCG2",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/CLB4TW7KALB3EEQWNWCN7OUIWWVWWCG2/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/E72T67UPDRXHIDLO3OROR25YAMN4GGW5",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/E72T67UPDRXHIDLO3OROR25YAMN4GGW5/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/FNA62Q767CFAFHBCDKYNPBMZWB7TWYVU",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/FNA62Q767CFAFHBCDKYNPBMZWB7TWYVU/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/HT7T2R4MQKLIF4ODV4BDLPARWFPCJ5CZ",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/HT7T2R4MQKLIF4ODV4BDLPARWFPCJ5CZ/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/JIZSEFC3YKCGABA2BZW6ZJRMDZJMB7PJ",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/JIZSEFC3YKCGABA2BZW6ZJRMDZJMB7PJ/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/JMEXY22BFG5Q64HQCM5CK2Q7KDKVV4TY",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/JMEXY22BFG5Q64HQCM5CK2Q7KDKVV4TY/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/KSEGD2IWKNUO3DWY4KQGUQM5BISRWHQE",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/KSEGD2IWKNUO3DWY4KQGUQM5BISRWHQE/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/LKYHSZQFDNR7RSA7LHVLLIAQMVYCUGBG",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/LKYHSZQFDNR7RSA7LHVLLIAQMVYCUGBG/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/LNMZJCDHGLJJLXO4OXWJMTVQRNWOC7UL",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/LNMZJCDHGLJJLXO4OXWJMTVQRNWOC7UL/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/VHUHTSXLXGXS7JYKBXTA3VINUPHTNGVU",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/VHUHTSXLXGXS7JYKBXTA3VINUPHTNGVU/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/VSRDIV77HNKUSM7SJC5BKE5JSHLHU2NK",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/VSRDIV77HNKUSM7SJC5BKE5JSHLHU2NK/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/WE2I52RHNNU42PX6NZ2RBUHSFFJ2LVZX",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/WE2I52RHNNU42PX6NZ2RBUHSFFJ2LVZX/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/WLPRQ5TWUQQXYWBJM7ECYDAIL2YVKIUH",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/WLPRQ5TWUQQXYWBJM7ECYDAIL2YVKIUH/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/X6QXN4ORIVF6XBW4WWFE7VNPVC74S45Y",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/X6QXN4ORIVF6XBW4WWFE7VNPVC74S45Y/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/XFOIBB4YFICHDM7IBOP7PWXW3FX4HLL2",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/XFOIBB4YFICHDM7IBOP7PWXW3FX4HLL2/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/ZB43REMKRQR62NJEI7I5NQ4FSXNLBKRT",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/ZB43REMKRQR62NJEI7I5NQ4FSXNLBKRT/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/ZKQSIKIAT5TJ3WSLU3RDBQ35YX4GY4V3",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/ZKQSIKIAT5TJ3WSLU3RDBQ35YX4GY4V3/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/ZLU6U2R2IC2K64NDPNMV55AUAO65MAF4",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/ZLU6U2R2IC2K64NDPNMV55AUAO65MAF4/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/3N4NJ7FR4X4FPZUGNTQAPSTVB2HB2Y4A",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/BFQD3KUEMFBHPAPBGLWQC34L4OWL5HAZ",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/CLB4TW7KALB3EEQWNWCN7OUIWWVWWCG2",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/E72T67UPDRXHIDLO3OROR25YAMN4GGW5",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FNA62Q767CFAFHBCDKYNPBMZWB7TWYVU",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/HT7T2R4MQKLIF4ODV4BDLPARWFPCJ5CZ",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/JIZSEFC3YKCGABA2BZW6ZJRMDZJMB7PJ",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/JMEXY22BFG5Q64HQCM5CK2Q7KDKVV4TY",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/KSEGD2IWKNUO3DWY4KQGUQM5BISRWHQE",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/LKYHSZQFDNR7RSA7LHVLLIAQMVYCUGBG",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/LNMZJCDHGLJJLXO4OXWJMTVQRNWOC7UL",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/VHUHTSXLXGXS7JYKBXTA3VINUPHTNGVU",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/VSRDIV77HNKUSM7SJC5BKE5JSHLHU2NK",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/WLPRQ5TWUQQXYWBJM7ECYDAIL2YVKIUH",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/X6QXN4ORIVF6XBW4WWFE7VNPVC74S45Y",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/XFOIBB4YFICHDM7IBOP7PWXW3FX4HLL2",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ZB43REMKRQR62NJEI7I5NQ4FSXNLBKRT",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ZKQSIKIAT5TJ3WSLU3RDBQ35YX4GY4V3",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ZLU6U2R2IC2K64NDPNMV55AUAO65MAF4",
            "https://lists.w3.org/Archives/Public/ietf-http-wg/2023OctDec/0025.html",
            "https://mailman.nginx.org/pipermail/nginx-devel/2023-October/S36Q5HBXR7CAIMPLLPRSSSYR4PCMWILK.html",
            "https://martinthomson.github.io/h2-stream-limits/draft-thomson-httpbis-h2-stream-limits.html",
            "https://msrc.microsoft.com/blog/2023/10/microsoft-response-to-distributed-denial-of-service-ddos-attacks-against-http/2",
            "https://msrc.microsoft.com/blog/2023/10/microsoft-response-to-distributed-denial-of-service-ddos-attacks-against-http/2/",
            "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-44487",
            "https://my.f5.com/manage/s/article/K000137106",
            "https://netty.io/news/2023/10/10/4-1-100-Final.html",
            "https://news.ycombinator.com/item?id=37830987",
            "https://news.ycombinator.com/item?id=37830998",
            "https://news.ycombinator.com/item?id=37831062",
            "https://news.ycombinator.com/item?id=37837043",
            "https://nodejs.org/en/blog/vulnerability/october-2023-security-releases",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-44487",
            "https://openssf.org/blog/2023/10/10/http-2-rapid-reset-vulnerability-highlights-need-for-rapid-response",
            "https://openssf.org/blog/2023/10/10/http-2-rapid-reset-vulnerability-highlights-need-for-rapid-response/",
            "https://pkg.go.dev/vuln/GO-2023-2102",
            "https://seanmonstar.com/post/730794151136935936/hyper-http2-rapid-reset-unaffected",
            "https://security.gentoo.org/glsa/202311-09",
            "https://security.netapp.com/advisory/ntap-20231016-0001",
            "https://security.netapp.com/advisory/ntap-20231016-0001/",
            "https://security.netapp.com/advisory/ntap-20240426-0007",
            "https://security.netapp.com/advisory/ntap-20240426-0007/",
            "https://security.netapp.com/advisory/ntap-20240621-0006",
            "https://security.netapp.com/advisory/ntap-20240621-0006/",
            "https://security.netapp.com/advisory/ntap-20240621-0007",
            "https://security.netapp.com/advisory/ntap-20240621-0007/",
            "https://security.paloaltonetworks.com/CVE-2023-44487",
            "https://tomcat.apache.org/security-10.html#Fixed_in_Apache_Tomcat_10.1.14",
            "https://tomcat.apache.org/security-11.html#Fixed_in_Apache_Tomcat_11.0.0-M12",
            "https://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.5.94",
            "https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.81",
            "https://ubuntu.com/security/CVE-2023-44487",
            "https://ubuntu.com/security/notices/USN-6427-1",
            "https://ubuntu.com/security/notices/USN-6427-2",
            "https://ubuntu.com/security/notices/USN-6438-1",
            "https://ubuntu.com/security/notices/USN-6505-1",
            "https://ubuntu.com/security/notices/USN-6574-1",
            "https://ubuntu.com/security/notices/USN-6754-1",
            "https://ubuntu.com/security/notices/USN-6994-1",
            "https://www.bleepingcomputer.com/news/security/new-http-2-rapid-reset-zero-day-attack-breaks-ddos-records",
            "https://www.bleepingcomputer.com/news/security/new-http-2-rapid-reset-zero-day-attack-breaks-ddos-records/",
            "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "https://www.cisa.gov/news-events/alerts/2023/10/10/http2-rapid-reset-vulnerability-cve-2023-44487",
            "https://www.cve.org/CVERecord?id=CVE-2023-44487",
            "https://www.darkreading.com/cloud/internet-wide-zero-day-bug-fuels-largest-ever-ddos-event",
            "https://www.debian.org/security/2023/dsa-5521",
            "https://www.debian.org/security/2023/dsa-5522",
            "https://www.debian.org/security/2023/dsa-5540",
            "https://www.debian.org/security/2023/dsa-5549",
            "https://www.debian.org/security/2023/dsa-5558",
            "https://www.debian.org/security/2023/dsa-5570",
            "https://www.eclipse.org/lists/jetty-announce/msg00181.html",
            "https://www.haproxy.com/blog/haproxy-is-not-affected-by-the-http-2-rapid-reset-attack-cve-2023-44487",
            "https://www.mail-archive.com/haproxy@formilux.org/msg44134.html",
            "https://www.netlify.com/blog/netlify-successfully-mitigates-cve-2023-44487",
            "https://www.netlify.com/blog/netlify-successfully-mitigates-cve-2023-44487/",
            "https://www.nginx.com/blog/http-2-rapid-reset-attack-impacting-f5-nginx-products",
            "https://www.nginx.com/blog/http-2-rapid-reset-attack-impacting-f5-nginx-products/",
            "https://www.openwall.com/lists/oss-security/2023/10/10/6",
            "https://www.phoronix.com/news/HTTP2-Rapid-Reset-Attack",
            "https://www.theregister.com/2023/10/10/http2_rapid_reset_zeroday",
            "https://www.theregister.com/2023/10/10/http2_rapid_reset_zeroday/"
          ],
          "PublishedDate": "2023-10-10T14:15:10.883Z",
          "LastModifiedDate": "2024-08-14T19:57:18.86Z"
        },
        {
          "VulnerabilityID": "CVE-2023-45288",
          "PkgName": "golang.org/x/net",
          "PkgIdentifier": {
            "PURL": "pkg:golang/golang.org/x/net@v0.10.0",
            "UID": "a0ebc39340d6f291"
          },
          "InstalledVersion": "v0.10.0",
          "FixedVersion": "0.23.0",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:1af0b9fc7854ee24c9d2c6a0bf240f0eda36f6d6745ceabead57db9d46154146",
            "DiffID": "sha256:b628230c51c7f48ef1625319af5a4dc0997450591fe9fb45b0fd7c9e743a69e5"
          },
          "SeveritySource": "ghsa",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-45288",
          "DataSource": {
            "ID": "ghsa",
            "Name": "GitHub Security Advisory Go",
            "URL": "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Ago"
          },
          "Title": "golang: net/http, x/net/http2: unlimited number of CONTINUATION frames causes DoS",
          "Description": "An attacker may cause an HTTP/2 endpoint to read arbitrary amounts of header data by sending an excessive number of CONTINUATION frames. Maintaining HPACK state requires parsing and processing all HEADERS and CONTINUATION frames on a connection. When a request's headers exceed MaxHeaderBytes, no memory is allocated to store the excess headers, but they are still parsed. This permits an attacker to cause an HTTP/2 endpoint to read arbitrary amounts of header data, all associated with a request which is going to be rejected. These headers can include Huffman-encoded data which is significantly more expensive for the receiver to decode than for an attacker to send. The fix sets a limit on the amount of excess header frames we will process before closing a connection.",
          "Severity": "MEDIUM",
          "VendorSeverity": {
            "alma": 3,
            "amazon": 2,
            "azure": 3,
            "bitnami": 3,
            "cbl-mariner": 3,
            "ghsa": 2,
            "oracle-oval": 3,
            "photon": 3,
            "redhat": 3,
            "rocky": 3,
            "ubuntu": 2
          },
          "CVSS": {
            "bitnami": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 7.5
            },
            "ghsa": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
              "V3Score": 5.3
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 7.5
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2024/04/03/16",
            "http://www.openwall.com/lists/oss-security/2024/04/05/4",
            "https://access.redhat.com/errata/RHSA-2024:2724",
            "https://access.redhat.com/security/cve/CVE-2023-45288",
            "https://bugzilla.redhat.com/2268017",
            "https://bugzilla.redhat.com/2268018",
            "https://bugzilla.redhat.com/2268019",
            "https://bugzilla.redhat.com/2268273",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2268017",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2268018",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2268019",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2268273",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-45288",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-45289",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-45290",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-24783",
            "https://errata.almalinux.org/9/ALSA-2024-2724.html",
            "https://errata.rockylinux.org/RLSA-2024:2724",
            "https://go.dev/cl/576155",
            "https://go.dev/issue/65051",
            "https://groups.google.com/g/golang-announce/c/YgW0sx8mN3M",
            "https://kb.cert.org/vuls/id/421644",
            "https://linux.oracle.com/cve/CVE-2023-45288.html",
            "https://linux.oracle.com/errata/ELSA-2024-3346.html",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/QRYFHIQ6XRKRYBI2F5UESH67BJBQXUPT",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/QRYFHIQ6XRKRYBI2F5UESH67BJBQXUPT/",
            "https://nowotarski.info/http2-continuation-flood-technical-details",
            "https://nowotarski.info/http2-continuation-flood/",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-45288",
            "https://pkg.go.dev/vuln/GO-2024-2687",
            "https://security.netapp.com/advisory/ntap-20240419-0009",
            "https://security.netapp.com/advisory/ntap-20240419-0009/",
            "https://ubuntu.com/security/notices/USN-6886-1",
            "https://www.cve.org/CVERecord?id=CVE-2023-45288",
            "https://www.kb.cert.org/vuls/id/421644"
          ],
          "PublishedDate": "2024-04-04T21:15:16.113Z",
          "LastModifiedDate": "2024-08-26T21:35:02.457Z"
        },
        {
          "VulnerabilityID": "CVE-2024-24786",
          "PkgName": "google.golang.org/protobuf",
          "PkgIdentifier": {
            "PURL": "pkg:golang/google.golang.org/protobuf@v1.30.0",
            "UID": "643ea23e8ba69a85"
          },
          "InstalledVersion": "v1.30.0",
          "FixedVersion": "1.33.0",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:1af0b9fc7854ee24c9d2c6a0bf240f0eda36f6d6745ceabead57db9d46154146",
            "DiffID": "sha256:b628230c51c7f48ef1625319af5a4dc0997450591fe9fb45b0fd7c9e743a69e5"
          },
          "SeveritySource": "ghsa",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-24786",
          "DataSource": {
            "ID": "ghsa",
            "Name": "GitHub Security Advisory Go",
            "URL": "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Ago"
          },
          "Title": "golang-protobuf: encoding/protojson, internal/encoding/json: infinite loop in protojson.Unmarshal when unmarshaling certain forms of invalid JSON",
          "Description": "The protojson.Unmarshal function can enter an infinite loop when unmarshaling certain forms of invalid JSON. This condition can occur when unmarshaling into a message which contains a google.protobuf.Any value, or when the UnmarshalOptions.DiscardUnknown option is set.",
          "Severity": "MEDIUM",
          "VendorSeverity": {
            "alma": 2,
            "amazon": 2,
            "azure": 2,
            "cbl-mariner": 2,
            "ghsa": 2,
            "oracle-oval": 2,
            "redhat": 2,
            "rocky": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 5.9
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2024/03/08/4",
            "https://access.redhat.com/errata/RHSA-2024:2550",
            "https://access.redhat.com/security/cve/CVE-2024-24786",
            "https://bugzilla.redhat.com/2268046",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-24786",
            "https://errata.almalinux.org/9/ALSA-2024-2550.html",
            "https://errata.rockylinux.org/RLSA-2024:2550",
            "https://github.com/protocolbuffers/protobuf-go",
            "https://github.com/protocolbuffers/protobuf-go/commit/f01a588e5810b90996452eec4a28f22a0afae023",
            "https://github.com/protocolbuffers/protobuf-go/releases/tag/v1.33.0",
            "https://go-review.googlesource.com/c/protobuf/+/569356",
            "https://go.dev/cl/569356",
            "https://groups.google.com/g/golang-announce/c/ArQ6CDgtEjY/",
            "https://linux.oracle.com/cve/CVE-2024-24786.html",
            "https://linux.oracle.com/errata/ELSA-2024-4246.html",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/JDMBHAVSDU2FBDZ45U3A2VLSM35OJ2HU",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/JDMBHAVSDU2FBDZ45U3A2VLSM35OJ2HU/",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-24786",
            "https://pkg.go.dev/vuln/GO-2024-2611",
            "https://security.netapp.com/advisory/ntap-20240517-0002",
            "https://security.netapp.com/advisory/ntap-20240517-0002/",
            "https://ubuntu.com/security/notices/USN-6746-1",
            "https://ubuntu.com/security/notices/USN-6746-2",
            "https://www.cve.org/CVERecord?id=CVE-2024-24786"
          ],
          "PublishedDate": "2024-03-05T23:15:07.82Z",
          "LastModifiedDate": "2024-06-10T18:15:26.83Z"
        },
        {
          "VulnerabilityID": "CVE-2024-24790",
          "PkgName": "stdlib",
          "PkgIdentifier": {
            "PURL": "pkg:golang/stdlib@1.20.6",
            "UID": "dc395f725e23d7d8"
          },
          "InstalledVersion": "1.20.6",
          "FixedVersion": "1.21.11, 1.22.4",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:1af0b9fc7854ee24c9d2c6a0bf240f0eda36f6d6745ceabead57db9d46154146",
            "DiffID": "sha256:b628230c51c7f48ef1625319af5a4dc0997450591fe9fb45b0fd7c9e743a69e5"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-24790",
          "DataSource": {
            "ID": "govulndb",
            "Name": "The Go Vulnerability Database",
            "URL": "https://pkg.go.dev/vuln/"
          },
          "Title": "golang: net/netip: Unexpected behavior from Is methods for IPv4-mapped IPv6 addresses",
          "Description": "The various Is methods (IsPrivate, IsLoopback, etc) did not work as expected for IPv4-mapped IPv6 addresses, returning false for addresses which would return true in their traditional IPv4 forms.",
          "Severity": "CRITICAL",
          "VendorSeverity": {
            "alma": 2,
            "amazon": 2,
            "bitnami": 4,
            "cbl-mariner": 4,
            "nvd": 4,
            "oracle-oval": 2,
            "photon": 4,
            "redhat": 2,
            "rocky": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "bitnami": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
              "V3Score": 9.8
            },
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
              "V3Score": 9.8
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
              "V3Score": 6.7
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2024/06/04/1",
            "https://access.redhat.com/errata/RHSA-2024:4212",
            "https://access.redhat.com/security/cve/CVE-2024-24790",
            "https://bugzilla.redhat.com/2292668",
            "https://bugzilla.redhat.com/2292787",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2292668",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2292787",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-24789",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-24790",
            "https://errata.almalinux.org/9/ALSA-2024-4212.html",
            "https://errata.rockylinux.org/RLSA-2024:4212",
            "https://github.com/golang/go/commit/051bdf3fd12a40307606ff9381138039c5f452f0 (1.21)",
            "https://github.com/golang/go/commit/12d5810cdb1f73cf23d7a86462143e9463317fca (1.22)",
            "https://github.com/golang/go/issues/67680",
            "https://go.dev/cl/590316",
            "https://go.dev/issue/67680",
            "https://groups.google.com/g/golang-announce/c/XbxouI9gY7k",
            "https://groups.google.com/g/golang-announce/c/XbxouI9gY7k/m/TuoGEhxIEwAJ",
            "https://linux.oracle.com/cve/CVE-2024-24790.html",
            "https://linux.oracle.com/errata/ELSA-2024-5291.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-24790",
            "https://pkg.go.dev/vuln/GO-2024-2887",
            "https://ubuntu.com/security/notices/USN-6886-1",
            "https://www.cve.org/CVERecord?id=CVE-2024-24790"
          ],
          "PublishedDate": "2024-06-05T16:15:10.56Z",
          "LastModifiedDate": "2024-09-03T18:35:07.483Z"
        },
        {
          "VulnerabilityID": "CVE-2023-39325",
          "PkgName": "stdlib",
          "PkgIdentifier": {
            "PURL": "pkg:golang/stdlib@1.20.6",
            "UID": "dc395f725e23d7d8"
          },
          "InstalledVersion": "1.20.6",
          "FixedVersion": "1.20.10, 1.21.3",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:1af0b9fc7854ee24c9d2c6a0bf240f0eda36f6d6745ceabead57db9d46154146",
            "DiffID": "sha256:b628230c51c7f48ef1625319af5a4dc0997450591fe9fb45b0fd7c9e743a69e5"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-39325",
          "DataSource": {
            "ID": "govulndb",
            "Name": "The Go Vulnerability Database",
            "URL": "https://pkg.go.dev/vuln/"
          },
          "Title": "golang: net/http, x/net/http2: rapid stream resets can cause excessive work (CVE-2023-44487)",
          "Description": "A malicious HTTP/2 client which rapidly creates requests and immediately resets them can cause excessive server resource consumption. While the total number of requests is bounded by the http2.Server.MaxConcurrentStreams setting, resetting an in-progress request allows the attacker to create a new request while the existing one is still executing. With the fix applied, HTTP/2 servers now bound the number of simultaneously executing handler goroutines to the stream concurrency limit (MaxConcurrentStreams). New requests arriving when at the limit (which can only happen after the client has reset an existing, in-flight request) will be queued until a handler exits. If the request queue grows too large, the server will terminate the connection. This issue is also fixed in golang.org/x/net/http2 for users manually configuring HTTP/2. The default stream concurrency limit is 250 streams (requests) per HTTP/2 connection. This value may be adjusted using the golang.org/x/net/http2 package; see the Server.MaxConcurrentStreams setting and the ConfigureServer function.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-770"
          ],
          "VendorSeverity": {
            "alma": 2,
            "amazon": 3,
            "azure": 3,
            "bitnami": 3,
            "cbl-mariner": 3,
            "ghsa": 3,
            "nvd": 3,
            "oracle-oval": 2,
            "redhat": 3,
            "rocky": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "bitnami": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 7.5
            },
            "ghsa": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 7.5
            },
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 7.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 7.5
            }
          },
          "References": [
            "golang.org/x/net",
            "https://access.redhat.com/errata/RHSA-2023:6077",
            "https://access.redhat.com/security/cve/CVE-2023-39325",
            "https://access.redhat.com/security/cve/CVE-2023-44487",
            "https://access.redhat.com/security/vulnerabilities/RHSB-2023-003",
            "https://bugzilla.redhat.com/2242803",
            "https://bugzilla.redhat.com/2243296",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2242803",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2243296",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-39325",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-44487",
            "https://errata.almalinux.org/9/ALSA-2023-6077.html",
            "https://errata.rockylinux.org/RLSA-2023:6077",
            "https://github.com/golang/go/commit/24ae2d927285c697440fdde3ad7f26028354bcf3 [golang- 1.21]",
            "https://github.com/golang/go/commit/e175f27f58aa7b9cd4d79607ae65d2cd5baaee68 [golang-1.20]",
            "https://github.com/golang/go/issues/63417",
            "https://go.dev/cl/534215",
            "https://go.dev/cl/534235",
            "https://go.dev/issue/63417",
            "https://groups.google.com/g/golang-announce/c/iNNxDTCjZvo/m/UDd7VKQuAAAJ",
            "https://linux.oracle.com/cve/CVE-2023-39325.html",
            "https://linux.oracle.com/errata/ELSA-2023-5867.html",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/3OVW5V2DM5K5IC3H7O42YDUGNJ74J35O",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/3OVW5V2DM5K5IC3H7O42YDUGNJ74J35O/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/3SZN67IL7HMGMNAVLOTIXLIHUDXZK4LH",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/3SZN67IL7HMGMNAVLOTIXLIHUDXZK4LH/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/3WJ4QVX2AMUJ2F2S27POOAHRC4K3CHU4",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/3WJ4QVX2AMUJ2F2S27POOAHRC4K3CHU4/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/4BUK2ZIAGCULOOYDNH25JPU6JBES5NF2",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/4BUK2ZIAGCULOOYDNH25JPU6JBES5NF2/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/5RSKA2II6QTD4YUKUNDVJQSRYSFC4VFR",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/5RSKA2II6QTD4YUKUNDVJQSRYSFC4VFR/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/AVZDNSMVDAQJ64LJC5I5U5LDM5753647",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/AVZDNSMVDAQJ64LJC5I5U5LDM5753647/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/CHHITS4PUOZAKFIUBQAQZC7JWXMOYE4B",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/CHHITS4PUOZAKFIUBQAQZC7JWXMOYE4B/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/CLB4TW7KALB3EEQWNWCN7OUIWWVWWCG2",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/CLB4TW7KALB3EEQWNWCN7OUIWWVWWCG2/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/D2BBIDR2ZMB3X5BC7SR4SLQMHRMVPY6L",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/D2BBIDR2ZMB3X5BC7SR4SLQMHRMVPY6L/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ECRC75BQJP6FJN2L7KCKYZW4DSBD7QSD",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ECRC75BQJP6FJN2L7KCKYZW4DSBD7QSD/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FTMJ3NJIDAZFWJQQSP3L22MUFJ3UP2PT",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FTMJ3NJIDAZFWJQQSP3L22MUFJ3UP2PT/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/GSY7SXFFTPZFWDM6XELSDSHZLVW3AHK7",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/GSY7SXFFTPZFWDM6XELSDSHZLVW3AHK7/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/HZQIELEIRSZUYTFFH5KTH2YJ4IIQG2KE",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/HZQIELEIRSZUYTFFH5KTH2YJ4IIQG2KE/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/IPWCNYB5PQ5PCVZ4NJT6G56ZYFZ5QBU6",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/IPWCNYB5PQ5PCVZ4NJT6G56ZYFZ5QBU6/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/KEOTKBUPZXHE3F352JBYNTSNRXYLWD6P",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/KEOTKBUPZXHE3F352JBYNTSNRXYLWD6P/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/KSEGD2IWKNUO3DWY4KQGUQM5BISRWHQE",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/KSEGD2IWKNUO3DWY4KQGUQM5BISRWHQE/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/L5E5JSJBZLYXOTZWXHJKRVCIXIHVWKJ6",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/L5E5JSJBZLYXOTZWXHJKRVCIXIHVWKJ6/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/MZQYOOKHQDQ57LV2IAG6NRFOVXKHJJ3Z",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/MZQYOOKHQDQ57LV2IAG6NRFOVXKHJJ3Z/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/NG7IMPL55MVWU3LCI4JQJT3K2U5CHDV7",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/NG7IMPL55MVWU3LCI4JQJT3K2U5CHDV7/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ODBY7RVMGZCBSTWF2OZGIZS57FNFUL67",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ODBY7RVMGZCBSTWF2OZGIZS57FNFUL67/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/OXGWPQOJ3JNDW2XIYKIVJ7N7QUIFNM2Q",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/OXGWPQOJ3JNDW2XIYKIVJ7N7QUIFNM2Q/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/PJCUNGIQDUMZ4Z6HWVYIMR66A35F5S74",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/PJCUNGIQDUMZ4Z6HWVYIMR66A35F5S74/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/QF5QSYAOPDOWLY6DUHID56Q4HQFYB45I",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/QF5QSYAOPDOWLY6DUHID56Q4HQFYB45I/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/QXOU2JZUBEBP7GBKAYIJRPRBZSJCD7ST",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/QXOU2JZUBEBP7GBKAYIJRPRBZSJCD7ST/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/R3UETKPUB3V5JS5TLZOF3SMTGT5K5APS",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/R3UETKPUB3V5JS5TLZOF3SMTGT5K5APS/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/REMHVVIBDNKSRKNOTV7EQSB7CYQWOUOU",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/REMHVVIBDNKSRKNOTV7EQSB7CYQWOUOU/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/T7N5GV4CHH6WAGX3GFMDD3COEOVCZ4RI",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/T7N5GV4CHH6WAGX3GFMDD3COEOVCZ4RI/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ULQQONMSCQSH5Z5OWFFQHCGEZ3NL4DRJ",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ULQQONMSCQSH5Z5OWFFQHCGEZ3NL4DRJ/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/UTT7DG3QOF5ZNJLUGHDNLRUIN6OWZARP",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/UTT7DG3QOF5ZNJLUGHDNLRUIN6OWZARP/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/W2LZSWTV4NV4SNQARNXG5T6LRHP26EW2",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/W2LZSWTV4NV4SNQARNXG5T6LRHP26EW2/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/WCNCBYKZXLDFGAJUB7ZP5VLC3YTHJNVH",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/WCNCBYKZXLDFGAJUB7ZP5VLC3YTHJNVH/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/XFOIBB4YFICHDM7IBOP7PWXW3FX4HLL2",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/XFOIBB4YFICHDM7IBOP7PWXW3FX4HLL2/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/XTNLSL44Y5FB6JWADSZH6DCV4JJAAEQY",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/XTNLSL44Y5FB6JWADSZH6DCV4JJAAEQY/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/YJWHBLVZDM5KQSDFRBFRKU5KSSOLIRQ4",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/YJWHBLVZDM5KQSDFRBFRKU5KSSOLIRQ4/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/YRKEXKANQ7BKJW2YTAMP625LJUJZLJ4P",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/YRKEXKANQ7BKJW2YTAMP625LJUJZLJ4P/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ZSVEMQV5ROY5YW5QE3I57HT3ITWG5GCV",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ZSVEMQV5ROY5YW5QE3I57HT3ITWG5GCV/",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-39325",
            "https://pkg.go.dev/vuln/GO-2023-2102",
            "https://security.gentoo.org/glsa/202311-09",
            "https://security.netapp.com/advisory/ntap-20231110-0008",
            "https://security.netapp.com/advisory/ntap-20231110-0008/",
            "https://ubuntu.com/security/notices/USN-6574-1",
            "https://www.cisa.gov/news-events/alerts/2023/10/10/http2-rapid-reset-vulnerability-cve-2023-44487",
            "https://www.cve.org/CVERecord?id=CVE-2023-39325"
          ],
          "PublishedDate": "2023-10-11T22:15:09.88Z",
          "LastModifiedDate": "2024-04-28T04:15:09.877Z"
        },
        {
          "VulnerabilityID": "CVE-2023-45283",
          "PkgName": "stdlib",
          "PkgIdentifier": {
            "PURL": "pkg:golang/stdlib@1.20.6",
            "UID": "dc395f725e23d7d8"
          },
          "InstalledVersion": "1.20.6",
          "FixedVersion": "1.20.11, 1.21.4, 1.20.12, 1.21.5",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:1af0b9fc7854ee24c9d2c6a0bf240f0eda36f6d6745ceabead57db9d46154146",
            "DiffID": "sha256:b628230c51c7f48ef1625319af5a4dc0997450591fe9fb45b0fd7c9e743a69e5"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-45283",
          "DataSource": {
            "ID": "govulndb",
            "Name": "The Go Vulnerability Database",
            "URL": "https://pkg.go.dev/vuln/"
          },
          "Title": "The filepath package does not recognize paths with a \\??\\ prefix as sp ...",
          "Description": "The filepath package does not recognize paths with a \\??\\ prefix as special. On Windows, a path beginning with \\??\\ is a Root Local Device path equivalent to a path beginning with \\\\?\\. Paths with a \\??\\ prefix may be used to access arbitrary locations on the system. For example, the path \\??\\c:\\x is equivalent to the more common path c:\\x. Before fix, Clean could convert a rooted path such as \\a\\..\\??\\b into the root local device path \\??\\b. Clean will now convert this to .\\??\\b. Similarly, Join(\\, ??, b) could convert a seemingly innocent sequence of path elements into the root local device path \\??\\b. Join will now convert this to \\.\\??\\b. In addition, with fix, IsAbs now correctly reports paths beginning with \\??\\ as absolute, and VolumeName correctly reports the \\??\\ prefix as a volume name. UPDATE: Go 1.20.11 and Go 1.21.4 inadvertently changed the definition of the volume name in Windows paths starting with \\?, resulting in filepath.Clean(\\?\\c:) returning \\?\\c: rather than \\?\\c:\\ (among other effects). The previous behavior has been restored.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-22"
          ],
          "VendorSeverity": {
            "amazon": 2,
            "bitnami": 3,
            "cbl-mariner": 3,
            "nvd": 3,
            "photon": 3
          },
          "CVSS": {
            "bitnami": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
              "V3Score": 7.5
            },
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
              "V3Score": 7.5
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2023/12/05/2",
            "https://go.dev/cl/540277",
            "https://go.dev/cl/541175",
            "https://go.dev/issue/63713",
            "https://go.dev/issue/64028",
            "https://groups.google.com/g/golang-announce/c/4tU8LZfBFkY",
            "https://groups.google.com/g/golang-dev/c/6ypN5EjibjM/m/KmLVYH_uAgAJ",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-45283",
            "https://pkg.go.dev/vuln/GO-2023-2185",
            "https://security.netapp.com/advisory/ntap-20231214-0008/"
          ],
          "PublishedDate": "2023-11-09T17:15:08.757Z",
          "LastModifiedDate": "2023-12-14T10:15:07.947Z"
        },
        {
          "VulnerabilityID": "CVE-2023-45288",
          "PkgName": "stdlib",
          "PkgIdentifier": {
            "PURL": "pkg:golang/stdlib@1.20.6",
            "UID": "dc395f725e23d7d8"
          },
          "InstalledVersion": "1.20.6",
          "FixedVersion": "1.21.9, 1.22.2",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:1af0b9fc7854ee24c9d2c6a0bf240f0eda36f6d6745ceabead57db9d46154146",
            "DiffID": "sha256:b628230c51c7f48ef1625319af5a4dc0997450591fe9fb45b0fd7c9e743a69e5"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-45288",
          "DataSource": {
            "ID": "govulndb",
            "Name": "The Go Vulnerability Database",
            "URL": "https://pkg.go.dev/vuln/"
          },
          "Title": "golang: net/http, x/net/http2: unlimited number of CONTINUATION frames causes DoS",
          "Description": "An attacker may cause an HTTP/2 endpoint to read arbitrary amounts of header data by sending an excessive number of CONTINUATION frames. Maintaining HPACK state requires parsing and processing all HEADERS and CONTINUATION frames on a connection. When a request's headers exceed MaxHeaderBytes, no memory is allocated to store the excess headers, but they are still parsed. This permits an attacker to cause an HTTP/2 endpoint to read arbitrary amounts of header data, all associated with a request which is going to be rejected. These headers can include Huffman-encoded data which is significantly more expensive for the receiver to decode than for an attacker to send. The fix sets a limit on the amount of excess header frames we will process before closing a connection.",
          "Severity": "HIGH",
          "VendorSeverity": {
            "alma": 3,
            "amazon": 2,
            "azure": 3,
            "bitnami": 3,
            "cbl-mariner": 3,
            "ghsa": 2,
            "oracle-oval": 3,
            "photon": 3,
            "redhat": 3,
            "rocky": 3,
            "ubuntu": 2
          },
          "CVSS": {
            "bitnami": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 7.5
            },
            "ghsa": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
              "V3Score": 5.3
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 7.5
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2024/04/03/16",
            "http://www.openwall.com/lists/oss-security/2024/04/05/4",
            "https://access.redhat.com/errata/RHSA-2024:2724",
            "https://access.redhat.com/security/cve/CVE-2023-45288",
            "https://bugzilla.redhat.com/2268017",
            "https://bugzilla.redhat.com/2268018",
            "https://bugzilla.redhat.com/2268019",
            "https://bugzilla.redhat.com/2268273",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2268017",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2268018",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2268019",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2268273",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-45288",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-45289",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-45290",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-24783",
            "https://errata.almalinux.org/9/ALSA-2024-2724.html",
            "https://errata.rockylinux.org/RLSA-2024:2724",
            "https://go.dev/cl/576155",
            "https://go.dev/issue/65051",
            "https://groups.google.com/g/golang-announce/c/YgW0sx8mN3M",
            "https://kb.cert.org/vuls/id/421644",
            "https://linux.oracle.com/cve/CVE-2023-45288.html",
            "https://linux.oracle.com/errata/ELSA-2024-3346.html",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/QRYFHIQ6XRKRYBI2F5UESH67BJBQXUPT",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/QRYFHIQ6XRKRYBI2F5UESH67BJBQXUPT/",
            "https://nowotarski.info/http2-continuation-flood-technical-details",
            "https://nowotarski.info/http2-continuation-flood/",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-45288",
            "https://pkg.go.dev/vuln/GO-2024-2687",
            "https://security.netapp.com/advisory/ntap-20240419-0009",
            "https://security.netapp.com/advisory/ntap-20240419-0009/",
            "https://ubuntu.com/security/notices/USN-6886-1",
            "https://www.cve.org/CVERecord?id=CVE-2023-45288",
            "https://www.kb.cert.org/vuls/id/421644"
          ],
          "PublishedDate": "2024-04-04T21:15:16.113Z",
          "LastModifiedDate": "2024-08-26T21:35:02.457Z"
        },
        {
          "VulnerabilityID": "CVE-2024-34156",
          "PkgName": "stdlib",
          "PkgIdentifier": {
            "PURL": "pkg:golang/stdlib@1.20.6",
            "UID": "dc395f725e23d7d8"
          },
          "InstalledVersion": "1.20.6",
          "FixedVersion": "1.22.7, 1.23.1",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:1af0b9fc7854ee24c9d2c6a0bf240f0eda36f6d6745ceabead57db9d46154146",
            "DiffID": "sha256:b628230c51c7f48ef1625319af5a4dc0997450591fe9fb45b0fd7c9e743a69e5"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-34156",
          "DataSource": {
            "ID": "govulndb",
            "Name": "The Go Vulnerability Database",
            "URL": "https://pkg.go.dev/vuln/"
          },
          "Title": "encoding/gob: golang: Calling Decoder.Decode on a message which contains deeply nested structures can cause a panic due to stack exhaustion",
          "Description": "Calling Decoder.Decode on a message which contains deeply nested structures can cause a panic due to stack exhaustion. This is a follow-up to CVE-2022-30635.",
          "Severity": "HIGH",
          "VendorSeverity": {
            "bitnami": 3,
            "redhat": 3
          },
          "CVSS": {
            "bitnami": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 7.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 7.5
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2024-34156",
            "https://go.dev/cl/611239",
            "https://go.dev/issue/69139",
            "https://groups.google.com/g/golang-dev/c/S9POB9NCTdk",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-34156",
            "https://pkg.go.dev/vuln/GO-2024-3106",
            "https://www.cve.org/CVERecord?id=CVE-2024-34156"
          ],
          "PublishedDate": "2024-09-06T21:15:12.02Z",
          "LastModifiedDate": "2024-09-09T15:35:07.573Z"
        },
        {
          "VulnerabilityID": "CVE-2023-29409",
          "PkgName": "stdlib",
          "PkgIdentifier": {
            "PURL": "pkg:golang/stdlib@1.20.6",
            "UID": "dc395f725e23d7d8"
          },
          "InstalledVersion": "1.20.6",
          "FixedVersion": "1.19.12, 1.20.7, 1.21.0-rc.4",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:1af0b9fc7854ee24c9d2c6a0bf240f0eda36f6d6745ceabead57db9d46154146",
            "DiffID": "sha256:b628230c51c7f48ef1625319af5a4dc0997450591fe9fb45b0fd7c9e743a69e5"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-29409",
          "DataSource": {
            "ID": "govulndb",
            "Name": "The Go Vulnerability Database",
            "URL": "https://pkg.go.dev/vuln/"
          },
          "Title": "golang: crypto/tls: slow verification of certificate chains containing large RSA keys",
          "Description": "Extremely large RSA keys in certificate chains can cause a client/server to expend significant CPU time verifying signatures. With fix, the size of RSA keys transmitted during handshakes is restricted to \u003c= 8192 bits. Based on a survey of publicly trusted RSA keys, there are currently only three certificates in circulation with keys larger than this, and all three appear to be test certificates that are not actively deployed. It is possible there are larger keys in use in private PKIs, but we target the web PKI, so causing breakage here in the interests of increasing the default safety of users of crypto/tls seems reasonable.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-400"
          ],
          "VendorSeverity": {
            "alma": 2,
            "amazon": 3,
            "azure": 2,
            "bitnami": 2,
            "cbl-mariner": 2,
            "nvd": 2,
            "oracle-oval": 2,
            "photon": 2,
            "redhat": 2
          },
          "CVSS": {
            "bitnami": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
              "V3Score": 5.3
            },
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
              "V3Score": 5.3
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
              "V3Score": 5.3
            }
          },
          "References": [
            "https://access.redhat.com/errata/RHSA-2023:7766",
            "https://access.redhat.com/security/cve/CVE-2023-29409",
            "https://bugzilla.redhat.com/2228743",
            "https://bugzilla.redhat.com/2237773",
            "https://bugzilla.redhat.com/2237776",
            "https://bugzilla.redhat.com/2237777",
            "https://bugzilla.redhat.com/2237778",
            "https://errata.almalinux.org/9/ALSA-2023-7766.html",
            "https://go.dev/cl/515257",
            "https://go.dev/issue/61460",
            "https://groups.google.com/g/golang-announce/c/X0b6CsSAaYI/m/Efv5DbZ9AwAJ",
            "https://linux.oracle.com/cve/CVE-2023-29409.html",
            "https://linux.oracle.com/errata/ELSA-2024-2988.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-29409",
            "https://pkg.go.dev/vuln/GO-2023-1987",
            "https://security.gentoo.org/glsa/202311-09",
            "https://security.netapp.com/advisory/ntap-20230831-0010/",
            "https://www.cve.org/CVERecord?id=CVE-2023-29409"
          ],
          "PublishedDate": "2023-08-02T20:15:11.94Z",
          "LastModifiedDate": "2023-11-25T11:15:14.87Z"
        },
        {
          "VulnerabilityID": "CVE-2023-39318",
          "PkgName": "stdlib",
          "PkgIdentifier": {
            "PURL": "pkg:golang/stdlib@1.20.6",
            "UID": "dc395f725e23d7d8"
          },
          "InstalledVersion": "1.20.6",
          "FixedVersion": "1.20.8, 1.21.1",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:1af0b9fc7854ee24c9d2c6a0bf240f0eda36f6d6745ceabead57db9d46154146",
            "DiffID": "sha256:b628230c51c7f48ef1625319af5a4dc0997450591fe9fb45b0fd7c9e743a69e5"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-39318",
          "DataSource": {
            "ID": "govulndb",
            "Name": "The Go Vulnerability Database",
            "URL": "https://pkg.go.dev/vuln/"
          },
          "Title": "golang: html/template: improper handling of HTML-like comments within script contexts",
          "Description": "The html/template package does not properly handle HTML-like \"\" comment tokens, nor hashbang \"#!\" comment tokens, in \u003cscript\u003e contexts. This may cause the template parser to improperly interpret the contents of \u003cscript\u003e contexts, causing actions to be improperly escaped. This may be leveraged to perform an XSS attack.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-79"
          ],
          "VendorSeverity": {
            "alma": 2,
            "amazon": 2,
            "azure": 2,
            "bitnami": 2,
            "cbl-mariner": 2,
            "nvd": 2,
            "oracle-oval": 2,
            "photon": 2,
            "redhat": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "bitnami": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
              "V3Score": 6.1
            },
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
              "V3Score": 6.1
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
              "V3Score": 6.1
            }
          },
          "References": [
            "https://access.redhat.com/errata/RHSA-2024:2160",
            "https://access.redhat.com/security/cve/CVE-2023-39318",
            "https://bugzilla.redhat.com/2237773",
            "https://bugzilla.redhat.com/2237776",
            "https://bugzilla.redhat.com/2253330",
            "https://errata.almalinux.org/9/ALSA-2024-2160.html",
            "https://github.com/golang/go/commit/023b542edf38e2a1f87fcefb9f75ff2f99401b4c (go1.20.8)",
            "https://github.com/golang/go/commit/b0e1d3ea26e8e8fce7726690c9ef0597e60739fb (go1.21.1)",
            "https://go.dev/cl/526156",
            "https://go.dev/issue/62196",
            "https://groups.google.com/g/golang-announce/c/Fm51GRLNRvM",
            "https://groups.google.com/g/golang-dev/c/2C5vbR-UNkI/m/L1hdrPhfBAAJ",
            "https://linux.oracle.com/cve/CVE-2023-39318.html",
            "https://linux.oracle.com/errata/ELSA-2024-2988.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-39318",
            "https://pkg.go.dev/vuln/GO-2023-2041",
            "https://security.gentoo.org/glsa/202311-09",
            "https://security.netapp.com/advisory/ntap-20231020-0009/",
            "https://ubuntu.com/security/notices/USN-6574-1",
            "https://vuln.go.dev/ID/GO-2023-2041.json",
            "https://www.cve.org/CVERecord?id=CVE-2023-39318"
          ],
          "PublishedDate": "2023-09-08T17:15:27.823Z",
          "LastModifiedDate": "2023-11-25T11:15:17.43Z"
        },
        {
          "VulnerabilityID": "CVE-2023-39319",
          "PkgName": "stdlib",
          "PkgIdentifier": {
            "PURL": "pkg:golang/stdlib@1.20.6",
            "UID": "dc395f725e23d7d8"
          },
          "InstalledVersion": "1.20.6",
          "FixedVersion": "1.20.8, 1.21.1",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:1af0b9fc7854ee24c9d2c6a0bf240f0eda36f6d6745ceabead57db9d46154146",
            "DiffID": "sha256:b628230c51c7f48ef1625319af5a4dc0997450591fe9fb45b0fd7c9e743a69e5"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-39319",
          "DataSource": {
            "ID": "govulndb",
            "Name": "The Go Vulnerability Database",
            "URL": "https://pkg.go.dev/vuln/"
          },
          "Title": "golang: html/template: improper handling of special tags within script contexts",
          "Description": "The html/template package does not apply the proper rules for handling occurrences of \"\u003cscript\", \"\u003c!--\", and \"\u003c/script\" within JS literals in \u003cscript\u003e contexts. This may cause the template parser to improperly consider script contexts to be terminated early, causing actions to be improperly escaped. This could be leveraged to perform an XSS attack.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-79"
          ],
          "VendorSeverity": {
            "alma": 2,
            "amazon": 2,
            "azure": 2,
            "bitnami": 2,
            "cbl-mariner": 2,
            "nvd": 2,
            "oracle-oval": 2,
            "photon": 2,
            "redhat": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "bitnami": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
              "V3Score": 6.1
            },
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
              "V3Score": 6.1
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
              "V3Score": 6.1
            }
          },
          "References": [
            "https://access.redhat.com/errata/RHSA-2024:2160",
            "https://access.redhat.com/security/cve/CVE-2023-39319",
            "https://bugzilla.redhat.com/2237773",
            "https://bugzilla.redhat.com/2237776",
            "https://bugzilla.redhat.com/2253330",
            "https://errata.almalinux.org/9/ALSA-2024-2160.html",
            "https://github.com/golang/go/commit/2070531d2f53df88e312edace6c8dfc9686ab2f5 (go1.20.8)",
            "https://github.com/golang/go/commit/bbd043ff0d6d59f1a9232d31ecd5eacf6507bf6a (go1.21.1)",
            "https://go.dev/cl/526157",
            "https://go.dev/issue/62197",
            "https://groups.google.com/g/golang-announce/c/Fm51GRLNRvM",
            "https://groups.google.com/g/golang-dev/c/2C5vbR-UNkI/m/L1hdrPhfBAAJ",
            "https://linux.oracle.com/cve/CVE-2023-39319.html",
            "https://linux.oracle.com/errata/ELSA-2024-2988.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-39319",
            "https://pkg.go.dev/vuln/GO-2023-2043",
            "https://security.gentoo.org/glsa/202311-09",
            "https://security.netapp.com/advisory/ntap-20231020-0009/",
            "https://ubuntu.com/security/notices/USN-6574-1",
            "https://vuln.go.dev/ID/GO-2023-2043.json",
            "https://www.cve.org/CVERecord?id=CVE-2023-39319"
          ],
          "PublishedDate": "2023-09-08T17:15:27.91Z",
          "LastModifiedDate": "2023-11-25T11:15:17.543Z"
        },
        {
          "VulnerabilityID": "CVE-2023-39326",
          "PkgName": "stdlib",
          "PkgIdentifier": {
            "PURL": "pkg:golang/stdlib@1.20.6",
            "UID": "dc395f725e23d7d8"
          },
          "InstalledVersion": "1.20.6",
          "FixedVersion": "1.20.12, 1.21.5",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:1af0b9fc7854ee24c9d2c6a0bf240f0eda36f6d6745ceabead57db9d46154146",
            "DiffID": "sha256:b628230c51c7f48ef1625319af5a4dc0997450591fe9fb45b0fd7c9e743a69e5"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-39326",
          "DataSource": {
            "ID": "govulndb",
            "Name": "The Go Vulnerability Database",
            "URL": "https://pkg.go.dev/vuln/"
          },
          "Title": "golang: net/http/internal: Denial of Service (DoS) via Resource Consumption via HTTP requests",
          "Description": "A malicious HTTP sender can use chunk extensions to cause a receiver reading from a request or response body to read many more bytes from the network than are in the body. A malicious HTTP client can further exploit this to cause a server to automatically read a large amount of data (up to about 1GiB) when a handler fails to read the entire body of a request. Chunk extensions are a little-used HTTP feature which permit including additional metadata in a request or response body sent using the chunked encoding. The net/http chunked encoding reader discards this metadata. A sender can exploit this by inserting a large metadata segment with each byte transferred. The chunk reader now produces an error if the ratio of real body to encoded bytes grows too small.",
          "Severity": "MEDIUM",
          "VendorSeverity": {
            "alma": 2,
            "amazon": 2,
            "bitnami": 2,
            "cbl-mariner": 2,
            "nvd": 2,
            "oracle-oval": 2,
            "photon": 2,
            "redhat": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "bitnami": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
              "V3Score": 5.3
            },
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
              "V3Score": 5.3
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
              "V3Score": 5.3
            }
          },
          "References": [
            "https://access.redhat.com/errata/RHSA-2024:2272",
            "https://access.redhat.com/security/cve/CVE-2023-39326",
            "https://bugzilla.redhat.com/2253193",
            "https://bugzilla.redhat.com/2253330",
            "https://errata.almalinux.org/9/ALSA-2024-2272.html",
            "https://github.com/golang/go/commit/6446af942e2e2b161c4ec1b60d9703a2b55dc4dd (go1.20.12)",
            "https://github.com/golang/go/commit/ec8c526e4be720e94b98ca509e6364f0efaf28f7 (go1.21.5)",
            "https://go.dev/cl/547335",
            "https://go.dev/issue/64433",
            "https://groups.google.com/g/golang-dev/c/6ypN5EjibjM/m/KmLVYH_uAgAJ",
            "https://linux.oracle.com/cve/CVE-2023-39326.html",
            "https://linux.oracle.com/errata/ELSA-2024-2988.html",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/UIU6HOGV6RRIKWM57LOXQA75BGZSIH6G/",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-39326",
            "https://pkg.go.dev/vuln/GO-2023-2382",
            "https://ubuntu.com/security/notices/USN-6574-1",
            "https://www.cve.org/CVERecord?id=CVE-2023-39326"
          ],
          "PublishedDate": "2023-12-06T17:15:07.147Z",
          "LastModifiedDate": "2024-01-20T04:15:07.89Z"
        },
        {
          "VulnerabilityID": "CVE-2023-45284",
          "PkgName": "stdlib",
          "PkgIdentifier": {
            "PURL": "pkg:golang/stdlib@1.20.6",
            "UID": "dc395f725e23d7d8"
          },
          "InstalledVersion": "1.20.6",
          "FixedVersion": "1.20.11, 1.21.4",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:1af0b9fc7854ee24c9d2c6a0bf240f0eda36f6d6745ceabead57db9d46154146",
            "DiffID": "sha256:b628230c51c7f48ef1625319af5a4dc0997450591fe9fb45b0fd7c9e743a69e5"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-45284",
          "DataSource": {
            "ID": "govulndb",
            "Name": "The Go Vulnerability Database",
            "URL": "https://pkg.go.dev/vuln/"
          },
          "Title": "On Windows, The IsLocal function does not correctly detect reserved de ...",
          "Description": "On Windows, The IsLocal function does not correctly detect reserved device names in some cases. Reserved names followed by spaces, such as \"COM1 \", and reserved names \"COM\" and \"LPT\" followed by superscript 1, 2, or 3, are incorrectly reported as local. With fix, IsLocal now correctly reports these names as non-local.",
          "Severity": "MEDIUM",
          "VendorSeverity": {
            "amazon": 2,
            "bitnami": 2,
            "cbl-mariner": 2,
            "nvd": 2,
            "photon": 2
          },
          "CVSS": {
            "bitnami": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
              "V3Score": 5.3
            },
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
              "V3Score": 5.3
            }
          },
          "References": [
            "https://go.dev/cl/540277",
            "https://go.dev/issue/63713",
            "https://groups.google.com/g/golang-announce/c/4tU8LZfBFkY",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-45284",
            "https://pkg.go.dev/vuln/GO-2023-2186"
          ],
          "PublishedDate": "2023-11-09T17:15:08.813Z",
          "LastModifiedDate": "2024-09-03T19:35:05.593Z"
        },
        {
          "VulnerabilityID": "CVE-2023-45289",
          "PkgName": "stdlib",
          "PkgIdentifier": {
            "PURL": "pkg:golang/stdlib@1.20.6",
            "UID": "dc395f725e23d7d8"
          },
          "InstalledVersion": "1.20.6",
          "FixedVersion": "1.21.8, 1.22.1",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:1af0b9fc7854ee24c9d2c6a0bf240f0eda36f6d6745ceabead57db9d46154146",
            "DiffID": "sha256:b628230c51c7f48ef1625319af5a4dc0997450591fe9fb45b0fd7c9e743a69e5"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-45289",
          "DataSource": {
            "ID": "govulndb",
            "Name": "The Go Vulnerability Database",
            "URL": "https://pkg.go.dev/vuln/"
          },
          "Title": "golang: net/http/cookiejar: incorrect forwarding of sensitive headers and cookies on HTTP redirect",
          "Description": "When following an HTTP redirect to a domain which is not a subdomain match or exact match of the initial domain, an http.Client does not forward sensitive headers such as \"Authorization\" or \"Cookie\". For example, a redirect from foo.com to www.foo.com will forward the Authorization header, but a redirect to bar.com will not. A maliciously crafted HTTP redirect could cause sensitive headers to be unexpectedly forwarded.",
          "Severity": "MEDIUM",
          "VendorSeverity": {
            "alma": 3,
            "amazon": 2,
            "cbl-mariner": 2,
            "oracle-oval": 3,
            "redhat": 2,
            "rocky": 3,
            "ubuntu": 2
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
              "V3Score": 5.3
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2024/03/08/4",
            "https://access.redhat.com/errata/RHSA-2024:2724",
            "https://access.redhat.com/security/cve/CVE-2023-45289",
            "https://bugzilla.redhat.com/2268017",
            "https://bugzilla.redhat.com/2268018",
            "https://bugzilla.redhat.com/2268019",
            "https://bugzilla.redhat.com/2268273",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2268017",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2268018",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2268019",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2268273",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-45288",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-45289",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-45290",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-24783",
            "https://errata.almalinux.org/9/ALSA-2024-2724.html",
            "https://errata.rockylinux.org/RLSA-2024:2724",
            "https://github.com/golang/go/commit/20586c0dbe03d144f914155f879fa5ee287591a1 (go1.21.8)",
            "https://github.com/golang/go/commit/3a855208e3efed2e9d7c20ad023f1fa78afcc0be (go1.22.1)",
            "https://github.com/golang/go/issues/65065",
            "https://go.dev/cl/569340",
            "https://go.dev/issue/65065",
            "https://groups.google.com/g/golang-announce/c/5pwGVUPoMbg",
            "https://linux.oracle.com/cve/CVE-2023-45289.html",
            "https://linux.oracle.com/errata/ELSA-2024-3346.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-45289",
            "https://pkg.go.dev/vuln/GO-2024-2600",
            "https://security.netapp.com/advisory/ntap-20240329-0006/",
            "https://ubuntu.com/security/notices/USN-6886-1",
            "https://www.cve.org/CVERecord?id=CVE-2023-45289"
          ],
          "PublishedDate": "2024-03-05T23:15:07.137Z",
          "LastModifiedDate": "2024-05-01T17:15:25.983Z"
        },
        {
          "VulnerabilityID": "CVE-2023-45290",
          "PkgName": "stdlib",
          "PkgIdentifier": {
            "PURL": "pkg:golang/stdlib@1.20.6",
            "UID": "dc395f725e23d7d8"
          },
          "InstalledVersion": "1.20.6",
          "FixedVersion": "1.21.8, 1.22.1",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:1af0b9fc7854ee24c9d2c6a0bf240f0eda36f6d6745ceabead57db9d46154146",
            "DiffID": "sha256:b628230c51c7f48ef1625319af5a4dc0997450591fe9fb45b0fd7c9e743a69e5"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-45290",
          "DataSource": {
            "ID": "govulndb",
            "Name": "The Go Vulnerability Database",
            "URL": "https://pkg.go.dev/vuln/"
          },
          "Title": "golang: net/http: memory exhaustion in Request.ParseMultipartForm",
          "Description": "When parsing a multipart form (either explicitly with Request.ParseMultipartForm or implicitly with Request.FormValue, Request.PostFormValue, or Request.FormFile), limits on the total size of the parsed form were not applied to the memory consumed while reading a single form line. This permits a maliciously crafted input containing very long lines to cause allocation of arbitrarily large amounts of memory, potentially leading to memory exhaustion. With fix, the ParseMultipartForm function now correctly limits the maximum size of form lines.",
          "Severity": "MEDIUM",
          "VendorSeverity": {
            "alma": 2,
            "amazon": 2,
            "cbl-mariner": 2,
            "oracle-oval": 3,
            "redhat": 2,
            "rocky": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
              "V3Score": 5.3
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2024/03/08/4",
            "https://access.redhat.com/errata/RHSA-2024:3831",
            "https://access.redhat.com/security/cve/CVE-2023-45290",
            "https://bugzilla.redhat.com/2268017",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2268017",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-45290",
            "https://errata.almalinux.org/9/ALSA-2024-3831.html",
            "https://errata.rockylinux.org/RLSA-2024:3830",
            "https://github.com/golang/go/commit/041a47712e765e94f86d841c3110c840e76d8f82 (go1.22.1)",
            "https://github.com/golang/go/commit/bf80213b121074f4ad9b449410a4d13bae5e9be0 (go1.21.8)",
            "https://github.com/golang/go/issues/65383",
            "https://go.dev/cl/569341",
            "https://go.dev/issue/65383",
            "https://groups.google.com/g/golang-announce/c/5pwGVUPoMbg",
            "https://linux.oracle.com/cve/CVE-2023-45290.html",
            "https://linux.oracle.com/errata/ELSA-2024-5258.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-45290",
            "https://pkg.go.dev/vuln/GO-2024-2599",
            "https://security.netapp.com/advisory/ntap-20240329-0004",
            "https://security.netapp.com/advisory/ntap-20240329-0004/",
            "https://ubuntu.com/security/notices/USN-6886-1",
            "https://www.cve.org/CVERecord?id=CVE-2023-45290"
          ],
          "PublishedDate": "2024-03-05T23:15:07.21Z",
          "LastModifiedDate": "2024-05-01T17:15:26.04Z"
        },
        {
          "VulnerabilityID": "CVE-2024-24783",
          "PkgName": "stdlib",
          "PkgIdentifier": {
            "PURL": "pkg:golang/stdlib@1.20.6",
            "UID": "dc395f725e23d7d8"
          },
          "InstalledVersion": "1.20.6",
          "FixedVersion": "1.21.8, 1.22.1",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:1af0b9fc7854ee24c9d2c6a0bf240f0eda36f6d6745ceabead57db9d46154146",
            "DiffID": "sha256:b628230c51c7f48ef1625319af5a4dc0997450591fe9fb45b0fd7c9e743a69e5"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-24783",
          "DataSource": {
            "ID": "govulndb",
            "Name": "The Go Vulnerability Database",
            "URL": "https://pkg.go.dev/vuln/"
          },
          "Title": "golang: crypto/x509: Verify panics on certificates with an unknown public key algorithm",
          "Description": "Verifying a certificate chain which contains a certificate with an unknown public key algorithm will cause Certificate.Verify to panic. This affects all crypto/tls clients, and servers that set Config.ClientAuth to VerifyClientCertIfGiven or RequireAndVerifyClientCert. The default behavior is for TLS servers to not verify client certificates.",
          "Severity": "MEDIUM",
          "VendorSeverity": {
            "alma": 2,
            "amazon": 2,
            "cbl-mariner": 2,
            "oracle-oval": 2,
            "redhat": 2,
            "rocky": 3,
            "ubuntu": 2
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N",
              "V3Score": 5.9
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2024/03/08/4",
            "https://access.redhat.com/errata/RHSA-2024:6195",
            "https://access.redhat.com/security/cve/CVE-2024-24783",
            "https://bugzilla.redhat.com/2268019",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2268017",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2268018",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2268019",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2268273",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-45288",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-45289",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-45290",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-24783",
            "https://errata.almalinux.org/9/ALSA-2024-6195.html",
            "https://errata.rockylinux.org/RLSA-2024:2724",
            "https://github.com/advisories/GHSA-3q2c-pvp5-3cqp",
            "https://github.com/golang/go/commit/337b8e9cbfa749d9d5c899e0dc358e2208d5e54f (go1.22.1)",
            "https://github.com/golang/go/commit/be5b52bea674190ef7de272664be6c7ae93ec5a0 (go1.21.8)",
            "https://github.com/golang/go/issues/65390",
            "https://go.dev/cl/569339",
            "https://go.dev/issue/65390",
            "https://groups.google.com/g/golang-announce/c/5pwGVUPoMbg",
            "https://linux.oracle.com/cve/CVE-2024-24783.html",
            "https://linux.oracle.com/errata/ELSA-2024-6195.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-24783",
            "https://pkg.go.dev/vuln/GO-2024-2598",
            "https://security.netapp.com/advisory/ntap-20240329-0005",
            "https://security.netapp.com/advisory/ntap-20240329-0005/",
            "https://ubuntu.com/security/notices/USN-6886-1",
            "https://www.cve.org/CVERecord?id=CVE-2024-24783"
          ],
          "PublishedDate": "2024-03-05T23:15:07.683Z",
          "LastModifiedDate": "2024-05-01T17:15:29.45Z"
        },
        {
          "VulnerabilityID": "CVE-2024-24784",
          "PkgName": "stdlib",
          "PkgIdentifier": {
            "PURL": "pkg:golang/stdlib@1.20.6",
            "UID": "dc395f725e23d7d8"
          },
          "InstalledVersion": "1.20.6",
          "FixedVersion": "1.21.8, 1.22.1",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:1af0b9fc7854ee24c9d2c6a0bf240f0eda36f6d6745ceabead57db9d46154146",
            "DiffID": "sha256:b628230c51c7f48ef1625319af5a4dc0997450591fe9fb45b0fd7c9e743a69e5"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-24784",
          "DataSource": {
            "ID": "govulndb",
            "Name": "The Go Vulnerability Database",
            "URL": "https://pkg.go.dev/vuln/"
          },
          "Title": "golang: net/mail: comments in display names are incorrectly handled",
          "Description": "The ParseAddressList function incorrectly handles comments (text within parentheses) within display names. Since this is a misalignment with conforming address parsers, it can result in different trust decisions being made by programs using different parsers.",
          "Severity": "MEDIUM",
          "VendorSeverity": {
            "alma": 3,
            "amazon": 2,
            "bitnami": 3,
            "cbl-mariner": 3,
            "oracle-oval": 3,
            "photon": 3,
            "redhat": 2,
            "rocky": 3,
            "ubuntu": 2
          },
          "CVSS": {
            "bitnami": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
              "V3Score": 7.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
              "V3Score": 5.4
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2024/03/08/4",
            "https://access.redhat.com/errata/RHSA-2024:2562",
            "https://access.redhat.com/security/cve/CVE-2024-24784",
            "https://bugzilla.redhat.com/2262921",
            "https://bugzilla.redhat.com/2268017",
            "https://bugzilla.redhat.com/2268018",
            "https://bugzilla.redhat.com/2268019",
            "https://bugzilla.redhat.com/2268021",
            "https://bugzilla.redhat.com/2268022",
            "https://bugzilla.redhat.com/2268273",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2262921",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2268017",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2268018",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2268019",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2268021",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2268022",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2268273",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-45288",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-45289",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-45290",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-1394",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-24783",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-24784",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-24785",
            "https://errata.almalinux.org/9/ALSA-2024-2562.html",
            "https://errata.rockylinux.org/RLSA-2024:2562",
            "https://github.com/golang/go/commit/263c059b09fdd40d9dd945f2ecb20c89ea28efe5 (go1.21.8)",
            "https://github.com/golang/go/commit/5330cd225ba54c7dc78c1b46dcdf61a4671a632c (go1.22.1)",
            "https://github.com/golang/go/issues/65083",
            "https://go.dev/cl/555596",
            "https://go.dev/issue/65083",
            "https://groups.google.com/g/golang-announce/c/5pwGVUPoMbg",
            "https://linux.oracle.com/cve/CVE-2024-24784.html",
            "https://linux.oracle.com/errata/ELSA-2024-5258.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-24784",
            "https://pkg.go.dev/vuln/GO-2024-2609",
            "https://security.netapp.com/advisory/ntap-20240329-0007/",
            "https://ubuntu.com/security/notices/USN-6886-1",
            "https://www.cve.org/CVERecord?id=CVE-2024-24784"
          ],
          "PublishedDate": "2024-03-05T23:15:07.733Z",
          "LastModifiedDate": "2024-08-05T21:35:04.457Z"
        },
        {
          "VulnerabilityID": "CVE-2024-24785",
          "PkgName": "stdlib",
          "PkgIdentifier": {
            "PURL": "pkg:golang/stdlib@1.20.6",
            "UID": "dc395f725e23d7d8"
          },
          "InstalledVersion": "1.20.6",
          "FixedVersion": "1.21.8, 1.22.1",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:1af0b9fc7854ee24c9d2c6a0bf240f0eda36f6d6745ceabead57db9d46154146",
            "DiffID": "sha256:b628230c51c7f48ef1625319af5a4dc0997450591fe9fb45b0fd7c9e743a69e5"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-24785",
          "DataSource": {
            "ID": "govulndb",
            "Name": "The Go Vulnerability Database",
            "URL": "https://pkg.go.dev/vuln/"
          },
          "Title": "golang: html/template: errors returned from MarshalJSON methods may break template escaping",
          "Description": "If errors returned from MarshalJSON methods contain user controlled data, they may be used to break the contextual auto-escaping behavior of the html/template package, allowing for subsequent actions to inject unexpected content into templates.",
          "Severity": "MEDIUM",
          "VendorSeverity": {
            "alma": 3,
            "amazon": 2,
            "cbl-mariner": 2,
            "oracle-oval": 3,
            "redhat": 2,
            "rocky": 3,
            "ubuntu": 2
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
              "V3Score": 6.5
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2024/03/08/4",
            "https://access.redhat.com/errata/RHSA-2024:2562",
            "https://access.redhat.com/security/cve/CVE-2024-24785",
            "https://bugzilla.redhat.com/2262921",
            "https://bugzilla.redhat.com/2268017",
            "https://bugzilla.redhat.com/2268018",
            "https://bugzilla.redhat.com/2268019",
            "https://bugzilla.redhat.com/2268021",
            "https://bugzilla.redhat.com/2268022",
            "https://bugzilla.redhat.com/2268273",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2262921",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2268017",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2268018",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2268019",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2268021",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2268022",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2268273",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-45288",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-45289",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-45290",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-1394",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-24783",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-24784",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-24785",
            "https://errata.almalinux.org/9/ALSA-2024-2562.html",
            "https://errata.rockylinux.org/RLSA-2024:2562",
            "https://github.com/golang/go/commit/056b0edcb8c152152021eebf4cf42adbfbe77992 (go1.22.1)",
            "https://github.com/golang/go/commit/3643147a29352ca2894fd5d0d2069bc4b4335a7e (go1.21.8)",
            "https://github.com/golang/go/issues/65697",
            "https://go.dev/cl/564196",
            "https://go.dev/issue/65697",
            "https://groups.google.com/g/golang-announce/c/5pwGVUPoMbg",
            "https://linux.oracle.com/cve/CVE-2024-24785.html",
            "https://linux.oracle.com/errata/ELSA-2024-3259.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-24785",
            "https://pkg.go.dev/vuln/GO-2024-2610",
            "https://security.netapp.com/advisory/ntap-20240329-0008/",
            "https://ubuntu.com/security/notices/USN-6886-1",
            "https://vuln.go.dev/ID/GO-2024-2610.json",
            "https://www.cve.org/CVERecord?id=CVE-2024-24785"
          ],
          "PublishedDate": "2024-03-05T23:15:07.777Z",
          "LastModifiedDate": "2024-05-01T17:15:29.61Z"
        },
        {
          "VulnerabilityID": "CVE-2024-24789",
          "PkgName": "stdlib",
          "PkgIdentifier": {
            "PURL": "pkg:golang/stdlib@1.20.6",
            "UID": "dc395f725e23d7d8"
          },
          "InstalledVersion": "1.20.6",
          "FixedVersion": "1.21.11, 1.22.4",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:1af0b9fc7854ee24c9d2c6a0bf240f0eda36f6d6745ceabead57db9d46154146",
            "DiffID": "sha256:b628230c51c7f48ef1625319af5a4dc0997450591fe9fb45b0fd7c9e743a69e5"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-24789",
          "DataSource": {
            "ID": "govulndb",
            "Name": "The Go Vulnerability Database",
            "URL": "https://pkg.go.dev/vuln/"
          },
          "Title": "golang: archive/zip: Incorrect handling of certain ZIP files",
          "Description": "The archive/zip package's handling of certain types of invalid zip files differs from the behavior of most zip implementations. This misalignment could be exploited to create an zip file with contents that vary depending on the implementation reading the file. The archive/zip package now rejects files containing these errors.",
          "Severity": "MEDIUM",
          "VendorSeverity": {
            "alma": 2,
            "amazon": 2,
            "azure": 2,
            "bitnami": 2,
            "cbl-mariner": 2,
            "nvd": 2,
            "oracle-oval": 2,
            "photon": 2,
            "redhat": 2,
            "rocky": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "bitnami": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",
              "V3Score": 5.5
            },
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",
              "V3Score": 5.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
              "V3Score": 7.5
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2024/06/04/1",
            "https://access.redhat.com/errata/RHSA-2024:4212",
            "https://access.redhat.com/security/cve/CVE-2024-24789",
            "https://bugzilla.redhat.com/2292668",
            "https://bugzilla.redhat.com/2292787",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2292668",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2292787",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-24789",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-24790",
            "https://errata.almalinux.org/9/ALSA-2024-4212.html",
            "https://errata.rockylinux.org/RLSA-2024:4212",
            "https://github.com/golang/go/commit/c8e40338cf00f3c1d86c8fb23863ad67a4c72bcc (1.21)",
            "https://github.com/golang/go/commit/cf501ac0c5fe351a8582d20b43562027927906e7 (1.22)",
            "https://github.com/golang/go/issues/66869",
            "https://go.dev/cl/585397",
            "https://go.dev/issue/66869",
            "https://groups.google.com/g/golang-announce/c/XbxouI9gY7k",
            "https://groups.google.com/g/golang-announce/c/XbxouI9gY7k/m/TuoGEhxIEwAJ",
            "https://linux.oracle.com/cve/CVE-2024-24789.html",
            "https://linux.oracle.com/errata/ELSA-2024-5291.html",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/U5YAEIA6IUHUNGJ7AIXXPQT6D2GYENX7/",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-24789",
            "https://pkg.go.dev/vuln/GO-2024-2888",
            "https://ubuntu.com/security/notices/USN-6886-1",
            "https://www.cve.org/CVERecord?id=CVE-2024-24789"
          ],
          "PublishedDate": "2024-06-05T16:15:10.47Z",
          "LastModifiedDate": "2024-07-03T01:48:25.51Z"
        },
        {
          "VulnerabilityID": "CVE-2024-24791",
          "PkgName": "stdlib",
          "PkgIdentifier": {
            "PURL": "pkg:golang/stdlib@1.20.6",
            "UID": "dc395f725e23d7d8"
          },
          "InstalledVersion": "1.20.6",
          "FixedVersion": "1.21.12, 1.22.5",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:1af0b9fc7854ee24c9d2c6a0bf240f0eda36f6d6745ceabead57db9d46154146",
            "DiffID": "sha256:b628230c51c7f48ef1625319af5a4dc0997450591fe9fb45b0fd7c9e743a69e5"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-24791",
          "DataSource": {
            "ID": "govulndb",
            "Name": "The Go Vulnerability Database",
            "URL": "https://pkg.go.dev/vuln/"
          },
          "Title": "net/http: Denial of service due to improper 100-continue handling in net/http",
          "Description": "The net/http HTTP/1.1 client mishandled the case where a server responds to a request with an \"Expect: 100-continue\" header with a non-informational (200 or higher) status. This mishandling could leave a client connection in an invalid state, where the next request sent on the connection will fail. An attacker sending a request to a net/http/httputil.ReverseProxy proxy can exploit this mishandling to cause a denial of service by sending \"Expect: 100-continue\" requests which elicit a non-informational response from the backend. Each such request leaves the proxy with an invalid connection, and causes one subsequent request using that connection to fail.",
          "Severity": "MEDIUM",
          "VendorSeverity": {
            "amazon": 2,
            "azure": 3,
            "bitnami": 3,
            "photon": 3,
            "redhat": 2
          },
          "CVSS": {
            "bitnami": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 7.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 5.9
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2024-24791",
            "https://go.dev/cl/591255",
            "https://go.dev/issue/67555",
            "https://groups.google.com/g/golang-dev/c/t0rK-qHBqzY/m/6MMoAZkMAgAJ",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-24791",
            "https://pkg.go.dev/vuln/GO-2024-2963",
            "https://www.cve.org/CVERecord?id=CVE-2024-24791"
          ],
          "PublishedDate": "2024-07-02T22:15:04.833Z",
          "LastModifiedDate": "2024-07-08T14:17:39.083Z"
        },
        {
          "VulnerabilityID": "CVE-2024-34155",
          "PkgName": "stdlib",
          "PkgIdentifier": {
            "PURL": "pkg:golang/stdlib@1.20.6",
            "UID": "dc395f725e23d7d8"
          },
          "InstalledVersion": "1.20.6",
          "FixedVersion": "1.22.7, 1.23.1",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:1af0b9fc7854ee24c9d2c6a0bf240f0eda36f6d6745ceabead57db9d46154146",
            "DiffID": "sha256:b628230c51c7f48ef1625319af5a4dc0997450591fe9fb45b0fd7c9e743a69e5"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-34155",
          "DataSource": {
            "ID": "govulndb",
            "Name": "The Go Vulnerability Database",
            "URL": "https://pkg.go.dev/vuln/"
          },
          "Title": "go/parser: golang: Calling any of the Parse functions containing deeply nested literals can cause a panic/stack exhaustion",
          "Description": "Calling any of the Parse functions on Go source code which contains deeply nested literals can cause a panic due to stack exhaustion.",
          "Severity": "MEDIUM",
          "VendorSeverity": {
            "redhat": 2
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 5.9
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2024-34155",
            "https://go.dev/cl/611238",
            "https://go.dev/issue/69138",
            "https://groups.google.com/g/golang-dev/c/S9POB9NCTdk",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-34155",
            "https://pkg.go.dev/vuln/GO-2024-3105",
            "https://www.cve.org/CVERecord?id=CVE-2024-34155"
          ],
          "PublishedDate": "2024-09-06T21:15:11.947Z",
          "LastModifiedDate": "2024-09-09T13:03:38.303Z"
        },
        {
          "VulnerabilityID": "CVE-2024-34158",
          "PkgName": "stdlib",
          "PkgIdentifier": {
            "PURL": "pkg:golang/stdlib@1.20.6",
            "UID": "dc395f725e23d7d8"
          },
          "InstalledVersion": "1.20.6",
          "FixedVersion": "1.22.7, 1.23.1",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:1af0b9fc7854ee24c9d2c6a0bf240f0eda36f6d6745ceabead57db9d46154146",
            "DiffID": "sha256:b628230c51c7f48ef1625319af5a4dc0997450591fe9fb45b0fd7c9e743a69e5"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-34158",
          "DataSource": {
            "ID": "govulndb",
            "Name": "The Go Vulnerability Database",
            "URL": "https://pkg.go.dev/vuln/"
          },
          "Title": "go/build/constraint: golang: Calling Parse on a \"// +build\" build tag line with deeply nested expressions can cause a panic due to stack exhaustion",
          "Description": "Calling Parse on a \"// +build\" build tag line with deeply nested expressions can cause a panic due to stack exhaustion.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-674"
          ],
          "VendorSeverity": {
            "bitnami": 3,
            "redhat": 2
          },
          "CVSS": {
            "bitnami": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 7.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 5.9
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2024-34158",
            "https://go.dev/cl/611240",
            "https://go.dev/issue/69141",
            "https://groups.google.com/g/golang-dev/c/S9POB9NCTdk",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-34158",
            "https://pkg.go.dev/vuln/GO-2024-3107",
            "https://www.cve.org/CVERecord?id=CVE-2024-34158"
          ],
          "PublishedDate": "2024-09-06T21:15:12.083Z",
          "LastModifiedDate": "2024-09-09T14:35:01.17Z"
        }
      ]
    }
  ]
}
