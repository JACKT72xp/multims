2024-09-15T12:10:36+02:00	INFO	[vuln] Vulnerability scanning is enabled
2024-09-15T12:10:36+02:00	INFO	[secret] Secret scanning is enabled
2024-09-15T12:10:36+02:00	INFO	[secret] If your scanning is slow, please try '--scanners vuln' to disable secret scanning
2024-09-15T12:10:36+02:00	INFO	[secret] Please see also https://aquasecurity.github.io/trivy/v0.55/docs/scanner/secret#recommendation for faster secret detection
2024-09-15T12:10:36+02:00	INFO	Detected OS	family="alpine" version="3.18.8"
2024-09-15T12:10:36+02:00	INFO	[alpine] Detecting vulnerabilities...	os_version="3.18" repository="3.18" pkg_num=56
2024-09-15T12:10:36+02:00	INFO	Number of language-specific files	num=1
2024-09-15T12:10:36+02:00	INFO	[gobinary] Detecting vulnerabilities...
2024-09-15T12:10:36+02:00	WARN	Using severities from other vendors for some vulnerabilities. Read https://aquasecurity.github.io/trivy/v0.55/docs/scanner/vulnerability#severity-selection for details.
{
  "SchemaVersion": 2,
  "CreatedAt": "2024-09-15T12:10:36.202583+02:00",
  "ArtifactName": "jackt72xp/multims:initv14",
  "ArtifactType": "container_image",
  "Metadata": {
    "OS": {
      "Family": "alpine",
      "Name": "3.18.8"
    },
    "ImageID": "sha256:2db2ceffdb3f8331038ebea85a4579e2dedb9da2a90c7c31bdd42388e97459a5",
    "DiffIDs": [
      "sha256:ce7f800efff9a5cfddf4805e3887943b4a7bd97cf83140587336261130ece03b",
      "sha256:d33f2258ad03b38b1d5e0efa2162da1a50241a9053df12483bd9c4a740b031ab",
      "sha256:f7f24e1ff9a307f673cfbe0f50d95657b6afeb6f16a462ea7e7342c9a6383279",
      "sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef",
      "sha256:432bdfaa17d818020d31edce692d8015cfe29e7e233015ee8217d808a24cb864",
      "sha256:23346767531ca7d8ee4ef3b7542a96fc338810fe4491871c93644d945772e5dc",
      "sha256:5e0be951a48fa9fa35299f97e4050a5d72f42999e0899339d520491592ff6b06"
    ],
    "RepoTags": [
      "jackt72xp/multims:initv14"
    ],
    "RepoDigests": [
      "jackt72xp/multims@sha256:2db2ceffdb3f8331038ebea85a4579e2dedb9da2a90c7c31bdd42388e97459a5"
    ],
    "ImageConfig": {
      "architecture": "amd64",
      "created": "2024-08-12T12:46:39.062438834Z",
      "docker_version": "26.1.1",
      "history": [
        {
          "created": "2024-07-22T22:26:55Z",
          "created_by": "/bin/sh -c #(nop) ADD file:5851aef23205a072ef361dd412a73a39a1ada75e19a207a392bb7ec9b8556e11 in / "
        },
        {
          "created": "2024-07-22T22:26:55Z",
          "created_by": "/bin/sh -c #(nop)  CMD [\"/bin/sh\"]",
          "empty_layer": true
        },
        {
          "created": "2024-08-11T19:32:57Z",
          "created_by": "ENV DEBIAN_FRONTEND=noninteractive",
          "comment": "buildkit.dockerfile.v0",
          "empty_layer": true
        },
        {
          "created": "2024-08-11T19:32:57Z",
          "created_by": "RUN /bin/sh -c apk add --no-cache     bash     curl     netcat-openbsd     inotify-tools     strace     gdb     vim     tcpdump     \u0026\u0026 rm -rf /var/cache/apk/* # buildkit",
          "comment": "buildkit.dockerfile.v0"
        },
        {
          "created": "2024-08-12T12:46:38Z",
          "created_by": "COPY msync /usr/local/bin/msync # buildkit",
          "comment": "buildkit.dockerfile.v0"
        },
        {
          "created": "2024-08-12T12:46:39Z",
          "created_by": "RUN /bin/sh -c chmod +x /usr/local/bin/msync # buildkit",
          "comment": "buildkit.dockerfile.v0"
        },
        {
          "created": "2024-08-12T12:46:39Z",
          "created_by": "COPY server.crt /etc/msync/server.crt # buildkit",
          "comment": "buildkit.dockerfile.v0"
        },
        {
          "created": "2024-08-12T12:46:39Z",
          "created_by": "COPY server.key /etc/msync/server.key # buildkit",
          "comment": "buildkit.dockerfile.v0"
        },
        {
          "created": "2024-08-12T12:46:39Z",
          "created_by": "WORKDIR /mnt/data",
          "comment": "buildkit.dockerfile.v0"
        },
        {
          "created": "2024-08-12T12:46:39Z",
          "created_by": "ENTRYPOINT [\"msync\"]",
          "comment": "buildkit.dockerfile.v0",
          "empty_layer": true
        },
        {
          "created": "2024-08-12T12:46:39Z",
          "created_by": "CMD [\"-mode=server\" \"-port=6060\" \"-directory=/mnt/data\" \"-certFile=/etc/msync/server.crt\" \"-keyFile=/etc/msync/server.key\"]",
          "comment": "buildkit.dockerfile.v0",
          "empty_layer": true
        }
      ],
      "os": "linux",
      "rootfs": {
        "type": "layers",
        "diff_ids": [
          "sha256:ce7f800efff9a5cfddf4805e3887943b4a7bd97cf83140587336261130ece03b",
          "sha256:d33f2258ad03b38b1d5e0efa2162da1a50241a9053df12483bd9c4a740b031ab",
          "sha256:f7f24e1ff9a307f673cfbe0f50d95657b6afeb6f16a462ea7e7342c9a6383279",
          "sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef",
          "sha256:432bdfaa17d818020d31edce692d8015cfe29e7e233015ee8217d808a24cb864",
          "sha256:23346767531ca7d8ee4ef3b7542a96fc338810fe4491871c93644d945772e5dc",
          "sha256:5e0be951a48fa9fa35299f97e4050a5d72f42999e0899339d520491592ff6b06"
        ]
      },
      "config": {
        "Cmd": [
          "-mode=server",
          "-port=6060",
          "-directory=/mnt/data",
          "-certFile=/etc/msync/server.crt",
          "-keyFile=/etc/msync/server.key"
        ],
        "Entrypoint": [
          "msync"
        ],
        "Env": [
          "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
          "DEBIAN_FRONTEND=noninteractive"
        ],
        "WorkingDir": "/mnt/data",
        "ArgsEscaped": true
      }
    }
  },
  "Results": [
    {
      "Target": "jackt72xp/multims:initv14 (alpine 3.18.8)",
      "Class": "os-pkgs",
      "Type": "alpine",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2024-6119",
          "PkgID": "libcrypto3@3.1.6-r0",
          "PkgName": "libcrypto3",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/libcrypto3@3.1.6-r0?arch=x86_64\u0026distro=3.18.8",
            "UID": "3d845bd57a31fbf"
          },
          "InstalledVersion": "3.1.6-r0",
          "FixedVersion": "3.1.7-r0",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:930bdd4d222e2e63c22bd9e88d29b3c5ddd3d8a9d8fb93cf8324f4e7b9577cfb",
            "DiffID": "sha256:ce7f800efff9a5cfddf4805e3887943b4a7bd97cf83140587336261130ece03b"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-6119",
          "DataSource": {
            "ID": "alpine",
            "Name": "Alpine Secdb",
            "URL": "https://secdb.alpinelinux.org/"
          },
          "Title": "openssl: Possible denial of service in X.509 name checks",
          "Description": "Issue summary: Applications performing certificate name checks (e.g., TLS\nclients checking server certificates) may attempt to read an invalid memory\naddress resulting in abnormal termination of the application process.\n\nImpact summary: Abnormal termination of an application can a cause a denial of\nservice.\n\nApplications performing certificate name checks (e.g., TLS clients checking\nserver certificates) may attempt to read an invalid memory address when\ncomparing the expected name with an `otherName` subject alternative name of an\nX.509 certificate. This may result in an exception that terminates the\napplication program.\n\nNote that basic certificate chain validation (signatures, dates, ...) is not\naffected, the denial of service can occur only when the application also\nspecifies an expected DNS name, Email address or IP address.\n\nTLS servers rarely solicit client certificates, and even when they do, they\ngenerally don't perform a name check against a reference identifier (expected\nidentity), but rather extract the presented identity after checking the\ncertificate chain.  So TLS servers are generally not affected and the severity\nof the issue is Moderate.\n\nThe FIPS modules in 3.3, 3.2, 3.1 and 3.0 are not affected by this issue.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-843"
          ],
          "VendorSeverity": {
            "photon": 3,
            "redhat": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 5.9
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2024-6119",
            "https://github.com/openssl/openssl/commit/05f360d9e849a1b277db628f1f13083a7f8dd04f",
            "https://github.com/openssl/openssl/commit/06d1dc3fa96a2ba5a3e22735a033012aadc9f0d6",
            "https://github.com/openssl/openssl/commit/621f3729831b05ee828a3203eddb621d014ff2b2",
            "https://github.com/openssl/openssl/commit/7dfcee2cd2a63b2c64b9b4b0850be64cb695b0a0",
            "https://github.com/openssl/openssl/security/advisories/GHSA-5qrj-vq78-58fj",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-6119",
            "https://openssl-library.org/news/secadv/20240903.txt",
            "https://ubuntu.com/security/notices/USN-6986-1",
            "https://www.cve.org/CVERecord?id=CVE-2024-6119"
          ],
          "PublishedDate": "2024-09-03T16:15:07.177Z",
          "LastModifiedDate": "2024-09-03T21:35:12.987Z"
        },
        {
          "VulnerabilityID": "CVE-2024-45490",
          "PkgID": "libexpat@2.6.2-r0",
          "PkgName": "libexpat",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/libexpat@2.6.2-r0?arch=x86_64\u0026distro=3.18.8",
            "UID": "18c0e8db946d840"
          },
          "InstalledVersion": "2.6.2-r0",
          "FixedVersion": "2.6.3-r0",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:e0438933db2c4dfc2590d009d4743559e822f88bcea754476741e383ec4ce873",
            "DiffID": "sha256:d33f2258ad03b38b1d5e0efa2162da1a50241a9053df12483bd9c4a740b031ab"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-45490",
          "DataSource": {
            "ID": "alpine",
            "Name": "Alpine Secdb",
            "URL": "https://secdb.alpinelinux.org/"
          },
          "Title": "libexpat: Negative Length Parsing Vulnerability in libexpat",
          "Description": "An issue was discovered in libexpat before 2.6.3. xmlparse.c does not reject a negative length for XML_ParseBuffer.",
          "Severity": "CRITICAL",
          "CweIDs": [
            "CWE-611"
          ],
          "VendorSeverity": {
            "cbl-mariner": 4,
            "nvd": 4,
            "photon": 4,
            "redhat": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
              "V3Score": 9.8
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L",
              "V3Score": 5.1
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2024-45490",
            "https://github.com/libexpat/libexpat/blob/R_2_6_3/expat/Changes",
            "https://github.com/libexpat/libexpat/issues/887",
            "https://github.com/libexpat/libexpat/pull/890",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-45490",
            "https://ubuntu.com/security/notices/USN-7000-1",
            "https://ubuntu.com/security/notices/USN-7001-1",
            "https://www.cve.org/CVERecord?id=CVE-2024-45490"
          ],
          "PublishedDate": "2024-08-30T03:15:03.757Z",
          "LastModifiedDate": "2024-09-04T14:28:19.313Z"
        },
        {
          "VulnerabilityID": "CVE-2024-45491",
          "PkgID": "libexpat@2.6.2-r0",
          "PkgName": "libexpat",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/libexpat@2.6.2-r0?arch=x86_64\u0026distro=3.18.8",
            "UID": "18c0e8db946d840"
          },
          "InstalledVersion": "2.6.2-r0",
          "FixedVersion": "2.6.3-r0",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:e0438933db2c4dfc2590d009d4743559e822f88bcea754476741e383ec4ce873",
            "DiffID": "sha256:d33f2258ad03b38b1d5e0efa2162da1a50241a9053df12483bd9c4a740b031ab"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-45491",
          "DataSource": {
            "ID": "alpine",
            "Name": "Alpine Secdb",
            "URL": "https://secdb.alpinelinux.org/"
          },
          "Title": "libexpat: Integer Overflow or Wraparound",
          "Description": "An issue was discovered in libexpat before 2.6.3. dtdCopy in xmlparse.c can have an integer overflow for nDefaultAtts on 32-bit platforms (where UINT_MAX equals SIZE_MAX).",
          "Severity": "CRITICAL",
          "CweIDs": [
            "CWE-190"
          ],
          "VendorSeverity": {
            "cbl-mariner": 3,
            "nvd": 4,
            "photon": 4,
            "redhat": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
              "V3Score": 9.8
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 7.5
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2024-45491",
            "https://github.com/libexpat/libexpat/blob/R_2_6_3/expat/Changes",
            "https://github.com/libexpat/libexpat/issues/888",
            "https://github.com/libexpat/libexpat/pull/891",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-45491",
            "https://ubuntu.com/security/notices/USN-7000-1",
            "https://ubuntu.com/security/notices/USN-7001-1",
            "https://www.cve.org/CVERecord?id=CVE-2024-45491"
          ],
          "PublishedDate": "2024-08-30T03:15:03.85Z",
          "LastModifiedDate": "2024-09-04T14:28:33.953Z"
        },
        {
          "VulnerabilityID": "CVE-2024-45492",
          "PkgID": "libexpat@2.6.2-r0",
          "PkgName": "libexpat",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/libexpat@2.6.2-r0?arch=x86_64\u0026distro=3.18.8",
            "UID": "18c0e8db946d840"
          },
          "InstalledVersion": "2.6.2-r0",
          "FixedVersion": "2.6.3-r0",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:e0438933db2c4dfc2590d009d4743559e822f88bcea754476741e383ec4ce873",
            "DiffID": "sha256:d33f2258ad03b38b1d5e0efa2162da1a50241a9053df12483bd9c4a740b031ab"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-45492",
          "DataSource": {
            "ID": "alpine",
            "Name": "Alpine Secdb",
            "URL": "https://secdb.alpinelinux.org/"
          },
          "Title": "libexpat: integer overflow",
          "Description": "An issue was discovered in libexpat before 2.6.3. nextScaffoldPart in xmlparse.c can have an integer overflow for m_groupSize on 32-bit platforms (where UINT_MAX equals SIZE_MAX).",
          "Severity": "CRITICAL",
          "CweIDs": [
            "CWE-190"
          ],
          "VendorSeverity": {
            "cbl-mariner": 3,
            "nvd": 4,
            "photon": 4,
            "redhat": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
              "V3Score": 9.8
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 6.2
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2024-45492",
            "https://github.com/libexpat/libexpat/blob/R_2_6_3/expat/Changes",
            "https://github.com/libexpat/libexpat/issues/889",
            "https://github.com/libexpat/libexpat/pull/892",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-45492",
            "https://ubuntu.com/security/notices/USN-7000-1",
            "https://www.cve.org/CVERecord?id=CVE-2024-45492"
          ],
          "PublishedDate": "2024-08-30T03:15:03.93Z",
          "LastModifiedDate": "2024-09-04T14:28:41.76Z"
        },
        {
          "VulnerabilityID": "CVE-2024-6119",
          "PkgID": "libssl3@3.1.6-r0",
          "PkgName": "libssl3",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/libssl3@3.1.6-r0?arch=x86_64\u0026distro=3.18.8",
            "UID": "679ad9b332d2ba18"
          },
          "InstalledVersion": "3.1.6-r0",
          "FixedVersion": "3.1.7-r0",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:930bdd4d222e2e63c22bd9e88d29b3c5ddd3d8a9d8fb93cf8324f4e7b9577cfb",
            "DiffID": "sha256:ce7f800efff9a5cfddf4805e3887943b4a7bd97cf83140587336261130ece03b"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-6119",
          "DataSource": {
            "ID": "alpine",
            "Name": "Alpine Secdb",
            "URL": "https://secdb.alpinelinux.org/"
          },
          "Title": "openssl: Possible denial of service in X.509 name checks",
          "Description": "Issue summary: Applications performing certificate name checks (e.g., TLS\nclients checking server certificates) may attempt to read an invalid memory\naddress resulting in abnormal termination of the application process.\n\nImpact summary: Abnormal termination of an application can a cause a denial of\nservice.\n\nApplications performing certificate name checks (e.g., TLS clients checking\nserver certificates) may attempt to read an invalid memory address when\ncomparing the expected name with an `otherName` subject alternative name of an\nX.509 certificate. This may result in an exception that terminates the\napplication program.\n\nNote that basic certificate chain validation (signatures, dates, ...) is not\naffected, the denial of service can occur only when the application also\nspecifies an expected DNS name, Email address or IP address.\n\nTLS servers rarely solicit client certificates, and even when they do, they\ngenerally don't perform a name check against a reference identifier (expected\nidentity), but rather extract the presented identity after checking the\ncertificate chain.  So TLS servers are generally not affected and the severity\nof the issue is Moderate.\n\nThe FIPS modules in 3.3, 3.2, 3.1 and 3.0 are not affected by this issue.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-843"
          ],
          "VendorSeverity": {
            "photon": 3,
            "redhat": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 5.9
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2024-6119",
            "https://github.com/openssl/openssl/commit/05f360d9e849a1b277db628f1f13083a7f8dd04f",
            "https://github.com/openssl/openssl/commit/06d1dc3fa96a2ba5a3e22735a033012aadc9f0d6",
            "https://github.com/openssl/openssl/commit/621f3729831b05ee828a3203eddb621d014ff2b2",
            "https://github.com/openssl/openssl/commit/7dfcee2cd2a63b2c64b9b4b0850be64cb695b0a0",
            "https://github.com/openssl/openssl/security/advisories/GHSA-5qrj-vq78-58fj",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-6119",
            "https://openssl-library.org/news/secadv/20240903.txt",
            "https://ubuntu.com/security/notices/USN-6986-1",
            "https://www.cve.org/CVERecord?id=CVE-2024-6119"
          ],
          "PublishedDate": "2024-09-03T16:15:07.177Z",
          "LastModifiedDate": "2024-09-03T21:35:12.987Z"
        },
        {
          "VulnerabilityID": "CVE-2024-6232",
          "PkgID": "python3@3.11.8-r0",
          "PkgName": "python3",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/python3@3.11.8-r0?arch=x86_64\u0026distro=3.18.8",
            "UID": "86d616c64c3d9bf3"
          },
          "InstalledVersion": "3.11.8-r0",
          "FixedVersion": "3.11.10-r0",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:e0438933db2c4dfc2590d009d4743559e822f88bcea754476741e383ec4ce873",
            "DiffID": "sha256:d33f2258ad03b38b1d5e0efa2162da1a50241a9053df12483bd9c4a740b031ab"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-6232",
          "DataSource": {
            "ID": "alpine",
            "Name": "Alpine Secdb",
            "URL": "https://secdb.alpinelinux.org/"
          },
          "Title": "python: cpython: tarfile: ReDos via excessive backtracking while parsing header values",
          "Description": "There is a MEDIUM severity vulnerability affecting CPython.\n\n\n\n\n\nRegular expressions that allowed excessive backtracking during tarfile.TarFile header parsing are vulnerable to ReDoS via specifically-crafted tar archives.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-1333"
          ],
          "VendorSeverity": {
            "nvd": 3,
            "redhat": 2,
            "ubuntu": 2
          },
          "CVSS": {
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
            "https://access.redhat.com/security/cve/CVE-2024-6232",
            "https://github.com/python/cpython/commit/4eaf4891c12589e3c7bdad5f5b076e4c8392dd06",
            "https://github.com/python/cpython/commit/743acbe872485dc18df4d8ab2dc7895187f062c4",
            "https://github.com/python/cpython/commit/7d1f50cd92ff7e10a1c15a8f591dde8a6843a64d",
            "https://github.com/python/cpython/commit/b4225ca91547aa97ed3aca391614afbb255bc877",
            "https://github.com/python/cpython/commit/d449caf8a179e3b954268b3a88eb9170be3c8fbf",
            "https://github.com/python/cpython/commit/ed3a49ea734ada357ff4442996fd4ae71d253373",
            "https://github.com/python/cpython/issues/121285",
            "https://github.com/python/cpython/pull/121286",
            "https://mail.python.org/archives/list/security-announce@python.org/thread/JRYFTPRHZRTLMZLWQEUHZSJXNHM4ACTY/",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-6232",
            "https://www.cve.org/CVERecord?id=CVE-2024-6232"
          ],
          "PublishedDate": "2024-09-03T13:15:05.363Z",
          "LastModifiedDate": "2024-09-04T21:15:14.48Z"
        },
        {
          "VulnerabilityID": "CVE-2024-7592",
          "PkgID": "python3@3.11.8-r0",
          "PkgName": "python3",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/python3@3.11.8-r0?arch=x86_64\u0026distro=3.18.8",
            "UID": "86d616c64c3d9bf3"
          },
          "InstalledVersion": "3.11.8-r0",
          "FixedVersion": "3.11.10-r0",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:e0438933db2c4dfc2590d009d4743559e822f88bcea754476741e383ec4ce873",
            "DiffID": "sha256:d33f2258ad03b38b1d5e0efa2162da1a50241a9053df12483bd9c4a740b031ab"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-7592",
          "DataSource": {
            "ID": "alpine",
            "Name": "Alpine Secdb",
            "URL": "https://secdb.alpinelinux.org/"
          },
          "Title": "cpython: python: Uncontrolled CPU resource consumption when in http.cookies module",
          "Description": "There is a LOW severity vulnerability affecting CPython, specifically the\n'http.cookies' standard library module.\n\n\nWhen parsing cookies that contained backslashes for quoted characters in\nthe cookie value, the parser would use an algorithm with quadratic\ncomplexity, resulting in excess CPU resources being used while parsing the\nvalue.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-1333",
            "CWE-400"
          ],
          "VendorSeverity": {
            "azure": 3,
            "cbl-mariner": 3,
            "nvd": 3,
            "redhat": 1,
            "ubuntu": 1
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 7.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:N/I:N/A:H",
              "V3Score": 4.8
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2024-7592",
            "https://github.com/python/cpython/commit/391e5626e3ee5af267b97e37abc7475732e67621",
            "https://github.com/python/cpython/commit/a77ab24427a18bff817025adb03ca920dc3f1a06",
            "https://github.com/python/cpython/commit/b2f11ca7667e4d57c71c1c88b255115f16042d9a",
            "https://github.com/python/cpython/commit/d4ac921a4b081f7f996a5d2b101684b67ba0ed7f",
            "https://github.com/python/cpython/commit/d662e2db2605515a767f88ad48096b8ac623c774",
            "https://github.com/python/cpython/commit/dcc3eaef98cd94d6cb6cb0f44bd1c903d04f33b1",
            "https://github.com/python/cpython/issues/123067",
            "https://github.com/python/cpython/pull/123075",
            "https://mail.python.org/archives/list/security-announce@python.org/thread/HXJAAAALNUNGCQUS2W7WR6GFIZIHFOOK/",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-7592",
            "https://www.cve.org/CVERecord?id=CVE-2024-7592"
          ],
          "PublishedDate": "2024-08-19T19:15:08.18Z",
          "LastModifiedDate": "2024-09-04T21:15:14.643Z"
        },
        {
          "VulnerabilityID": "CVE-2023-27043",
          "PkgID": "python3@3.11.8-r0",
          "PkgName": "python3",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/python3@3.11.8-r0?arch=x86_64\u0026distro=3.18.8",
            "UID": "86d616c64c3d9bf3"
          },
          "InstalledVersion": "3.11.8-r0",
          "FixedVersion": "3.11.10-r0",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:e0438933db2c4dfc2590d009d4743559e822f88bcea754476741e383ec4ce873",
            "DiffID": "sha256:d33f2258ad03b38b1d5e0efa2162da1a50241a9053df12483bd9c4a740b031ab"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-27043",
          "DataSource": {
            "ID": "alpine",
            "Name": "Alpine Secdb",
            "URL": "https://secdb.alpinelinux.org/"
          },
          "Title": "python: Parsing errors in email/_parseaddr.py lead to incorrect value in email address part of tuple",
          "Description": "The email module of Python through 3.11.3 incorrectly parses e-mail addresses that contain a special character. The wrong portion of an RFC2822 header is identified as the value of the addr-spec. In some applications, an attacker can bypass a protection mechanism in which application access is granted only after verifying receipt of e-mail to a specific domain (e.g., only @company.example.com addresses may be used for signup). This occurs in email/_parseaddr.py in recent versions of Python.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-20"
          ],
          "VendorSeverity": {
            "alma": 2,
            "amazon": 2,
            "bitnami": 2,
            "nvd": 2,
            "oracle-oval": 2,
            "photon": 2,
            "redhat": 2,
            "rocky": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "bitnami": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
              "V3Score": 5.3
            },
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
              "V3Score": 5.3
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
              "V3Score": 5.3
            }
          },
          "References": [
            "http://python.org",
            "https://access.redhat.com/articles/7051467",
            "https://access.redhat.com/errata/RHSA-2024:2292",
            "https://access.redhat.com/security/cve/CVE-2023-27043",
            "https://bugzilla.redhat.com/2196183",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2196183",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-27043",
            "https://errata.almalinux.org/9/ALSA-2024-2292.html",
            "https://errata.rockylinux.org/RLSA-2024:0256",
            "https://github.com/python/cpython/issues/102988",
            "https://github.com/python/cpython/pull/102990",
            "https://github.com/python/cpython/pull/105127",
            "https://linux.oracle.com/cve/CVE-2023-27043.html",
            "https://linux.oracle.com/errata/ELSA-2024-3062.html",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/4ZAEFSFZDNBNJPNOUTLG5COISGQDLMGV/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/75DTHSTNOFFNAWHXKMDXS7EJWC6W2FUC/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/ARI7VDSNTQVXRQFM6IK5GSSLEIYV4VZH/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/BQAKLUJMHFGVBRDPEY57BJGNCE5UUPHW/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/HXYVPEZUA3465AEFX5JVFVP7KIFZMF3N/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/N6M5I6OQHJABNEYY555HUMMKX3Y4P25Z/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/NEUNZSZ3CVSM2QWVYH3N2XGOCDWNYUA3/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/ORLXS5YTKN65E2Q2NWKXMFS5FWQHRNZW/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/P2MAICLFDDO3QVNHTZ2OCERZQ34R2PIC/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/P2W2BZQIHMCKRI5FNBJERFYMS5PK6TAH/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/PHVGRKQAGANCSGFI3QMYOCIMS4IFOZA5/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/PU6Y2S5CBN5BWCBDAJFTGIBZLK3S2G3J/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/QDRDDPDN3VFIYXJIYEABY6USX5EU66AG/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/RDDC2VOX7OQC6OHMYTVD4HLFZIV6PYBC/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/SINP4OVYNB2AGDYI2GS37EMW3H3F7XPZ/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/SOX7BCN6YL7B3RFPEEXPIU5CMTEHJOKR/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/VZXC32CJ7TWDPJO6GY2XIQRO7JZX5FLP/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/XWMBD4LNHWEXRI6YVFWJMTJQUL5WOFTS/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/YQVY5C5REXWJIORJIL2FIL3ALOEJEF72/",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-27043",
            "https://python-security.readthedocs.io/vuln/email-parseaddr-realname.html",
            "https://security.netapp.com/advisory/ntap-20230601-0003/",
            "https://www.cve.org/CVERecord?id=CVE-2023-27043"
          ],
          "PublishedDate": "2023-04-19T00:15:07.973Z",
          "LastModifiedDate": "2024-02-26T16:27:45.78Z"
        },
        {
          "VulnerabilityID": "CVE-2024-6923",
          "PkgID": "python3@3.11.8-r0",
          "PkgName": "python3",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/python3@3.11.8-r0?arch=x86_64\u0026distro=3.18.8",
            "UID": "86d616c64c3d9bf3"
          },
          "InstalledVersion": "3.11.8-r0",
          "FixedVersion": "3.11.10-r0",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:e0438933db2c4dfc2590d009d4743559e822f88bcea754476741e383ec4ce873",
            "DiffID": "sha256:d33f2258ad03b38b1d5e0efa2162da1a50241a9053df12483bd9c4a740b031ab"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-6923",
          "DataSource": {
            "ID": "alpine",
            "Name": "Alpine Secdb",
            "URL": "https://secdb.alpinelinux.org/"
          },
          "Title": "cpython: python: email module doesn't properly quotes newlines in email headers, allowing header injection",
          "Description": "There is a MEDIUM severity vulnerability affecting CPython.\n\nThe \nemail module didn’t properly quote newlines for email headers when \nserializing an email message allowing for header injection when an email\n is serialized.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-94"
          ],
          "VendorSeverity": {
            "alma": 2,
            "bitnami": 2,
            "oracle-oval": 2,
            "photon": 2,
            "redhat": 2
          },
          "CVSS": {
            "bitnami": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:L",
              "V3Score": 5.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N",
              "V3Score": 6.8
            }
          },
          "References": [
            "https://access.redhat.com/errata/RHSA-2024:6179",
            "https://access.redhat.com/security/cve/CVE-2024-6923",
            "https://bugzilla.redhat.com/2302255",
            "https://errata.almalinux.org/9/ALSA-2024-6179.html",
            "https://github.com/python/cpython/commit/06f28dc236708f72871c64d4bc4b4ea144c50147",
            "https://github.com/python/cpython/commit/4766d1200fdf8b6728137aa2927a297e224d5fa7",
            "https://github.com/python/cpython/commit/4aaa4259b5a6e664b7316a4d60bdec7ee0f124d0",
            "https://github.com/python/cpython/commit/b158a76ce094897c870fb6b3de62887b7ccc33f1",
            "https://github.com/python/cpython/commit/f7be505d137a22528cb0fc004422c0081d5d90e6",
            "https://github.com/python/cpython/commit/f7c0f09e69e950cf3c5ada9dbde93898eb975533",
            "https://github.com/python/cpython/issues/121650",
            "https://github.com/python/cpython/pull/122233",
            "https://linux.oracle.com/cve/CVE-2024-6923.html",
            "https://linux.oracle.com/errata/ELSA-2024-6179.html",
            "https://mail.python.org/archives/list/security-announce@python.org/thread/QH3BUOE2DYQBWP7NAQ7UNHPPOELKISRW/",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-6923",
            "https://www.cve.org/CVERecord?id=CVE-2024-6923"
          ],
          "PublishedDate": "2024-08-01T14:15:03.647Z",
          "LastModifiedDate": "2024-09-04T21:15:14.567Z"
        },
        {
          "VulnerabilityID": "CVE-2024-8088",
          "PkgID": "python3@3.11.8-r0",
          "PkgName": "python3",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/python3@3.11.8-r0?arch=x86_64\u0026distro=3.18.8",
            "UID": "86d616c64c3d9bf3"
          },
          "InstalledVersion": "3.11.8-r0",
          "FixedVersion": "3.11.8-r1",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:e0438933db2c4dfc2590d009d4743559e822f88bcea754476741e383ec4ce873",
            "DiffID": "sha256:d33f2258ad03b38b1d5e0efa2162da1a50241a9053df12483bd9c4a740b031ab"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-8088",
          "DataSource": {
            "ID": "alpine",
            "Name": "Alpine Secdb",
            "URL": "https://secdb.alpinelinux.org/"
          },
          "Title": "python: cpython: Iterating over a malicious ZIP file may lead to Denial of Service",
          "Description": "There is a HIGH severity vulnerability affecting the CPython \"zipfile\"\nmodule affecting \"zipfile.Path\". Note that the more common API \"zipfile.ZipFile\" class is unaffected.\n\n\n\n\n\nWhen iterating over names of entries in a zip archive (for example, methods\nof \"zipfile.Path\" like \"namelist()\", \"iterdir()\", etc)\nthe process can be put into an infinite loop with a maliciously crafted\nzip archive. This defect applies when reading only metadata or extracting\nthe contents of the zip archive. Programs that are not handling\nuser-controlled zip archives are not affected.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-835"
          ],
          "VendorSeverity": {
            "alma": 2,
            "oracle-oval": 2,
            "redhat": 2
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:H",
              "V3Score": 5.3
            }
          },
          "References": [
            "https://access.redhat.com/errata/RHSA-2024:5962",
            "https://access.redhat.com/security/cve/CVE-2024-8088",
            "https://bugzilla.redhat.com/2292921",
            "https://bugzilla.redhat.com/2297771",
            "https://bugzilla.redhat.com/2302255",
            "https://bugzilla.redhat.com/2307370",
            "https://errata.almalinux.org/8/ALSA-2024-5962.html",
            "https://github.com/python/cpython/commit/0aa1ee22ab6e204e9d3d0e9dd63ea648ed691ef1",
            "https://github.com/python/cpython/commit/2231286d78d328c2f575e0b05b16fe447d1656d6",
            "https://github.com/python/cpython/commit/795f2597a4be988e2bb19b69ff9958e981cb894e",
            "https://github.com/python/cpython/commit/7bc367e464ce50b956dd232c1dfa1cad4e7fb814",
            "https://github.com/python/cpython/commit/7e8883a3f04d308302361aeffc73e0e9837f19d4",
            "https://github.com/python/cpython/commit/8c7348939d8a3ecd79d630075f6be1b0c5b41f64",
            "https://github.com/python/cpython/commit/95b073bddefa6243effa08e131e297c0383e7f6a",
            "https://github.com/python/cpython/commit/962055268ed4f2ca1d717bfc8b6385de50a23ab7",
            "https://github.com/python/cpython/commit/dcc5182f27c1500006a1ef78e10613bb45788dea",
            "https://github.com/python/cpython/commit/e0264a61119d551658d9445af38323ba94fc16db",
            "https://github.com/python/cpython/commit/fc0b8259e693caa8400fa8b6ac1e494e47ea7798",
            "https://github.com/python/cpython/issues/122905",
            "https://github.com/python/cpython/issues/123270",
            "https://github.com/python/cpython/pull/122906",
            "https://linux.oracle.com/cve/CVE-2024-8088.html",
            "https://linux.oracle.com/errata/ELSA-2024-5962.html",
            "https://mail.python.org/archives/list/security-announce@python.org/thread/GNFCKVI4TCATKQLALJ5SN4L4CSPSMILU/",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-8088",
            "https://www.cve.org/CVERecord?id=CVE-2024-8088"
          ],
          "PublishedDate": "2024-08-22T19:15:09.72Z",
          "LastModifiedDate": "2024-09-04T23:15:13.1Z"
        },
        {
          "VulnerabilityID": "CVE-2024-4032",
          "PkgID": "python3@3.11.8-r0",
          "PkgName": "python3",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/python3@3.11.8-r0?arch=x86_64\u0026distro=3.18.8",
            "UID": "86d616c64c3d9bf3"
          },
          "InstalledVersion": "3.11.8-r0",
          "FixedVersion": "3.11.10-r0",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:e0438933db2c4dfc2590d009d4743559e822f88bcea754476741e383ec4ce873",
            "DiffID": "sha256:d33f2258ad03b38b1d5e0efa2162da1a50241a9053df12483bd9c4a740b031ab"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-4032",
          "DataSource": {
            "ID": "alpine",
            "Name": "Alpine Secdb",
            "URL": "https://secdb.alpinelinux.org/"
          },
          "Title": "python: incorrect IPv4 and IPv6 private ranges",
          "Description": "The “ipaddress” module contained incorrect information about whether certain IPv4 and IPv6 addresses were designated as “globally reachable” or “private”. This affected the is_private and is_global properties of the ipaddress.IPv4Address, ipaddress.IPv4Network, ipaddress.IPv6Address, and ipaddress.IPv6Network classes, where values wouldn’t be returned in accordance with the latest information from the IANA Special-Purpose Address Registries.\n\nCPython 3.12.4 and 3.13.0a6 contain updated information from these registries and thus have the intended behavior.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-697"
          ],
          "VendorSeverity": {
            "alma": 1,
            "bitnami": 3,
            "oracle-oval": 2,
            "photon": 1,
            "redhat": 1,
            "ubuntu": 1
          },
          "CVSS": {
            "bitnami": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
              "V3Score": 7.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L",
              "V3Score": 3.7
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2024/06/17/3",
            "https://access.redhat.com/errata/RHSA-2024:4779",
            "https://access.redhat.com/security/cve/CVE-2024-4032",
            "https://bugzilla.redhat.com/2292921",
            "https://errata.almalinux.org/9/ALSA-2024-4779.html",
            "https://github.com/advisories/GHSA-mh6q-v4mp-2cc7",
            "https://github.com/python/cpython/commit/22adf29da8d99933ffed8647d3e0726edd16f7f8",
            "https://github.com/python/cpython/commit/40d75c2b7f5c67e254d0a025e0f2e2c7ada7f69f",
            "https://github.com/python/cpython/commit/40d75c2b7f5c67e254d0a025e0f2e2c7ada7f69f (3.13)",
            "https://github.com/python/cpython/commit/895f7e2ac23eff4743143beef0f0c5ac71ea27d3",
            "https://github.com/python/cpython/commit/ba431579efdcbaed7a96f2ac4ea0775879a332fb",
            "https://github.com/python/cpython/commit/c62c9e518b784fe44432a3f4fc265fb95b651906",
            "https://github.com/python/cpython/commit/f86b17ac511e68192ba71f27e752321a3252cee3",
            "https://github.com/python/cpython/issues/113171",
            "https://github.com/python/cpython/pull/113179",
            "https://linux.oracle.com/cve/CVE-2024-4032.html",
            "https://linux.oracle.com/errata/ELSA-2024-5962.html",
            "https://mail.python.org/archives/list/security-announce@python.org/thread/NRUHDUS2IV2USIZM2CVMSFL6SCKU3RZA/",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-4032",
            "https://security.netapp.com/advisory/ntap-20240726-0004/",
            "https://ubuntu.com/security/notices/USN-6928-1",
            "https://ubuntu.com/security/notices/USN-6941-1",
            "https://www.cve.org/CVERecord?id=CVE-2024-4032",
            "https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml",
            "https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml"
          ],
          "PublishedDate": "2024-06-17T15:15:52.517Z",
          "LastModifiedDate": "2024-08-29T21:35:11.017Z"
        },
        {
          "VulnerabilityID": "CVE-2015-2104",
          "PkgID": "python3@3.11.8-r0",
          "PkgName": "python3",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/python3@3.11.8-r0?arch=x86_64\u0026distro=3.18.8",
            "UID": "86d616c64c3d9bf3"
          },
          "InstalledVersion": "3.11.8-r0",
          "FixedVersion": "3.11.10-r0",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:e0438933db2c4dfc2590d009d4743559e822f88bcea754476741e383ec4ce873",
            "DiffID": "sha256:d33f2258ad03b38b1d5e0efa2162da1a50241a9053df12483bd9c4a740b031ab"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2015-2104",
          "DataSource": {
            "ID": "alpine",
            "Name": "Alpine Secdb",
            "URL": "https://secdb.alpinelinux.org/"
          },
          "Description": "Rejected reason: DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This candidate was withdrawn by its CNA. Further investigation showed that it was not a security issue. Notes: none",
          "Severity": "UNKNOWN",
          "PublishedDate": "2020-02-19T14:15:10.357Z",
          "LastModifiedDate": "2023-11-07T02:25:05.71Z"
        },
        {
          "VulnerabilityID": "CVE-2024-6232",
          "PkgID": "python3-pyc@3.11.8-r0",
          "PkgName": "python3-pyc",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/python3-pyc@3.11.8-r0?arch=x86_64\u0026distro=3.18.8",
            "UID": "2627c3a3a5829fff"
          },
          "InstalledVersion": "3.11.8-r0",
          "FixedVersion": "3.11.10-r0",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:e0438933db2c4dfc2590d009d4743559e822f88bcea754476741e383ec4ce873",
            "DiffID": "sha256:d33f2258ad03b38b1d5e0efa2162da1a50241a9053df12483bd9c4a740b031ab"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-6232",
          "DataSource": {
            "ID": "alpine",
            "Name": "Alpine Secdb",
            "URL": "https://secdb.alpinelinux.org/"
          },
          "Title": "python: cpython: tarfile: ReDos via excessive backtracking while parsing header values",
          "Description": "There is a MEDIUM severity vulnerability affecting CPython.\n\n\n\n\n\nRegular expressions that allowed excessive backtracking during tarfile.TarFile header parsing are vulnerable to ReDoS via specifically-crafted tar archives.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-1333"
          ],
          "VendorSeverity": {
            "nvd": 3,
            "redhat": 2,
            "ubuntu": 2
          },
          "CVSS": {
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
            "https://access.redhat.com/security/cve/CVE-2024-6232",
            "https://github.com/python/cpython/commit/4eaf4891c12589e3c7bdad5f5b076e4c8392dd06",
            "https://github.com/python/cpython/commit/743acbe872485dc18df4d8ab2dc7895187f062c4",
            "https://github.com/python/cpython/commit/7d1f50cd92ff7e10a1c15a8f591dde8a6843a64d",
            "https://github.com/python/cpython/commit/b4225ca91547aa97ed3aca391614afbb255bc877",
            "https://github.com/python/cpython/commit/d449caf8a179e3b954268b3a88eb9170be3c8fbf",
            "https://github.com/python/cpython/commit/ed3a49ea734ada357ff4442996fd4ae71d253373",
            "https://github.com/python/cpython/issues/121285",
            "https://github.com/python/cpython/pull/121286",
            "https://mail.python.org/archives/list/security-announce@python.org/thread/JRYFTPRHZRTLMZLWQEUHZSJXNHM4ACTY/",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-6232",
            "https://www.cve.org/CVERecord?id=CVE-2024-6232"
          ],
          "PublishedDate": "2024-09-03T13:15:05.363Z",
          "LastModifiedDate": "2024-09-04T21:15:14.48Z"
        },
        {
          "VulnerabilityID": "CVE-2024-7592",
          "PkgID": "python3-pyc@3.11.8-r0",
          "PkgName": "python3-pyc",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/python3-pyc@3.11.8-r0?arch=x86_64\u0026distro=3.18.8",
            "UID": "2627c3a3a5829fff"
          },
          "InstalledVersion": "3.11.8-r0",
          "FixedVersion": "3.11.10-r0",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:e0438933db2c4dfc2590d009d4743559e822f88bcea754476741e383ec4ce873",
            "DiffID": "sha256:d33f2258ad03b38b1d5e0efa2162da1a50241a9053df12483bd9c4a740b031ab"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-7592",
          "DataSource": {
            "ID": "alpine",
            "Name": "Alpine Secdb",
            "URL": "https://secdb.alpinelinux.org/"
          },
          "Title": "cpython: python: Uncontrolled CPU resource consumption when in http.cookies module",
          "Description": "There is a LOW severity vulnerability affecting CPython, specifically the\n'http.cookies' standard library module.\n\n\nWhen parsing cookies that contained backslashes for quoted characters in\nthe cookie value, the parser would use an algorithm with quadratic\ncomplexity, resulting in excess CPU resources being used while parsing the\nvalue.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-1333",
            "CWE-400"
          ],
          "VendorSeverity": {
            "azure": 3,
            "cbl-mariner": 3,
            "nvd": 3,
            "redhat": 1,
            "ubuntu": 1
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 7.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:N/I:N/A:H",
              "V3Score": 4.8
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2024-7592",
            "https://github.com/python/cpython/commit/391e5626e3ee5af267b97e37abc7475732e67621",
            "https://github.com/python/cpython/commit/a77ab24427a18bff817025adb03ca920dc3f1a06",
            "https://github.com/python/cpython/commit/b2f11ca7667e4d57c71c1c88b255115f16042d9a",
            "https://github.com/python/cpython/commit/d4ac921a4b081f7f996a5d2b101684b67ba0ed7f",
            "https://github.com/python/cpython/commit/d662e2db2605515a767f88ad48096b8ac623c774",
            "https://github.com/python/cpython/commit/dcc3eaef98cd94d6cb6cb0f44bd1c903d04f33b1",
            "https://github.com/python/cpython/issues/123067",
            "https://github.com/python/cpython/pull/123075",
            "https://mail.python.org/archives/list/security-announce@python.org/thread/HXJAAAALNUNGCQUS2W7WR6GFIZIHFOOK/",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-7592",
            "https://www.cve.org/CVERecord?id=CVE-2024-7592"
          ],
          "PublishedDate": "2024-08-19T19:15:08.18Z",
          "LastModifiedDate": "2024-09-04T21:15:14.643Z"
        },
        {
          "VulnerabilityID": "CVE-2023-27043",
          "PkgID": "python3-pyc@3.11.8-r0",
          "PkgName": "python3-pyc",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/python3-pyc@3.11.8-r0?arch=x86_64\u0026distro=3.18.8",
            "UID": "2627c3a3a5829fff"
          },
          "InstalledVersion": "3.11.8-r0",
          "FixedVersion": "3.11.10-r0",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:e0438933db2c4dfc2590d009d4743559e822f88bcea754476741e383ec4ce873",
            "DiffID": "sha256:d33f2258ad03b38b1d5e0efa2162da1a50241a9053df12483bd9c4a740b031ab"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-27043",
          "DataSource": {
            "ID": "alpine",
            "Name": "Alpine Secdb",
            "URL": "https://secdb.alpinelinux.org/"
          },
          "Title": "python: Parsing errors in email/_parseaddr.py lead to incorrect value in email address part of tuple",
          "Description": "The email module of Python through 3.11.3 incorrectly parses e-mail addresses that contain a special character. The wrong portion of an RFC2822 header is identified as the value of the addr-spec. In some applications, an attacker can bypass a protection mechanism in which application access is granted only after verifying receipt of e-mail to a specific domain (e.g., only @company.example.com addresses may be used for signup). This occurs in email/_parseaddr.py in recent versions of Python.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-20"
          ],
          "VendorSeverity": {
            "alma": 2,
            "amazon": 2,
            "bitnami": 2,
            "nvd": 2,
            "oracle-oval": 2,
            "photon": 2,
            "redhat": 2,
            "rocky": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "bitnami": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
              "V3Score": 5.3
            },
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
              "V3Score": 5.3
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
              "V3Score": 5.3
            }
          },
          "References": [
            "http://python.org",
            "https://access.redhat.com/articles/7051467",
            "https://access.redhat.com/errata/RHSA-2024:2292",
            "https://access.redhat.com/security/cve/CVE-2023-27043",
            "https://bugzilla.redhat.com/2196183",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2196183",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-27043",
            "https://errata.almalinux.org/9/ALSA-2024-2292.html",
            "https://errata.rockylinux.org/RLSA-2024:0256",
            "https://github.com/python/cpython/issues/102988",
            "https://github.com/python/cpython/pull/102990",
            "https://github.com/python/cpython/pull/105127",
            "https://linux.oracle.com/cve/CVE-2023-27043.html",
            "https://linux.oracle.com/errata/ELSA-2024-3062.html",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/4ZAEFSFZDNBNJPNOUTLG5COISGQDLMGV/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/75DTHSTNOFFNAWHXKMDXS7EJWC6W2FUC/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/ARI7VDSNTQVXRQFM6IK5GSSLEIYV4VZH/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/BQAKLUJMHFGVBRDPEY57BJGNCE5UUPHW/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/HXYVPEZUA3465AEFX5JVFVP7KIFZMF3N/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/N6M5I6OQHJABNEYY555HUMMKX3Y4P25Z/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/NEUNZSZ3CVSM2QWVYH3N2XGOCDWNYUA3/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/ORLXS5YTKN65E2Q2NWKXMFS5FWQHRNZW/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/P2MAICLFDDO3QVNHTZ2OCERZQ34R2PIC/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/P2W2BZQIHMCKRI5FNBJERFYMS5PK6TAH/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/PHVGRKQAGANCSGFI3QMYOCIMS4IFOZA5/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/PU6Y2S5CBN5BWCBDAJFTGIBZLK3S2G3J/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/QDRDDPDN3VFIYXJIYEABY6USX5EU66AG/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/RDDC2VOX7OQC6OHMYTVD4HLFZIV6PYBC/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/SINP4OVYNB2AGDYI2GS37EMW3H3F7XPZ/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/SOX7BCN6YL7B3RFPEEXPIU5CMTEHJOKR/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/VZXC32CJ7TWDPJO6GY2XIQRO7JZX5FLP/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/XWMBD4LNHWEXRI6YVFWJMTJQUL5WOFTS/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/YQVY5C5REXWJIORJIL2FIL3ALOEJEF72/",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-27043",
            "https://python-security.readthedocs.io/vuln/email-parseaddr-realname.html",
            "https://security.netapp.com/advisory/ntap-20230601-0003/",
            "https://www.cve.org/CVERecord?id=CVE-2023-27043"
          ],
          "PublishedDate": "2023-04-19T00:15:07.973Z",
          "LastModifiedDate": "2024-02-26T16:27:45.78Z"
        },
        {
          "VulnerabilityID": "CVE-2024-6923",
          "PkgID": "python3-pyc@3.11.8-r0",
          "PkgName": "python3-pyc",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/python3-pyc@3.11.8-r0?arch=x86_64\u0026distro=3.18.8",
            "UID": "2627c3a3a5829fff"
          },
          "InstalledVersion": "3.11.8-r0",
          "FixedVersion": "3.11.10-r0",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:e0438933db2c4dfc2590d009d4743559e822f88bcea754476741e383ec4ce873",
            "DiffID": "sha256:d33f2258ad03b38b1d5e0efa2162da1a50241a9053df12483bd9c4a740b031ab"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-6923",
          "DataSource": {
            "ID": "alpine",
            "Name": "Alpine Secdb",
            "URL": "https://secdb.alpinelinux.org/"
          },
          "Title": "cpython: python: email module doesn't properly quotes newlines in email headers, allowing header injection",
          "Description": "There is a MEDIUM severity vulnerability affecting CPython.\n\nThe \nemail module didn’t properly quote newlines for email headers when \nserializing an email message allowing for header injection when an email\n is serialized.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-94"
          ],
          "VendorSeverity": {
            "alma": 2,
            "bitnami": 2,
            "oracle-oval": 2,
            "photon": 2,
            "redhat": 2
          },
          "CVSS": {
            "bitnami": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:L",
              "V3Score": 5.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N",
              "V3Score": 6.8
            }
          },
          "References": [
            "https://access.redhat.com/errata/RHSA-2024:6179",
            "https://access.redhat.com/security/cve/CVE-2024-6923",
            "https://bugzilla.redhat.com/2302255",
            "https://errata.almalinux.org/9/ALSA-2024-6179.html",
            "https://github.com/python/cpython/commit/06f28dc236708f72871c64d4bc4b4ea144c50147",
            "https://github.com/python/cpython/commit/4766d1200fdf8b6728137aa2927a297e224d5fa7",
            "https://github.com/python/cpython/commit/4aaa4259b5a6e664b7316a4d60bdec7ee0f124d0",
            "https://github.com/python/cpython/commit/b158a76ce094897c870fb6b3de62887b7ccc33f1",
            "https://github.com/python/cpython/commit/f7be505d137a22528cb0fc004422c0081d5d90e6",
            "https://github.com/python/cpython/commit/f7c0f09e69e950cf3c5ada9dbde93898eb975533",
            "https://github.com/python/cpython/issues/121650",
            "https://github.com/python/cpython/pull/122233",
            "https://linux.oracle.com/cve/CVE-2024-6923.html",
            "https://linux.oracle.com/errata/ELSA-2024-6179.html",
            "https://mail.python.org/archives/list/security-announce@python.org/thread/QH3BUOE2DYQBWP7NAQ7UNHPPOELKISRW/",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-6923",
            "https://www.cve.org/CVERecord?id=CVE-2024-6923"
          ],
          "PublishedDate": "2024-08-01T14:15:03.647Z",
          "LastModifiedDate": "2024-09-04T21:15:14.567Z"
        },
        {
          "VulnerabilityID": "CVE-2024-8088",
          "PkgID": "python3-pyc@3.11.8-r0",
          "PkgName": "python3-pyc",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/python3-pyc@3.11.8-r0?arch=x86_64\u0026distro=3.18.8",
            "UID": "2627c3a3a5829fff"
          },
          "InstalledVersion": "3.11.8-r0",
          "FixedVersion": "3.11.8-r1",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:e0438933db2c4dfc2590d009d4743559e822f88bcea754476741e383ec4ce873",
            "DiffID": "sha256:d33f2258ad03b38b1d5e0efa2162da1a50241a9053df12483bd9c4a740b031ab"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-8088",
          "DataSource": {
            "ID": "alpine",
            "Name": "Alpine Secdb",
            "URL": "https://secdb.alpinelinux.org/"
          },
          "Title": "python: cpython: Iterating over a malicious ZIP file may lead to Denial of Service",
          "Description": "There is a HIGH severity vulnerability affecting the CPython \"zipfile\"\nmodule affecting \"zipfile.Path\". Note that the more common API \"zipfile.ZipFile\" class is unaffected.\n\n\n\n\n\nWhen iterating over names of entries in a zip archive (for example, methods\nof \"zipfile.Path\" like \"namelist()\", \"iterdir()\", etc)\nthe process can be put into an infinite loop with a maliciously crafted\nzip archive. This defect applies when reading only metadata or extracting\nthe contents of the zip archive. Programs that are not handling\nuser-controlled zip archives are not affected.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-835"
          ],
          "VendorSeverity": {
            "alma": 2,
            "oracle-oval": 2,
            "redhat": 2
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:H",
              "V3Score": 5.3
            }
          },
          "References": [
            "https://access.redhat.com/errata/RHSA-2024:5962",
            "https://access.redhat.com/security/cve/CVE-2024-8088",
            "https://bugzilla.redhat.com/2292921",
            "https://bugzilla.redhat.com/2297771",
            "https://bugzilla.redhat.com/2302255",
            "https://bugzilla.redhat.com/2307370",
            "https://errata.almalinux.org/8/ALSA-2024-5962.html",
            "https://github.com/python/cpython/commit/0aa1ee22ab6e204e9d3d0e9dd63ea648ed691ef1",
            "https://github.com/python/cpython/commit/2231286d78d328c2f575e0b05b16fe447d1656d6",
            "https://github.com/python/cpython/commit/795f2597a4be988e2bb19b69ff9958e981cb894e",
            "https://github.com/python/cpython/commit/7bc367e464ce50b956dd232c1dfa1cad4e7fb814",
            "https://github.com/python/cpython/commit/7e8883a3f04d308302361aeffc73e0e9837f19d4",
            "https://github.com/python/cpython/commit/8c7348939d8a3ecd79d630075f6be1b0c5b41f64",
            "https://github.com/python/cpython/commit/95b073bddefa6243effa08e131e297c0383e7f6a",
            "https://github.com/python/cpython/commit/962055268ed4f2ca1d717bfc8b6385de50a23ab7",
            "https://github.com/python/cpython/commit/dcc5182f27c1500006a1ef78e10613bb45788dea",
            "https://github.com/python/cpython/commit/e0264a61119d551658d9445af38323ba94fc16db",
            "https://github.com/python/cpython/commit/fc0b8259e693caa8400fa8b6ac1e494e47ea7798",
            "https://github.com/python/cpython/issues/122905",
            "https://github.com/python/cpython/issues/123270",
            "https://github.com/python/cpython/pull/122906",
            "https://linux.oracle.com/cve/CVE-2024-8088.html",
            "https://linux.oracle.com/errata/ELSA-2024-5962.html",
            "https://mail.python.org/archives/list/security-announce@python.org/thread/GNFCKVI4TCATKQLALJ5SN4L4CSPSMILU/",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-8088",
            "https://www.cve.org/CVERecord?id=CVE-2024-8088"
          ],
          "PublishedDate": "2024-08-22T19:15:09.72Z",
          "LastModifiedDate": "2024-09-04T23:15:13.1Z"
        },
        {
          "VulnerabilityID": "CVE-2024-4032",
          "PkgID": "python3-pyc@3.11.8-r0",
          "PkgName": "python3-pyc",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/python3-pyc@3.11.8-r0?arch=x86_64\u0026distro=3.18.8",
            "UID": "2627c3a3a5829fff"
          },
          "InstalledVersion": "3.11.8-r0",
          "FixedVersion": "3.11.10-r0",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:e0438933db2c4dfc2590d009d4743559e822f88bcea754476741e383ec4ce873",
            "DiffID": "sha256:d33f2258ad03b38b1d5e0efa2162da1a50241a9053df12483bd9c4a740b031ab"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-4032",
          "DataSource": {
            "ID": "alpine",
            "Name": "Alpine Secdb",
            "URL": "https://secdb.alpinelinux.org/"
          },
          "Title": "python: incorrect IPv4 and IPv6 private ranges",
          "Description": "The “ipaddress” module contained incorrect information about whether certain IPv4 and IPv6 addresses were designated as “globally reachable” or “private”. This affected the is_private and is_global properties of the ipaddress.IPv4Address, ipaddress.IPv4Network, ipaddress.IPv6Address, and ipaddress.IPv6Network classes, where values wouldn’t be returned in accordance with the latest information from the IANA Special-Purpose Address Registries.\n\nCPython 3.12.4 and 3.13.0a6 contain updated information from these registries and thus have the intended behavior.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-697"
          ],
          "VendorSeverity": {
            "alma": 1,
            "bitnami": 3,
            "oracle-oval": 2,
            "photon": 1,
            "redhat": 1,
            "ubuntu": 1
          },
          "CVSS": {
            "bitnami": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
              "V3Score": 7.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L",
              "V3Score": 3.7
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2024/06/17/3",
            "https://access.redhat.com/errata/RHSA-2024:4779",
            "https://access.redhat.com/security/cve/CVE-2024-4032",
            "https://bugzilla.redhat.com/2292921",
            "https://errata.almalinux.org/9/ALSA-2024-4779.html",
            "https://github.com/advisories/GHSA-mh6q-v4mp-2cc7",
            "https://github.com/python/cpython/commit/22adf29da8d99933ffed8647d3e0726edd16f7f8",
            "https://github.com/python/cpython/commit/40d75c2b7f5c67e254d0a025e0f2e2c7ada7f69f",
            "https://github.com/python/cpython/commit/40d75c2b7f5c67e254d0a025e0f2e2c7ada7f69f (3.13)",
            "https://github.com/python/cpython/commit/895f7e2ac23eff4743143beef0f0c5ac71ea27d3",
            "https://github.com/python/cpython/commit/ba431579efdcbaed7a96f2ac4ea0775879a332fb",
            "https://github.com/python/cpython/commit/c62c9e518b784fe44432a3f4fc265fb95b651906",
            "https://github.com/python/cpython/commit/f86b17ac511e68192ba71f27e752321a3252cee3",
            "https://github.com/python/cpython/issues/113171",
            "https://github.com/python/cpython/pull/113179",
            "https://linux.oracle.com/cve/CVE-2024-4032.html",
            "https://linux.oracle.com/errata/ELSA-2024-5962.html",
            "https://mail.python.org/archives/list/security-announce@python.org/thread/NRUHDUS2IV2USIZM2CVMSFL6SCKU3RZA/",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-4032",
            "https://security.netapp.com/advisory/ntap-20240726-0004/",
            "https://ubuntu.com/security/notices/USN-6928-1",
            "https://ubuntu.com/security/notices/USN-6941-1",
            "https://www.cve.org/CVERecord?id=CVE-2024-4032",
            "https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml",
            "https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml"
          ],
          "PublishedDate": "2024-06-17T15:15:52.517Z",
          "LastModifiedDate": "2024-08-29T21:35:11.017Z"
        },
        {
          "VulnerabilityID": "CVE-2015-2104",
          "PkgID": "python3-pyc@3.11.8-r0",
          "PkgName": "python3-pyc",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/python3-pyc@3.11.8-r0?arch=x86_64\u0026distro=3.18.8",
            "UID": "2627c3a3a5829fff"
          },
          "InstalledVersion": "3.11.8-r0",
          "FixedVersion": "3.11.10-r0",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:e0438933db2c4dfc2590d009d4743559e822f88bcea754476741e383ec4ce873",
            "DiffID": "sha256:d33f2258ad03b38b1d5e0efa2162da1a50241a9053df12483bd9c4a740b031ab"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2015-2104",
          "DataSource": {
            "ID": "alpine",
            "Name": "Alpine Secdb",
            "URL": "https://secdb.alpinelinux.org/"
          },
          "Description": "Rejected reason: DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This candidate was withdrawn by its CNA. Further investigation showed that it was not a security issue. Notes: none",
          "Severity": "UNKNOWN",
          "PublishedDate": "2020-02-19T14:15:10.357Z",
          "LastModifiedDate": "2023-11-07T02:25:05.71Z"
        },
        {
          "VulnerabilityID": "CVE-2024-6232",
          "PkgID": "python3-pycache-pyc0@3.11.8-r0",
          "PkgName": "python3-pycache-pyc0",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/python3-pycache-pyc0@3.11.8-r0?arch=x86_64\u0026distro=3.18.8",
            "UID": "6ed950fb7c1f908b"
          },
          "InstalledVersion": "3.11.8-r0",
          "FixedVersion": "3.11.10-r0",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:e0438933db2c4dfc2590d009d4743559e822f88bcea754476741e383ec4ce873",
            "DiffID": "sha256:d33f2258ad03b38b1d5e0efa2162da1a50241a9053df12483bd9c4a740b031ab"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-6232",
          "DataSource": {
            "ID": "alpine",
            "Name": "Alpine Secdb",
            "URL": "https://secdb.alpinelinux.org/"
          },
          "Title": "python: cpython: tarfile: ReDos via excessive backtracking while parsing header values",
          "Description": "There is a MEDIUM severity vulnerability affecting CPython.\n\n\n\n\n\nRegular expressions that allowed excessive backtracking during tarfile.TarFile header parsing are vulnerable to ReDoS via specifically-crafted tar archives.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-1333"
          ],
          "VendorSeverity": {
            "nvd": 3,
            "redhat": 2,
            "ubuntu": 2
          },
          "CVSS": {
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
            "https://access.redhat.com/security/cve/CVE-2024-6232",
            "https://github.com/python/cpython/commit/4eaf4891c12589e3c7bdad5f5b076e4c8392dd06",
            "https://github.com/python/cpython/commit/743acbe872485dc18df4d8ab2dc7895187f062c4",
            "https://github.com/python/cpython/commit/7d1f50cd92ff7e10a1c15a8f591dde8a6843a64d",
            "https://github.com/python/cpython/commit/b4225ca91547aa97ed3aca391614afbb255bc877",
            "https://github.com/python/cpython/commit/d449caf8a179e3b954268b3a88eb9170be3c8fbf",
            "https://github.com/python/cpython/commit/ed3a49ea734ada357ff4442996fd4ae71d253373",
            "https://github.com/python/cpython/issues/121285",
            "https://github.com/python/cpython/pull/121286",
            "https://mail.python.org/archives/list/security-announce@python.org/thread/JRYFTPRHZRTLMZLWQEUHZSJXNHM4ACTY/",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-6232",
            "https://www.cve.org/CVERecord?id=CVE-2024-6232"
          ],
          "PublishedDate": "2024-09-03T13:15:05.363Z",
          "LastModifiedDate": "2024-09-04T21:15:14.48Z"
        },
        {
          "VulnerabilityID": "CVE-2024-7592",
          "PkgID": "python3-pycache-pyc0@3.11.8-r0",
          "PkgName": "python3-pycache-pyc0",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/python3-pycache-pyc0@3.11.8-r0?arch=x86_64\u0026distro=3.18.8",
            "UID": "6ed950fb7c1f908b"
          },
          "InstalledVersion": "3.11.8-r0",
          "FixedVersion": "3.11.10-r0",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:e0438933db2c4dfc2590d009d4743559e822f88bcea754476741e383ec4ce873",
            "DiffID": "sha256:d33f2258ad03b38b1d5e0efa2162da1a50241a9053df12483bd9c4a740b031ab"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-7592",
          "DataSource": {
            "ID": "alpine",
            "Name": "Alpine Secdb",
            "URL": "https://secdb.alpinelinux.org/"
          },
          "Title": "cpython: python: Uncontrolled CPU resource consumption when in http.cookies module",
          "Description": "There is a LOW severity vulnerability affecting CPython, specifically the\n'http.cookies' standard library module.\n\n\nWhen parsing cookies that contained backslashes for quoted characters in\nthe cookie value, the parser would use an algorithm with quadratic\ncomplexity, resulting in excess CPU resources being used while parsing the\nvalue.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-1333",
            "CWE-400"
          ],
          "VendorSeverity": {
            "azure": 3,
            "cbl-mariner": 3,
            "nvd": 3,
            "redhat": 1,
            "ubuntu": 1
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 7.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:N/I:N/A:H",
              "V3Score": 4.8
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2024-7592",
            "https://github.com/python/cpython/commit/391e5626e3ee5af267b97e37abc7475732e67621",
            "https://github.com/python/cpython/commit/a77ab24427a18bff817025adb03ca920dc3f1a06",
            "https://github.com/python/cpython/commit/b2f11ca7667e4d57c71c1c88b255115f16042d9a",
            "https://github.com/python/cpython/commit/d4ac921a4b081f7f996a5d2b101684b67ba0ed7f",
            "https://github.com/python/cpython/commit/d662e2db2605515a767f88ad48096b8ac623c774",
            "https://github.com/python/cpython/commit/dcc3eaef98cd94d6cb6cb0f44bd1c903d04f33b1",
            "https://github.com/python/cpython/issues/123067",
            "https://github.com/python/cpython/pull/123075",
            "https://mail.python.org/archives/list/security-announce@python.org/thread/HXJAAAALNUNGCQUS2W7WR6GFIZIHFOOK/",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-7592",
            "https://www.cve.org/CVERecord?id=CVE-2024-7592"
          ],
          "PublishedDate": "2024-08-19T19:15:08.18Z",
          "LastModifiedDate": "2024-09-04T21:15:14.643Z"
        },
        {
          "VulnerabilityID": "CVE-2023-27043",
          "PkgID": "python3-pycache-pyc0@3.11.8-r0",
          "PkgName": "python3-pycache-pyc0",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/python3-pycache-pyc0@3.11.8-r0?arch=x86_64\u0026distro=3.18.8",
            "UID": "6ed950fb7c1f908b"
          },
          "InstalledVersion": "3.11.8-r0",
          "FixedVersion": "3.11.10-r0",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:e0438933db2c4dfc2590d009d4743559e822f88bcea754476741e383ec4ce873",
            "DiffID": "sha256:d33f2258ad03b38b1d5e0efa2162da1a50241a9053df12483bd9c4a740b031ab"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-27043",
          "DataSource": {
            "ID": "alpine",
            "Name": "Alpine Secdb",
            "URL": "https://secdb.alpinelinux.org/"
          },
          "Title": "python: Parsing errors in email/_parseaddr.py lead to incorrect value in email address part of tuple",
          "Description": "The email module of Python through 3.11.3 incorrectly parses e-mail addresses that contain a special character. The wrong portion of an RFC2822 header is identified as the value of the addr-spec. In some applications, an attacker can bypass a protection mechanism in which application access is granted only after verifying receipt of e-mail to a specific domain (e.g., only @company.example.com addresses may be used for signup). This occurs in email/_parseaddr.py in recent versions of Python.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-20"
          ],
          "VendorSeverity": {
            "alma": 2,
            "amazon": 2,
            "bitnami": 2,
            "nvd": 2,
            "oracle-oval": 2,
            "photon": 2,
            "redhat": 2,
            "rocky": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "bitnami": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
              "V3Score": 5.3
            },
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
              "V3Score": 5.3
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
              "V3Score": 5.3
            }
          },
          "References": [
            "http://python.org",
            "https://access.redhat.com/articles/7051467",
            "https://access.redhat.com/errata/RHSA-2024:2292",
            "https://access.redhat.com/security/cve/CVE-2023-27043",
            "https://bugzilla.redhat.com/2196183",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2196183",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-27043",
            "https://errata.almalinux.org/9/ALSA-2024-2292.html",
            "https://errata.rockylinux.org/RLSA-2024:0256",
            "https://github.com/python/cpython/issues/102988",
            "https://github.com/python/cpython/pull/102990",
            "https://github.com/python/cpython/pull/105127",
            "https://linux.oracle.com/cve/CVE-2023-27043.html",
            "https://linux.oracle.com/errata/ELSA-2024-3062.html",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/4ZAEFSFZDNBNJPNOUTLG5COISGQDLMGV/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/75DTHSTNOFFNAWHXKMDXS7EJWC6W2FUC/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/ARI7VDSNTQVXRQFM6IK5GSSLEIYV4VZH/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/BQAKLUJMHFGVBRDPEY57BJGNCE5UUPHW/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/HXYVPEZUA3465AEFX5JVFVP7KIFZMF3N/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/N6M5I6OQHJABNEYY555HUMMKX3Y4P25Z/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/NEUNZSZ3CVSM2QWVYH3N2XGOCDWNYUA3/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/ORLXS5YTKN65E2Q2NWKXMFS5FWQHRNZW/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/P2MAICLFDDO3QVNHTZ2OCERZQ34R2PIC/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/P2W2BZQIHMCKRI5FNBJERFYMS5PK6TAH/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/PHVGRKQAGANCSGFI3QMYOCIMS4IFOZA5/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/PU6Y2S5CBN5BWCBDAJFTGIBZLK3S2G3J/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/QDRDDPDN3VFIYXJIYEABY6USX5EU66AG/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/RDDC2VOX7OQC6OHMYTVD4HLFZIV6PYBC/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/SINP4OVYNB2AGDYI2GS37EMW3H3F7XPZ/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/SOX7BCN6YL7B3RFPEEXPIU5CMTEHJOKR/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/VZXC32CJ7TWDPJO6GY2XIQRO7JZX5FLP/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/XWMBD4LNHWEXRI6YVFWJMTJQUL5WOFTS/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/YQVY5C5REXWJIORJIL2FIL3ALOEJEF72/",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-27043",
            "https://python-security.readthedocs.io/vuln/email-parseaddr-realname.html",
            "https://security.netapp.com/advisory/ntap-20230601-0003/",
            "https://www.cve.org/CVERecord?id=CVE-2023-27043"
          ],
          "PublishedDate": "2023-04-19T00:15:07.973Z",
          "LastModifiedDate": "2024-02-26T16:27:45.78Z"
        },
        {
          "VulnerabilityID": "CVE-2024-6923",
          "PkgID": "python3-pycache-pyc0@3.11.8-r0",
          "PkgName": "python3-pycache-pyc0",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/python3-pycache-pyc0@3.11.8-r0?arch=x86_64\u0026distro=3.18.8",
            "UID": "6ed950fb7c1f908b"
          },
          "InstalledVersion": "3.11.8-r0",
          "FixedVersion": "3.11.10-r0",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:e0438933db2c4dfc2590d009d4743559e822f88bcea754476741e383ec4ce873",
            "DiffID": "sha256:d33f2258ad03b38b1d5e0efa2162da1a50241a9053df12483bd9c4a740b031ab"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-6923",
          "DataSource": {
            "ID": "alpine",
            "Name": "Alpine Secdb",
            "URL": "https://secdb.alpinelinux.org/"
          },
          "Title": "cpython: python: email module doesn't properly quotes newlines in email headers, allowing header injection",
          "Description": "There is a MEDIUM severity vulnerability affecting CPython.\n\nThe \nemail module didn’t properly quote newlines for email headers when \nserializing an email message allowing for header injection when an email\n is serialized.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-94"
          ],
          "VendorSeverity": {
            "alma": 2,
            "bitnami": 2,
            "oracle-oval": 2,
            "photon": 2,
            "redhat": 2
          },
          "CVSS": {
            "bitnami": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:L",
              "V3Score": 5.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N",
              "V3Score": 6.8
            }
          },
          "References": [
            "https://access.redhat.com/errata/RHSA-2024:6179",
            "https://access.redhat.com/security/cve/CVE-2024-6923",
            "https://bugzilla.redhat.com/2302255",
            "https://errata.almalinux.org/9/ALSA-2024-6179.html",
            "https://github.com/python/cpython/commit/06f28dc236708f72871c64d4bc4b4ea144c50147",
            "https://github.com/python/cpython/commit/4766d1200fdf8b6728137aa2927a297e224d5fa7",
            "https://github.com/python/cpython/commit/4aaa4259b5a6e664b7316a4d60bdec7ee0f124d0",
            "https://github.com/python/cpython/commit/b158a76ce094897c870fb6b3de62887b7ccc33f1",
            "https://github.com/python/cpython/commit/f7be505d137a22528cb0fc004422c0081d5d90e6",
            "https://github.com/python/cpython/commit/f7c0f09e69e950cf3c5ada9dbde93898eb975533",
            "https://github.com/python/cpython/issues/121650",
            "https://github.com/python/cpython/pull/122233",
            "https://linux.oracle.com/cve/CVE-2024-6923.html",
            "https://linux.oracle.com/errata/ELSA-2024-6179.html",
            "https://mail.python.org/archives/list/security-announce@python.org/thread/QH3BUOE2DYQBWP7NAQ7UNHPPOELKISRW/",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-6923",
            "https://www.cve.org/CVERecord?id=CVE-2024-6923"
          ],
          "PublishedDate": "2024-08-01T14:15:03.647Z",
          "LastModifiedDate": "2024-09-04T21:15:14.567Z"
        },
        {
          "VulnerabilityID": "CVE-2024-8088",
          "PkgID": "python3-pycache-pyc0@3.11.8-r0",
          "PkgName": "python3-pycache-pyc0",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/python3-pycache-pyc0@3.11.8-r0?arch=x86_64\u0026distro=3.18.8",
            "UID": "6ed950fb7c1f908b"
          },
          "InstalledVersion": "3.11.8-r0",
          "FixedVersion": "3.11.8-r1",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:e0438933db2c4dfc2590d009d4743559e822f88bcea754476741e383ec4ce873",
            "DiffID": "sha256:d33f2258ad03b38b1d5e0efa2162da1a50241a9053df12483bd9c4a740b031ab"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-8088",
          "DataSource": {
            "ID": "alpine",
            "Name": "Alpine Secdb",
            "URL": "https://secdb.alpinelinux.org/"
          },
          "Title": "python: cpython: Iterating over a malicious ZIP file may lead to Denial of Service",
          "Description": "There is a HIGH severity vulnerability affecting the CPython \"zipfile\"\nmodule affecting \"zipfile.Path\". Note that the more common API \"zipfile.ZipFile\" class is unaffected.\n\n\n\n\n\nWhen iterating over names of entries in a zip archive (for example, methods\nof \"zipfile.Path\" like \"namelist()\", \"iterdir()\", etc)\nthe process can be put into an infinite loop with a maliciously crafted\nzip archive. This defect applies when reading only metadata or extracting\nthe contents of the zip archive. Programs that are not handling\nuser-controlled zip archives are not affected.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-835"
          ],
          "VendorSeverity": {
            "alma": 2,
            "oracle-oval": 2,
            "redhat": 2
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:H",
              "V3Score": 5.3
            }
          },
          "References": [
            "https://access.redhat.com/errata/RHSA-2024:5962",
            "https://access.redhat.com/security/cve/CVE-2024-8088",
            "https://bugzilla.redhat.com/2292921",
            "https://bugzilla.redhat.com/2297771",
            "https://bugzilla.redhat.com/2302255",
            "https://bugzilla.redhat.com/2307370",
            "https://errata.almalinux.org/8/ALSA-2024-5962.html",
            "https://github.com/python/cpython/commit/0aa1ee22ab6e204e9d3d0e9dd63ea648ed691ef1",
            "https://github.com/python/cpython/commit/2231286d78d328c2f575e0b05b16fe447d1656d6",
            "https://github.com/python/cpython/commit/795f2597a4be988e2bb19b69ff9958e981cb894e",
            "https://github.com/python/cpython/commit/7bc367e464ce50b956dd232c1dfa1cad4e7fb814",
            "https://github.com/python/cpython/commit/7e8883a3f04d308302361aeffc73e0e9837f19d4",
            "https://github.com/python/cpython/commit/8c7348939d8a3ecd79d630075f6be1b0c5b41f64",
            "https://github.com/python/cpython/commit/95b073bddefa6243effa08e131e297c0383e7f6a",
            "https://github.com/python/cpython/commit/962055268ed4f2ca1d717bfc8b6385de50a23ab7",
            "https://github.com/python/cpython/commit/dcc5182f27c1500006a1ef78e10613bb45788dea",
            "https://github.com/python/cpython/commit/e0264a61119d551658d9445af38323ba94fc16db",
            "https://github.com/python/cpython/commit/fc0b8259e693caa8400fa8b6ac1e494e47ea7798",
            "https://github.com/python/cpython/issues/122905",
            "https://github.com/python/cpython/issues/123270",
            "https://github.com/python/cpython/pull/122906",
            "https://linux.oracle.com/cve/CVE-2024-8088.html",
            "https://linux.oracle.com/errata/ELSA-2024-5962.html",
            "https://mail.python.org/archives/list/security-announce@python.org/thread/GNFCKVI4TCATKQLALJ5SN4L4CSPSMILU/",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-8088",
            "https://www.cve.org/CVERecord?id=CVE-2024-8088"
          ],
          "PublishedDate": "2024-08-22T19:15:09.72Z",
          "LastModifiedDate": "2024-09-04T23:15:13.1Z"
        },
        {
          "VulnerabilityID": "CVE-2024-4032",
          "PkgID": "python3-pycache-pyc0@3.11.8-r0",
          "PkgName": "python3-pycache-pyc0",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/python3-pycache-pyc0@3.11.8-r0?arch=x86_64\u0026distro=3.18.8",
            "UID": "6ed950fb7c1f908b"
          },
          "InstalledVersion": "3.11.8-r0",
          "FixedVersion": "3.11.10-r0",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:e0438933db2c4dfc2590d009d4743559e822f88bcea754476741e383ec4ce873",
            "DiffID": "sha256:d33f2258ad03b38b1d5e0efa2162da1a50241a9053df12483bd9c4a740b031ab"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-4032",
          "DataSource": {
            "ID": "alpine",
            "Name": "Alpine Secdb",
            "URL": "https://secdb.alpinelinux.org/"
          },
          "Title": "python: incorrect IPv4 and IPv6 private ranges",
          "Description": "The “ipaddress” module contained incorrect information about whether certain IPv4 and IPv6 addresses were designated as “globally reachable” or “private”. This affected the is_private and is_global properties of the ipaddress.IPv4Address, ipaddress.IPv4Network, ipaddress.IPv6Address, and ipaddress.IPv6Network classes, where values wouldn’t be returned in accordance with the latest information from the IANA Special-Purpose Address Registries.\n\nCPython 3.12.4 and 3.13.0a6 contain updated information from these registries and thus have the intended behavior.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-697"
          ],
          "VendorSeverity": {
            "alma": 1,
            "bitnami": 3,
            "oracle-oval": 2,
            "photon": 1,
            "redhat": 1,
            "ubuntu": 1
          },
          "CVSS": {
            "bitnami": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
              "V3Score": 7.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L",
              "V3Score": 3.7
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2024/06/17/3",
            "https://access.redhat.com/errata/RHSA-2024:4779",
            "https://access.redhat.com/security/cve/CVE-2024-4032",
            "https://bugzilla.redhat.com/2292921",
            "https://errata.almalinux.org/9/ALSA-2024-4779.html",
            "https://github.com/advisories/GHSA-mh6q-v4mp-2cc7",
            "https://github.com/python/cpython/commit/22adf29da8d99933ffed8647d3e0726edd16f7f8",
            "https://github.com/python/cpython/commit/40d75c2b7f5c67e254d0a025e0f2e2c7ada7f69f",
            "https://github.com/python/cpython/commit/40d75c2b7f5c67e254d0a025e0f2e2c7ada7f69f (3.13)",
            "https://github.com/python/cpython/commit/895f7e2ac23eff4743143beef0f0c5ac71ea27d3",
            "https://github.com/python/cpython/commit/ba431579efdcbaed7a96f2ac4ea0775879a332fb",
            "https://github.com/python/cpython/commit/c62c9e518b784fe44432a3f4fc265fb95b651906",
            "https://github.com/python/cpython/commit/f86b17ac511e68192ba71f27e752321a3252cee3",
            "https://github.com/python/cpython/issues/113171",
            "https://github.com/python/cpython/pull/113179",
            "https://linux.oracle.com/cve/CVE-2024-4032.html",
            "https://linux.oracle.com/errata/ELSA-2024-5962.html",
            "https://mail.python.org/archives/list/security-announce@python.org/thread/NRUHDUS2IV2USIZM2CVMSFL6SCKU3RZA/",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-4032",
            "https://security.netapp.com/advisory/ntap-20240726-0004/",
            "https://ubuntu.com/security/notices/USN-6928-1",
            "https://ubuntu.com/security/notices/USN-6941-1",
            "https://www.cve.org/CVERecord?id=CVE-2024-4032",
            "https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml",
            "https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml"
          ],
          "PublishedDate": "2024-06-17T15:15:52.517Z",
          "LastModifiedDate": "2024-08-29T21:35:11.017Z"
        },
        {
          "VulnerabilityID": "CVE-2015-2104",
          "PkgID": "python3-pycache-pyc0@3.11.8-r0",
          "PkgName": "python3-pycache-pyc0",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/python3-pycache-pyc0@3.11.8-r0?arch=x86_64\u0026distro=3.18.8",
            "UID": "6ed950fb7c1f908b"
          },
          "InstalledVersion": "3.11.8-r0",
          "FixedVersion": "3.11.10-r0",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:e0438933db2c4dfc2590d009d4743559e822f88bcea754476741e383ec4ce873",
            "DiffID": "sha256:d33f2258ad03b38b1d5e0efa2162da1a50241a9053df12483bd9c4a740b031ab"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2015-2104",
          "DataSource": {
            "ID": "alpine",
            "Name": "Alpine Secdb",
            "URL": "https://secdb.alpinelinux.org/"
          },
          "Description": "Rejected reason: DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This candidate was withdrawn by its CNA. Further investigation showed that it was not a security issue. Notes: none",
          "Severity": "UNKNOWN",
          "PublishedDate": "2020-02-19T14:15:10.357Z",
          "LastModifiedDate": "2023-11-07T02:25:05.71Z"
        }
      ]
    },
    {
      "Target": "usr/local/bin/msync",
      "Class": "lang-pkgs",
      "Type": "gobinary",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2024-34156",
          "PkgName": "stdlib",
          "PkgIdentifier": {
            "PURL": "pkg:golang/stdlib@1.22.5",
            "UID": "c3c40d0bffb22ee6"
          },
          "InstalledVersion": "1.22.5",
          "FixedVersion": "1.22.7, 1.23.1",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:bb0b32e259979a43d8e4e6d7c4601e746c34cb4aab020501328a8dbcd9b37c7e",
            "DiffID": "sha256:f7f24e1ff9a307f673cfbe0f50d95657b6afeb6f16a462ea7e7342c9a6383279"
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
          "VulnerabilityID": "CVE-2024-34155",
          "PkgName": "stdlib",
          "PkgIdentifier": {
            "PURL": "pkg:golang/stdlib@1.22.5",
            "UID": "c3c40d0bffb22ee6"
          },
          "InstalledVersion": "1.22.5",
          "FixedVersion": "1.22.7, 1.23.1",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:bb0b32e259979a43d8e4e6d7c4601e746c34cb4aab020501328a8dbcd9b37c7e",
            "DiffID": "sha256:f7f24e1ff9a307f673cfbe0f50d95657b6afeb6f16a462ea7e7342c9a6383279"
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
            "PURL": "pkg:golang/stdlib@1.22.5",
            "UID": "c3c40d0bffb22ee6"
          },
          "InstalledVersion": "1.22.5",
          "FixedVersion": "1.22.7, 1.23.1",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:bb0b32e259979a43d8e4e6d7c4601e746c34cb4aab020501328a8dbcd9b37c7e",
            "DiffID": "sha256:f7f24e1ff9a307f673cfbe0f50d95657b6afeb6f16a462ea7e7342c9a6383279"
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
    },
    {
      "Target": "/etc/msync/server.key",
      "Class": "secret",
      "Secrets": [
        {
          "RuleID": "private-key",
          "Category": "AsymmetricPrivateKey",
          "Severity": "HIGH",
          "Title": "Asymmetric Private Key",
          "StartLine": 1,
          "EndLine": 1,
          "Code": {
            "Lines": [
              {
                "Number": 1,
                "Content": "-----BEGIN PRIVATE KEY-----*******************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************-----END PRIVATE KEY",
                "IsCause": true,
                "Annotation": "",
                "Truncated": false,
                "Highlighted": "-----BEGIN PRIVATE KEY-----*******************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************-----END PRIVATE KEY",
                "FirstCause": true,
                "LastCause": true
              },
              {
                "Number": 2,
                "Content": "",
                "IsCause": false,
                "Annotation": "",
                "Truncated": false,
                "FirstCause": false,
                "LastCause": false
              }
            ]
          },
          "Match": "-----BEGIN PRIVATE KEY-----*******************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************-----END PRIVATE KEY",
          "Layer": {
            "Digest": "sha256:938adefa1b9db91ba51b5c7faab01c4e6b604ff101212ba13a7fdda99e79dfd5",
            "DiffID": "sha256:23346767531ca7d8ee4ef3b7542a96fc338810fe4491871c93644d945772e5dc",
            "CreatedBy": "COPY server.key /etc/msync/server.key # buildkit"
          }
        }
      ]
    }
  ]
}
