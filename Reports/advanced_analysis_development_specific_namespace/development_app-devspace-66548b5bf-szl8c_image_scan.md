2024-09-15T11:52:12+02:00	INFO	[vuln] Vulnerability scanning is enabled
2024-09-15T11:52:12+02:00	INFO	[secret] Secret scanning is enabled
2024-09-15T11:52:12+02:00	INFO	[secret] If your scanning is slow, please try '--scanners vuln' to disable secret scanning
2024-09-15T11:52:12+02:00	INFO	[secret] Please see also https://aquasecurity.github.io/trivy/v0.55/docs/scanner/secret#recommendation for faster secret detection
2024-09-15T11:52:13+02:00	INFO	[python] License acquired from METADATA classifiers may be subject to additional terms	name="pip" version="24.0"
2024-09-15T11:52:14+02:00	INFO	Detected OS	family="alpine" version="3.19.1"
2024-09-15T11:52:14+02:00	INFO	[alpine] Detecting vulnerabilities...	os_version="3.19" repository="3.19" pkg_num=74
2024-09-15T11:52:14+02:00	INFO	Number of language-specific files	num=5
2024-09-15T11:52:14+02:00	INFO	[gobinary] Detecting vulnerabilities...
2024-09-15T11:52:14+02:00	INFO	[python-pkg] Detecting vulnerabilities...
2024-09-15T11:52:14+02:00	INFO	[node-pkg] Detecting vulnerabilities...
2024-09-15T11:52:14+02:00	WARN	Using severities from other vendors for some vulnerabilities. Read https://aquasecurity.github.io/trivy/v0.55/docs/scanner/vulnerability#severity-selection for details.
{
  "SchemaVersion": 2,
  "CreatedAt": "2024-09-15T11:52:14.457662+02:00",
  "ArtifactName": "ghcr.io/loft-sh/devspace-containers/python:3-alpine",
  "ArtifactType": "container_image",
  "Metadata": {
    "OS": {
      "Family": "alpine",
      "Name": "3.19.1"
    },
    "ImageID": "sha256:d3f7110447c9cd555077b4b4a43a89b801d5981f509d1357a749a8aa0ba2d9d6",
    "DiffIDs": [
      "sha256:b09314aec293bcd9a8ee5e643539437b3846f9e5e55f79e282e5f67e3026de5e",
      "sha256:c5abfaf05e68b157ee1767d6415983d7987e32efea2b90f52db4ddd95f7c070c",
      "sha256:1fe037e9153d3390f9f6f775c05084cc49c55877b3785a00de5510f977aae8aa",
      "sha256:e6cc2e27a4e31fabe6b83fc5c64e59b531921fe75c0eddc1fb0248da0c593841",
      "sha256:23b346ea16dd47905c76b6dbd5602af34324bd16ab0844b10914337226a5d193",
      "sha256:38f45d95946e8f60aec438af7ade427eed8ef63ab3d462c0615273fbf60f5025",
      "sha256:c35d41b66b2428ad976e2931ba2b12aa8ac674c445e70b88b65cfcf1c2e011c4",
      "sha256:53a2763a2f061ad8aa06c347fd3029b89e1b7d6b56be8d0df8e63fc8da00ef02"
    ],
    "RepoTags": [
      "ghcr.io/loft-sh/devspace-containers/python:3-alpine"
    ],
    "RepoDigests": [
      "ghcr.io/loft-sh/devspace-containers/python@sha256:d3f7110447c9cd555077b4b4a43a89b801d5981f509d1357a749a8aa0ba2d9d6"
    ],
    "ImageConfig": {
      "architecture": "arm64",
      "created": "2024-04-25T09:21:02.361754562Z",
      "docker_version": "26.1.1",
      "history": [
        {
          "created": "2024-01-26T23:44:47Z",
          "created_by": "/bin/sh -c #(nop) ADD file:d0764a717d1e9d0aff3fa84779b11bfa0afe4430dcb6b46d965b209167639ba0 in / "
        },
        {
          "created": "2024-01-26T23:44:47Z",
          "created_by": "/bin/sh -c #(nop)  CMD [\"/bin/sh\"]",
          "empty_layer": true
        },
        {
          "created": "2024-04-09T15:49:24Z",
          "created_by": "ENV PATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
          "comment": "buildkit.dockerfile.v0",
          "empty_layer": true
        },
        {
          "created": "2024-04-09T15:49:24Z",
          "created_by": "ENV LANG=C.UTF-8",
          "comment": "buildkit.dockerfile.v0",
          "empty_layer": true
        },
        {
          "created": "2024-04-09T15:49:24Z",
          "created_by": "RUN /bin/sh -c set -eux; \tapk add --no-cache \t\tca-certificates \t\ttzdata \t; # buildkit",
          "comment": "buildkit.dockerfile.v0"
        },
        {
          "created": "2024-04-09T15:49:24Z",
          "created_by": "ENV GPG_KEY=7169605F62C751356D054A26A821E680E5FA6305",
          "comment": "buildkit.dockerfile.v0",
          "empty_layer": true
        },
        {
          "created": "2024-04-09T15:49:24Z",
          "created_by": "ENV PYTHON_VERSION=3.12.3",
          "comment": "buildkit.dockerfile.v0",
          "empty_layer": true
        },
        {
          "created": "2024-04-09T15:49:24Z",
          "created_by": "RUN /bin/sh -c set -eux; \t\tapk add --no-cache --virtual .build-deps \t\tgnupg \t\ttar \t\txz \t\t\t\tbluez-dev \t\tbzip2-dev \t\tdpkg-dev dpkg \t\texpat-dev \t\tfindutils \t\tgcc \t\tgdbm-dev \t\tlibc-dev \t\tlibffi-dev \t\tlibnsl-dev \t\tlibtirpc-dev \t\tlinux-headers \t\tmake \t\tncurses-dev \t\topenssl-dev \t\tpax-utils \t\treadline-dev \t\tsqlite-dev \t\ttcl-dev \t\ttk \t\ttk-dev \t\tutil-linux-dev \t\txz-dev \t\tzlib-dev \t; \t\twget -O python.tar.xz \"https://www.python.org/ftp/python/${PYTHON_VERSION%%[a-z]*}/Python-$PYTHON_VERSION.tar.xz\"; \twget -O python.tar.xz.asc \"https://www.python.org/ftp/python/${PYTHON_VERSION%%[a-z]*}/Python-$PYTHON_VERSION.tar.xz.asc\"; \tGNUPGHOME=\"$(mktemp -d)\"; export GNUPGHOME; \tgpg --batch --keyserver hkps://keys.openpgp.org --recv-keys \"$GPG_KEY\"; \tgpg --batch --verify python.tar.xz.asc python.tar.xz; \tgpgconf --kill all; \trm -rf \"$GNUPGHOME\" python.tar.xz.asc; \tmkdir -p /usr/src/python; \ttar --extract --directory /usr/src/python --strip-components=1 --file python.tar.xz; \trm python.tar.xz; \t\tcd /usr/src/python; \tgnuArch=\"$(dpkg-architecture --query DEB_BUILD_GNU_TYPE)\"; \t./configure \t\t--build=\"$gnuArch\" \t\t--enable-loadable-sqlite-extensions \t\t--enable-optimizations \t\t--enable-option-checking=fatal \t\t--enable-shared \t\t--with-lto \t\t--with-system-expat \t\t--without-ensurepip \t; \tnproc=\"$(nproc)\"; \tEXTRA_CFLAGS=\"-DTHREAD_STACK_SIZE=0x100000\"; \tLDFLAGS=\"${LDFLAGS:--Wl},--strip-all\"; \tmake -j \"$nproc\" \t\t\"EXTRA_CFLAGS=${EXTRA_CFLAGS:-}\" \t\t\"LDFLAGS=${LDFLAGS:-}\" \t\t\"PROFILE_TASK=${PROFILE_TASK:-}\" \t; \trm python; \tmake -j \"$nproc\" \t\t\"EXTRA_CFLAGS=${EXTRA_CFLAGS:-}\" \t\t\"LDFLAGS=${LDFLAGS:--Wl},-rpath='\\$\\$ORIGIN/../lib'\" \t\t\"PROFILE_TASK=${PROFILE_TASK:-}\" \t\tpython \t; \tmake install; \t\tcd /; \trm -rf /usr/src/python; \t\tfind /usr/local -depth \t\t\\( \t\t\t\\( -type d -a \\( -name test -o -name tests -o -name idle_test \\) \\) \t\t\t-o \\( -type f -a \\( -name '*.pyc' -o -name '*.pyo' -o -name 'libpython*.a' \\) \\) \t\t\\) -exec rm -rf '{}' + \t; \t\tfind /usr/local -type f -executable -not \\( -name '*tkinter*' \\) -exec scanelf --needed --nobanner --format '%n#p' '{}' ';' \t\t| tr ',' '\\n' \t\t| sort -u \t\t| awk 'system(\"[ -e /usr/local/lib/\" $1 \" ]\") == 0 { next } { print \"so:\" $1 }' \t\t| xargs -rt apk add --no-network --virtual .python-rundeps \t; \tapk del --no-network .build-deps; \t\tpython3 --version # buildkit",
          "comment": "buildkit.dockerfile.v0"
        },
        {
          "created": "2024-04-09T15:49:24Z",
          "created_by": "RUN /bin/sh -c set -eux; \tfor src in idle3 pydoc3 python3 python3-config; do \t\tdst=\"$(echo \"$src\" | tr -d 3)\"; \t\t[ -s \"/usr/local/bin/$src\" ]; \t\t[ ! -e \"/usr/local/bin/$dst\" ]; \t\tln -svT \"$src\" \"/usr/local/bin/$dst\"; \tdone # buildkit",
          "comment": "buildkit.dockerfile.v0"
        },
        {
          "created": "2024-04-09T15:49:24Z",
          "created_by": "ENV PYTHON_PIP_VERSION=24.0",
          "comment": "buildkit.dockerfile.v0",
          "empty_layer": true
        },
        {
          "created": "2024-04-09T15:49:24Z",
          "created_by": "ENV PYTHON_GET_PIP_URL=https://github.com/pypa/get-pip/raw/dbf0c85f76fb6e1ab42aa672ffca6f0a675d9ee4/public/get-pip.py",
          "comment": "buildkit.dockerfile.v0",
          "empty_layer": true
        },
        {
          "created": "2024-04-09T15:49:24Z",
          "created_by": "ENV PYTHON_GET_PIP_SHA256=dfe9fd5c28dc98b5ac17979a953ea550cec37ae1b47a5116007395bfacff2ab9",
          "comment": "buildkit.dockerfile.v0",
          "empty_layer": true
        },
        {
          "created": "2024-04-09T15:49:24Z",
          "created_by": "RUN /bin/sh -c set -eux; \t\twget -O get-pip.py \"$PYTHON_GET_PIP_URL\"; \techo \"$PYTHON_GET_PIP_SHA256 *get-pip.py\" | sha256sum -c -; \t\texport PYTHONDONTWRITEBYTECODE=1; \t\tpython get-pip.py \t\t--disable-pip-version-check \t\t--no-cache-dir \t\t--no-compile \t\t\"pip==$PYTHON_PIP_VERSION\" \t; \trm -f get-pip.py; \t\tpip --version # buildkit",
          "comment": "buildkit.dockerfile.v0"
        },
        {
          "created": "2024-04-09T15:49:24Z",
          "created_by": "CMD [\"python3\"]",
          "comment": "buildkit.dockerfile.v0",
          "empty_layer": true
        },
        {
          "created": "2024-04-25T09:20:31Z",
          "created_by": "WORKDIR /app",
          "comment": "buildkit.dockerfile.v0"
        },
        {
          "created": "2024-04-25T09:20:31Z",
          "created_by": "ADD install_tooling.sh . # buildkit",
          "comment": "buildkit.dockerfile.v0"
        },
        {
          "created": "2024-04-25T09:21:02Z",
          "created_by": "RUN /bin/sh -c chmod +x install_tooling.sh \u0026\u0026 ./install_tooling.sh \u0026\u0026 rm install_tooling.sh # buildkit",
          "comment": "buildkit.dockerfile.v0"
        }
      ],
      "os": "linux",
      "rootfs": {
        "type": "layers",
        "diff_ids": [
          "sha256:b09314aec293bcd9a8ee5e643539437b3846f9e5e55f79e282e5f67e3026de5e",
          "sha256:c5abfaf05e68b157ee1767d6415983d7987e32efea2b90f52db4ddd95f7c070c",
          "sha256:1fe037e9153d3390f9f6f775c05084cc49c55877b3785a00de5510f977aae8aa",
          "sha256:e6cc2e27a4e31fabe6b83fc5c64e59b531921fe75c0eddc1fb0248da0c593841",
          "sha256:23b346ea16dd47905c76b6dbd5602af34324bd16ab0844b10914337226a5d193",
          "sha256:38f45d95946e8f60aec438af7ade427eed8ef63ab3d462c0615273fbf60f5025",
          "sha256:c35d41b66b2428ad976e2931ba2b12aa8ac674c445e70b88b65cfcf1c2e011c4",
          "sha256:53a2763a2f061ad8aa06c347fd3029b89e1b7d6b56be8d0df8e63fc8da00ef02"
        ]
      },
      "config": {
        "Cmd": [
          "python3"
        ],
        "Env": [
          "PATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
          "LANG=C.UTF-8",
          "GPG_KEY=7169605F62C751356D054A26A821E680E5FA6305",
          "PYTHON_VERSION=3.12.3",
          "PYTHON_PIP_VERSION=24.0",
          "PYTHON_GET_PIP_URL=https://github.com/pypa/get-pip/raw/dbf0c85f76fb6e1ab42aa672ffca6f0a675d9ee4/public/get-pip.py",
          "PYTHON_GET_PIP_SHA256=dfe9fd5c28dc98b5ac17979a953ea550cec37ae1b47a5116007395bfacff2ab9"
        ],
        "WorkingDir": "/app",
        "ArgsEscaped": true
      }
    }
  },
  "Results": [
    {
      "Target": "ghcr.io/loft-sh/devspace-containers/python:3-alpine (alpine 3.19.1)",
      "Class": "os-pkgs",
      "Type": "alpine",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2023-42363",
          "PkgID": "busybox@1.36.1-r15",
          "PkgName": "busybox",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/busybox@1.36.1-r15?arch=aarch64\u0026distro=3.19.1",
            "UID": "9cfed348c81ed164"
          },
          "InstalledVersion": "1.36.1-r15",
          "FixedVersion": "1.36.1-r17",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:bca4290a96390d7a6fc6f2f9929370d06f8dfcacba591c76e3d5c5044e7f420c",
            "DiffID": "sha256:b09314aec293bcd9a8ee5e643539437b3846f9e5e55f79e282e5f67e3026de5e"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-42363",
          "DataSource": {
            "ID": "alpine",
            "Name": "Alpine Secdb",
            "URL": "https://secdb.alpinelinux.org/"
          },
          "Title": "busybox: use-after-free in awk",
          "Description": "A use-after-free vulnerability was discovered in xasprintf function in xfuncs_printf.c:344 in BusyBox v.1.36.1.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-416"
          ],
          "VendorSeverity": {
            "azure": 2,
            "cbl-mariner": 2,
            "nvd": 2,
            "redhat": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
              "V3Score": 5.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
              "V3Score": 7.8
            }
          },
          "References": [
            "http://lists.busybox.net/pipermail/busybox/2024-May/090760.html",
            "https://access.redhat.com/security/cve/CVE-2023-42363",
            "https://bugs.busybox.net/show_bug.cgi?id=15865",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-42363",
            "https://ubuntu.com/security/notices/USN-6961-1",
            "https://www.cve.org/CVERecord?id=CVE-2023-42363"
          ],
          "PublishedDate": "2023-11-27T22:15:07.94Z",
          "LastModifiedDate": "2023-11-30T05:06:49.523Z"
        },
        {
          "VulnerabilityID": "CVE-2023-42364",
          "PkgID": "busybox@1.36.1-r15",
          "PkgName": "busybox",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/busybox@1.36.1-r15?arch=aarch64\u0026distro=3.19.1",
            "UID": "9cfed348c81ed164"
          },
          "InstalledVersion": "1.36.1-r15",
          "FixedVersion": "1.36.1-r19",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:bca4290a96390d7a6fc6f2f9929370d06f8dfcacba591c76e3d5c5044e7f420c",
            "DiffID": "sha256:b09314aec293bcd9a8ee5e643539437b3846f9e5e55f79e282e5f67e3026de5e"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-42364",
          "DataSource": {
            "ID": "alpine",
            "Name": "Alpine Secdb",
            "URL": "https://secdb.alpinelinux.org/"
          },
          "Title": "busybox: use-after-free",
          "Description": "A use-after-free vulnerability in BusyBox v.1.36.1 allows attackers to cause a denial of service via a crafted awk pattern in the awk.c evaluate function.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-416"
          ],
          "VendorSeverity": {
            "nvd": 2,
            "redhat": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
              "V3Score": 5.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
              "V3Score": 7.8
            }
          },
          "References": [
            "http://lists.busybox.net/pipermail/busybox/2024-May/090762.html",
            "https://access.redhat.com/security/cve/CVE-2023-42364",
            "https://bugs.busybox.net/show_bug.cgi?id=15868",
            "https://gitlab.alpinelinux.org/alpine/aports/-/blob/master/main/busybox/CVE-2023-42364-CVE-2023-42365.patch",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-42364",
            "https://ubuntu.com/security/notices/USN-6961-1",
            "https://www.cve.org/CVERecord?id=CVE-2023-42364"
          ],
          "PublishedDate": "2023-11-27T23:15:07.313Z",
          "LastModifiedDate": "2023-11-30T05:07:10.827Z"
        },
        {
          "VulnerabilityID": "CVE-2023-42365",
          "PkgID": "busybox@1.36.1-r15",
          "PkgName": "busybox",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/busybox@1.36.1-r15?arch=aarch64\u0026distro=3.19.1",
            "UID": "9cfed348c81ed164"
          },
          "InstalledVersion": "1.36.1-r15",
          "FixedVersion": "1.36.1-r19",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:bca4290a96390d7a6fc6f2f9929370d06f8dfcacba591c76e3d5c5044e7f420c",
            "DiffID": "sha256:b09314aec293bcd9a8ee5e643539437b3846f9e5e55f79e282e5f67e3026de5e"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-42365",
          "DataSource": {
            "ID": "alpine",
            "Name": "Alpine Secdb",
            "URL": "https://secdb.alpinelinux.org/"
          },
          "Title": "busybox: use-after-free",
          "Description": "A use-after-free vulnerability was discovered in BusyBox v.1.36.1 via a crafted awk pattern in the awk.c copyvar function.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-416"
          ],
          "VendorSeverity": {
            "azure": 2,
            "cbl-mariner": 2,
            "nvd": 2,
            "redhat": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
              "V3Score": 5.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
              "V3Score": 7.8
            }
          },
          "References": [
            "http://lists.busybox.net/pipermail/busybox/2024-May/090762.html",
            "https://access.redhat.com/security/cve/CVE-2023-42365",
            "https://bugs.busybox.net/show_bug.cgi?id=15871",
            "https://gitlab.alpinelinux.org/alpine/aports/-/blob/master/main/busybox/CVE-2023-42364-CVE-2023-42365.patch",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-42365",
            "https://ubuntu.com/security/notices/USN-6961-1",
            "https://www.cve.org/CVERecord?id=CVE-2023-42365"
          ],
          "PublishedDate": "2023-11-27T23:15:07.373Z",
          "LastModifiedDate": "2023-11-30T05:08:08.77Z"
        },
        {
          "VulnerabilityID": "CVE-2023-42366",
          "PkgID": "busybox@1.36.1-r15",
          "PkgName": "busybox",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/busybox@1.36.1-r15?arch=aarch64\u0026distro=3.19.1",
            "UID": "9cfed348c81ed164"
          },
          "InstalledVersion": "1.36.1-r15",
          "FixedVersion": "1.36.1-r16",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:bca4290a96390d7a6fc6f2f9929370d06f8dfcacba591c76e3d5c5044e7f420c",
            "DiffID": "sha256:b09314aec293bcd9a8ee5e643539437b3846f9e5e55f79e282e5f67e3026de5e"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-42366",
          "DataSource": {
            "ID": "alpine",
            "Name": "Alpine Secdb",
            "URL": "https://secdb.alpinelinux.org/"
          },
          "Title": "busybox: A heap-buffer-overflow",
          "Description": "A heap-buffer-overflow was discovered in BusyBox v.1.36.1 in the next_token function at awk.c:1159.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-787"
          ],
          "VendorSeverity": {
            "nvd": 2,
            "redhat": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
              "V3Score": 5.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H",
              "V3Score": 7.1
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2023-42366",
            "https://bugs.busybox.net/show_bug.cgi?id=15874",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-42366",
            "https://www.cve.org/CVERecord?id=CVE-2023-42366"
          ],
          "PublishedDate": "2023-11-27T23:15:07.42Z",
          "LastModifiedDate": "2023-11-30T05:08:23.197Z"
        },
        {
          "VulnerabilityID": "CVE-2023-42363",
          "PkgID": "busybox-binsh@1.36.1-r15",
          "PkgName": "busybox-binsh",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/busybox-binsh@1.36.1-r15?arch=aarch64\u0026distro=3.19.1",
            "UID": "c890c007ea4d67fd"
          },
          "InstalledVersion": "1.36.1-r15",
          "FixedVersion": "1.36.1-r17",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:bca4290a96390d7a6fc6f2f9929370d06f8dfcacba591c76e3d5c5044e7f420c",
            "DiffID": "sha256:b09314aec293bcd9a8ee5e643539437b3846f9e5e55f79e282e5f67e3026de5e"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-42363",
          "DataSource": {
            "ID": "alpine",
            "Name": "Alpine Secdb",
            "URL": "https://secdb.alpinelinux.org/"
          },
          "Title": "busybox: use-after-free in awk",
          "Description": "A use-after-free vulnerability was discovered in xasprintf function in xfuncs_printf.c:344 in BusyBox v.1.36.1.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-416"
          ],
          "VendorSeverity": {
            "azure": 2,
            "cbl-mariner": 2,
            "nvd": 2,
            "redhat": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
              "V3Score": 5.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
              "V3Score": 7.8
            }
          },
          "References": [
            "http://lists.busybox.net/pipermail/busybox/2024-May/090760.html",
            "https://access.redhat.com/security/cve/CVE-2023-42363",
            "https://bugs.busybox.net/show_bug.cgi?id=15865",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-42363",
            "https://ubuntu.com/security/notices/USN-6961-1",
            "https://www.cve.org/CVERecord?id=CVE-2023-42363"
          ],
          "PublishedDate": "2023-11-27T22:15:07.94Z",
          "LastModifiedDate": "2023-11-30T05:06:49.523Z"
        },
        {
          "VulnerabilityID": "CVE-2023-42364",
          "PkgID": "busybox-binsh@1.36.1-r15",
          "PkgName": "busybox-binsh",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/busybox-binsh@1.36.1-r15?arch=aarch64\u0026distro=3.19.1",
            "UID": "c890c007ea4d67fd"
          },
          "InstalledVersion": "1.36.1-r15",
          "FixedVersion": "1.36.1-r19",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:bca4290a96390d7a6fc6f2f9929370d06f8dfcacba591c76e3d5c5044e7f420c",
            "DiffID": "sha256:b09314aec293bcd9a8ee5e643539437b3846f9e5e55f79e282e5f67e3026de5e"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-42364",
          "DataSource": {
            "ID": "alpine",
            "Name": "Alpine Secdb",
            "URL": "https://secdb.alpinelinux.org/"
          },
          "Title": "busybox: use-after-free",
          "Description": "A use-after-free vulnerability in BusyBox v.1.36.1 allows attackers to cause a denial of service via a crafted awk pattern in the awk.c evaluate function.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-416"
          ],
          "VendorSeverity": {
            "nvd": 2,
            "redhat": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
              "V3Score": 5.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
              "V3Score": 7.8
            }
          },
          "References": [
            "http://lists.busybox.net/pipermail/busybox/2024-May/090762.html",
            "https://access.redhat.com/security/cve/CVE-2023-42364",
            "https://bugs.busybox.net/show_bug.cgi?id=15868",
            "https://gitlab.alpinelinux.org/alpine/aports/-/blob/master/main/busybox/CVE-2023-42364-CVE-2023-42365.patch",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-42364",
            "https://ubuntu.com/security/notices/USN-6961-1",
            "https://www.cve.org/CVERecord?id=CVE-2023-42364"
          ],
          "PublishedDate": "2023-11-27T23:15:07.313Z",
          "LastModifiedDate": "2023-11-30T05:07:10.827Z"
        },
        {
          "VulnerabilityID": "CVE-2023-42365",
          "PkgID": "busybox-binsh@1.36.1-r15",
          "PkgName": "busybox-binsh",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/busybox-binsh@1.36.1-r15?arch=aarch64\u0026distro=3.19.1",
            "UID": "c890c007ea4d67fd"
          },
          "InstalledVersion": "1.36.1-r15",
          "FixedVersion": "1.36.1-r19",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:bca4290a96390d7a6fc6f2f9929370d06f8dfcacba591c76e3d5c5044e7f420c",
            "DiffID": "sha256:b09314aec293bcd9a8ee5e643539437b3846f9e5e55f79e282e5f67e3026de5e"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-42365",
          "DataSource": {
            "ID": "alpine",
            "Name": "Alpine Secdb",
            "URL": "https://secdb.alpinelinux.org/"
          },
          "Title": "busybox: use-after-free",
          "Description": "A use-after-free vulnerability was discovered in BusyBox v.1.36.1 via a crafted awk pattern in the awk.c copyvar function.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-416"
          ],
          "VendorSeverity": {
            "azure": 2,
            "cbl-mariner": 2,
            "nvd": 2,
            "redhat": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
              "V3Score": 5.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
              "V3Score": 7.8
            }
          },
          "References": [
            "http://lists.busybox.net/pipermail/busybox/2024-May/090762.html",
            "https://access.redhat.com/security/cve/CVE-2023-42365",
            "https://bugs.busybox.net/show_bug.cgi?id=15871",
            "https://gitlab.alpinelinux.org/alpine/aports/-/blob/master/main/busybox/CVE-2023-42364-CVE-2023-42365.patch",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-42365",
            "https://ubuntu.com/security/notices/USN-6961-1",
            "https://www.cve.org/CVERecord?id=CVE-2023-42365"
          ],
          "PublishedDate": "2023-11-27T23:15:07.373Z",
          "LastModifiedDate": "2023-11-30T05:08:08.77Z"
        },
        {
          "VulnerabilityID": "CVE-2023-42366",
          "PkgID": "busybox-binsh@1.36.1-r15",
          "PkgName": "busybox-binsh",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/busybox-binsh@1.36.1-r15?arch=aarch64\u0026distro=3.19.1",
            "UID": "c890c007ea4d67fd"
          },
          "InstalledVersion": "1.36.1-r15",
          "FixedVersion": "1.36.1-r16",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:bca4290a96390d7a6fc6f2f9929370d06f8dfcacba591c76e3d5c5044e7f420c",
            "DiffID": "sha256:b09314aec293bcd9a8ee5e643539437b3846f9e5e55f79e282e5f67e3026de5e"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-42366",
          "DataSource": {
            "ID": "alpine",
            "Name": "Alpine Secdb",
            "URL": "https://secdb.alpinelinux.org/"
          },
          "Title": "busybox: A heap-buffer-overflow",
          "Description": "A heap-buffer-overflow was discovered in BusyBox v.1.36.1 in the next_token function at awk.c:1159.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-787"
          ],
          "VendorSeverity": {
            "nvd": 2,
            "redhat": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
              "V3Score": 5.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H",
              "V3Score": 7.1
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2023-42366",
            "https://bugs.busybox.net/show_bug.cgi?id=15874",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-42366",
            "https://www.cve.org/CVERecord?id=CVE-2023-42366"
          ],
          "PublishedDate": "2023-11-27T23:15:07.42Z",
          "LastModifiedDate": "2023-11-30T05:08:23.197Z"
        },
        {
          "VulnerabilityID": "CVE-2024-2398",
          "PkgID": "curl@8.5.0-r0",
          "PkgName": "curl",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/curl@8.5.0-r0?arch=aarch64\u0026distro=3.19.1",
            "UID": "e1f0554259624b64"
          },
          "InstalledVersion": "8.5.0-r0",
          "FixedVersion": "8.7.1-r0",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:5ea2e59d5bc556b78ceb30c39b0b7be8e6a7c511150811cf7c445275c485c502",
            "DiffID": "sha256:53a2763a2f061ad8aa06c347fd3029b89e1b7d6b56be8d0df8e63fc8da00ef02"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-2398",
          "DataSource": {
            "ID": "alpine",
            "Name": "Alpine Secdb",
            "URL": "https://secdb.alpinelinux.org/"
          },
          "Title": "curl: HTTP/2 push headers memory-leak",
          "Description": "When an application tells libcurl it wants to allow HTTP/2 server push, and the amount of received headers for the push surpasses the maximum allowed limit (1000), libcurl aborts the server push. When aborting, libcurl inadvertently does not free all the previously allocated headers and instead leaks the memory.  Further, this error condition fails silently and is therefore not easily detected by an application.",
          "Severity": "HIGH",
          "VendorSeverity": {
            "alma": 2,
            "amazon": 2,
            "azure": 3,
            "cbl-mariner": 3,
            "oracle-oval": 2,
            "photon": 3,
            "redhat": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
              "V3Score": 7.5
            }
          },
          "References": [
            "http://seclists.org/fulldisclosure/2024/Jul/18",
            "http://seclists.org/fulldisclosure/2024/Jul/19",
            "http://seclists.org/fulldisclosure/2024/Jul/20",
            "http://www.openwall.com/lists/oss-security/2024/03/27/3",
            "https://access.redhat.com/errata/RHSA-2024:5529",
            "https://access.redhat.com/security/cve/CVE-2024-2398",
            "https://bugzilla.redhat.com/2270498",
            "https://curl.se/docs/CVE-2024-2398.html",
            "https://curl.se/docs/CVE-2024-2398.json",
            "https://errata.almalinux.org/9/ALSA-2024-5529.html",
            "https://hackerone.com/reports/2402845",
            "https://linux.oracle.com/cve/CVE-2024-2398.html",
            "https://linux.oracle.com/errata/ELSA-2024-5654.html",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/2D44YLAUFJU6BZ4XFG2FYV7SBKXB5IZ6/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/GMD6UYKCCRCYETWQZUJ65ZRFULT6SHLI/",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-2398",
            "https://security.netapp.com/advisory/ntap-20240503-0009/",
            "https://support.apple.com/kb/HT214118",
            "https://support.apple.com/kb/HT214119",
            "https://support.apple.com/kb/HT214120",
            "https://ubuntu.com/security/notices/USN-6718-1",
            "https://ubuntu.com/security/notices/USN-6718-2",
            "https://ubuntu.com/security/notices/USN-6718-3",
            "https://www.cve.org/CVERecord?id=CVE-2024-2398"
          ],
          "PublishedDate": "2024-03-27T08:15:41.283Z",
          "LastModifiedDate": "2024-07-30T02:15:05.45Z"
        },
        {
          "VulnerabilityID": "CVE-2024-6197",
          "PkgID": "curl@8.5.0-r0",
          "PkgName": "curl",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/curl@8.5.0-r0?arch=aarch64\u0026distro=3.19.1",
            "UID": "e1f0554259624b64"
          },
          "InstalledVersion": "8.5.0-r0",
          "FixedVersion": "8.9.0-r0",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:5ea2e59d5bc556b78ceb30c39b0b7be8e6a7c511150811cf7c445275c485c502",
            "DiffID": "sha256:53a2763a2f061ad8aa06c347fd3029b89e1b7d6b56be8d0df8e63fc8da00ef02"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-6197",
          "DataSource": {
            "ID": "alpine",
            "Name": "Alpine Secdb",
            "URL": "https://secdb.alpinelinux.org/"
          },
          "Title": "curl: freeing stack buffer in utf8asn1str",
          "Description": "libcurl's ASN1 parser has this utf8asn1str() function used for parsing an ASN.1 UTF-8 string. Itcan detect an invalid field and return error. Unfortunately, when doing so it also invokes `free()` on a 4 byte localstack buffer.  Most modern malloc implementations detect this error and immediately abort. Some however accept the input pointer and add that memory to its list of available chunks. This leads to the overwriting of nearby stack memory. The content of the overwrite is decided by the `free()` implementation; likely to be memory pointers and a set of flags.  The most likely outcome of exploting this flaw is a crash, although it cannot be ruled out that more serious results can be had in special circumstances.",
          "Severity": "HIGH",
          "VendorSeverity": {
            "cbl-mariner": 3,
            "nvd": 3,
            "photon": 3,
            "redhat": 2
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 7.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:H",
              "V3Score": 6.5
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2024/07/24/1",
            "http://www.openwall.com/lists/oss-security/2024/07/24/5",
            "https://access.redhat.com/security/cve/CVE-2024-6197",
            "https://curl.se/docs/CVE-2024-6197.html",
            "https://curl.se/docs/CVE-2024-6197.json",
            "https://hackerone.com/reports/2559516",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-6197",
            "https://www.cve.org/CVERecord?id=CVE-2024-6197"
          ],
          "PublishedDate": "2024-07-24T08:15:03.34Z",
          "LastModifiedDate": "2024-08-26T15:25:59.96Z"
        },
        {
          "VulnerabilityID": "CVE-2024-0853",
          "PkgID": "curl@8.5.0-r0",
          "PkgName": "curl",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/curl@8.5.0-r0?arch=aarch64\u0026distro=3.19.1",
            "UID": "e1f0554259624b64"
          },
          "InstalledVersion": "8.5.0-r0",
          "FixedVersion": "8.6.0-r0",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:5ea2e59d5bc556b78ceb30c39b0b7be8e6a7c511150811cf7c445275c485c502",
            "DiffID": "sha256:53a2763a2f061ad8aa06c347fd3029b89e1b7d6b56be8d0df8e63fc8da00ef02"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-0853",
          "DataSource": {
            "ID": "alpine",
            "Name": "Alpine Secdb",
            "URL": "https://secdb.alpinelinux.org/"
          },
          "Title": "curl: OCSP verification bypass with TLS session reuse",
          "Description": "curl inadvertently kept the SSL session ID for connections in its cache even when the verify status (*OCSP stapling*) test failed. A subsequent transfer to\nthe same hostname could then succeed if the session ID cache was still fresh, which then skipped the verify status check.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-295"
          ],
          "VendorSeverity": {
            "amazon": 1,
            "azure": 2,
            "cbl-mariner": 2,
            "nvd": 2,
            "redhat": 1,
            "ubuntu": 1
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
              "V3Score": 5.3
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N",
              "V3Score": 3.8
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2024-0853",
            "https://curl.se/docs/CVE-2024-0853.html",
            "https://curl.se/docs/CVE-2024-0853.json",
            "https://hackerone.com/reports/2298922",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-0853",
            "https://security.netapp.com/advisory/ntap-20240307-0004/",
            "https://security.netapp.com/advisory/ntap-20240426-0009/",
            "https://security.netapp.com/advisory/ntap-20240503-0012/",
            "https://www.cve.org/CVERecord?id=CVE-2024-0853"
          ],
          "PublishedDate": "2024-02-03T14:15:50.85Z",
          "LastModifiedDate": "2024-05-03T13:15:21.32Z"
        },
        {
          "VulnerabilityID": "CVE-2024-2004",
          "PkgID": "curl@8.5.0-r0",
          "PkgName": "curl",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/curl@8.5.0-r0?arch=aarch64\u0026distro=3.19.1",
            "UID": "e1f0554259624b64"
          },
          "InstalledVersion": "8.5.0-r0",
          "FixedVersion": "8.7.1-r0",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:5ea2e59d5bc556b78ceb30c39b0b7be8e6a7c511150811cf7c445275c485c502",
            "DiffID": "sha256:53a2763a2f061ad8aa06c347fd3029b89e1b7d6b56be8d0df8e63fc8da00ef02"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-2004",
          "DataSource": {
            "ID": "alpine",
            "Name": "Alpine Secdb",
            "URL": "https://secdb.alpinelinux.org/"
          },
          "Title": "curl: Usage of disabled protocol",
          "Description": "When a protocol selection parameter option disables all protocols without adding any then the default set of protocols would remain in the allowed set due to an error in the logic for removing protocols. The below command would perform a request to curl.se with a plaintext protocol which has been explicitly disabled.      curl --proto -all,-http http://curl.se  The flaw is only present if the set of selected protocols disables the entire set of available protocols, in itself a command with no practical use and therefore unlikely to be encountered in real situations. The curl security team has thus assessed this to be low severity bug.",
          "Severity": "MEDIUM",
          "VendorSeverity": {
            "amazon": 2,
            "azure": 1,
            "cbl-mariner": 1,
            "photon": 2,
            "redhat": 1,
            "ubuntu": 1
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L",
              "V3Score": 5.3
            }
          },
          "References": [
            "http://seclists.org/fulldisclosure/2024/Jul/18",
            "http://seclists.org/fulldisclosure/2024/Jul/19",
            "http://seclists.org/fulldisclosure/2024/Jul/20",
            "http://www.openwall.com/lists/oss-security/2024/03/27/1",
            "https://access.redhat.com/security/cve/CVE-2024-2004",
            "https://curl.se/docs/CVE-2024-2004.html",
            "https://curl.se/docs/CVE-2024-2004.json",
            "https://hackerone.com/reports/2384833",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/2D44YLAUFJU6BZ4XFG2FYV7SBKXB5IZ6/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/GMD6UYKCCRCYETWQZUJ65ZRFULT6SHLI/",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-2004",
            "https://security.netapp.com/advisory/ntap-20240524-0006/",
            "https://support.apple.com/kb/HT214118",
            "https://support.apple.com/kb/HT214119",
            "https://support.apple.com/kb/HT214120",
            "https://ubuntu.com/security/notices/USN-6718-1",
            "https://ubuntu.com/security/notices/USN-6718-3",
            "https://www.cve.org/CVERecord?id=CVE-2024-2004"
          ],
          "PublishedDate": "2024-03-27T08:15:41.173Z",
          "LastModifiedDate": "2024-07-30T02:15:05.32Z"
        },
        {
          "VulnerabilityID": "CVE-2024-2379",
          "PkgID": "curl@8.5.0-r0",
          "PkgName": "curl",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/curl@8.5.0-r0?arch=aarch64\u0026distro=3.19.1",
            "UID": "e1f0554259624b64"
          },
          "InstalledVersion": "8.5.0-r0",
          "FixedVersion": "8.7.1-r0",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:5ea2e59d5bc556b78ceb30c39b0b7be8e6a7c511150811cf7c445275c485c502",
            "DiffID": "sha256:53a2763a2f061ad8aa06c347fd3029b89e1b7d6b56be8d0df8e63fc8da00ef02"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-2379",
          "DataSource": {
            "ID": "alpine",
            "Name": "Alpine Secdb",
            "URL": "https://secdb.alpinelinux.org/"
          },
          "Title": "curl: QUIC certificate check bypass with wolfSSL",
          "Description": "libcurl skips the certificate verification for a QUIC connection under certain conditions, when built to use wolfSSL. If told to use an unknown/bad cipher or curve, the error path accidentally skips the verification and returns OK, thus ignoring any certificate problems.",
          "Severity": "MEDIUM",
          "VendorSeverity": {
            "redhat": 1
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
              "V3Score": 5.4
            }
          },
          "References": [
            "http://seclists.org/fulldisclosure/2024/Jul/18",
            "http://seclists.org/fulldisclosure/2024/Jul/19",
            "http://seclists.org/fulldisclosure/2024/Jul/20",
            "http://www.openwall.com/lists/oss-security/2024/03/27/2",
            "https://access.redhat.com/security/cve/CVE-2024-2379",
            "https://curl.se/docs/CVE-2024-2379.html",
            "https://curl.se/docs/CVE-2024-2379.json",
            "https://hackerone.com/reports/2410774",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-2379",
            "https://security.netapp.com/advisory/ntap-20240531-0001/",
            "https://support.apple.com/kb/HT214118",
            "https://support.apple.com/kb/HT214119",
            "https://support.apple.com/kb/HT214120",
            "https://www.cve.org/CVERecord?id=CVE-2024-2379"
          ],
          "PublishedDate": "2024-03-27T08:15:41.23Z",
          "LastModifiedDate": "2024-07-30T02:15:05.397Z"
        },
        {
          "VulnerabilityID": "CVE-2024-2466",
          "PkgID": "curl@8.5.0-r0",
          "PkgName": "curl",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/curl@8.5.0-r0?arch=aarch64\u0026distro=3.19.1",
            "UID": "e1f0554259624b64"
          },
          "InstalledVersion": "8.5.0-r0",
          "FixedVersion": "8.7.1-r0",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:5ea2e59d5bc556b78ceb30c39b0b7be8e6a7c511150811cf7c445275c485c502",
            "DiffID": "sha256:53a2763a2f061ad8aa06c347fd3029b89e1b7d6b56be8d0df8e63fc8da00ef02"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-2466",
          "DataSource": {
            "ID": "alpine",
            "Name": "Alpine Secdb",
            "URL": "https://secdb.alpinelinux.org/"
          },
          "Title": "curl: TLS certificate check bypass with mbedTLS",
          "Description": "libcurl did not check the server certificate of TLS connections done to a host specified as an IP address, when built to use mbedTLS.  libcurl would wrongly avoid using the set hostname function when the specified hostname was given as an IP address, therefore completely skipping the certificate check. This affects all uses of TLS protocols (HTTPS, FTPS, IMAPS, POPS3, SMTPS, etc).",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-297"
          ],
          "VendorSeverity": {
            "azure": 2,
            "cbl-mariner": 2,
            "redhat": 2
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:H/A:N",
              "V3Score": 5.3
            }
          },
          "References": [
            "http://seclists.org/fulldisclosure/2024/Jul/18",
            "http://seclists.org/fulldisclosure/2024/Jul/19",
            "http://seclists.org/fulldisclosure/2024/Jul/20",
            "http://www.openwall.com/lists/oss-security/2024/03/27/4",
            "https://access.redhat.com/security/cve/CVE-2024-2466",
            "https://curl.se/docs/CVE-2024-2466.html",
            "https://curl.se/docs/CVE-2024-2466.json",
            "https://hackerone.com/reports/2416725",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-2466",
            "https://security.netapp.com/advisory/ntap-20240503-0010/",
            "https://support.apple.com/kb/HT214118",
            "https://support.apple.com/kb/HT214119",
            "https://support.apple.com/kb/HT214120",
            "https://www.cve.org/CVERecord?id=CVE-2024-2466"
          ],
          "PublishedDate": "2024-03-27T08:15:41.343Z",
          "LastModifiedDate": "2024-08-23T19:35:12.65Z"
        },
        {
          "VulnerabilityID": "CVE-2024-6874",
          "PkgID": "curl@8.5.0-r0",
          "PkgName": "curl",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/curl@8.5.0-r0?arch=aarch64\u0026distro=3.19.1",
            "UID": "e1f0554259624b64"
          },
          "InstalledVersion": "8.5.0-r0",
          "FixedVersion": "8.9.0-r0",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:5ea2e59d5bc556b78ceb30c39b0b7be8e6a7c511150811cf7c445275c485c502",
            "DiffID": "sha256:53a2763a2f061ad8aa06c347fd3029b89e1b7d6b56be8d0df8e63fc8da00ef02"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-6874",
          "DataSource": {
            "ID": "alpine",
            "Name": "Alpine Secdb",
            "URL": "https://secdb.alpinelinux.org/"
          },
          "Title": "curl: macidn punycode buffer overread",
          "Description": "libcurl's URL API function\n[curl_url_get()](https://curl.se/libcurl/c/curl_url_get.html) offers punycode\nconversions, to and from IDN. Asking to convert a name that is exactly 256\nbytes, libcurl ends up reading outside of a stack based buffer when built to\nuse the *macidn* IDN backend. The conversion function then fills up the\nprovided buffer exactly - but does not null terminate the string.\n\nThis flaw can lead to stack contents accidently getting returned as part of\nthe converted string.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-125"
          ],
          "VendorSeverity": {
            "nvd": 2,
            "redhat": 1
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
              "V3Score": 4.3
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
              "V3Score": 5.3
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2024/07/24/2",
            "https://access.redhat.com/security/cve/CVE-2024-6874",
            "https://curl.se/docs/CVE-2024-6874.html",
            "https://curl.se/docs/CVE-2024-6874.json",
            "https://hackerone.com/reports/2604391",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-6874",
            "https://www.cve.org/CVERecord?id=CVE-2024-6874"
          ],
          "PublishedDate": "2024-07-24T08:15:03.413Z",
          "LastModifiedDate": "2024-09-10T15:27:04.19Z"
        },
        {
          "VulnerabilityID": "CVE-2024-32002",
          "PkgID": "git@2.43.0-r0",
          "PkgName": "git",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/git@2.43.0-r0?arch=aarch64\u0026distro=3.19.1",
            "UID": "73b808d2adf25d38"
          },
          "InstalledVersion": "2.43.0-r0",
          "FixedVersion": "2.43.4-r0",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:5ea2e59d5bc556b78ceb30c39b0b7be8e6a7c511150811cf7c445275c485c502",
            "DiffID": "sha256:53a2763a2f061ad8aa06c347fd3029b89e1b7d6b56be8d0df8e63fc8da00ef02"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-32002",
          "DataSource": {
            "ID": "alpine",
            "Name": "Alpine Secdb",
            "URL": "https://secdb.alpinelinux.org/"
          },
          "Title": "git: Recursive clones RCE",
          "Description": "Git is a revision control system. Prior to versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4, repositories with submodules can be crafted in a way that exploits a bug in Git whereby it can be fooled into writing files not into the submodule's worktree but into a `.git/` directory. This allows writing a hook that will be executed while the clone operation is still running, giving the user no opportunity to inspect the code that is being executed. The problem has been patched in versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4. If symbolic link support is disabled in Git (e.g. via `git config --global core.symlinks false`), the described attack won't work. As always, it is best to avoid cloning repositories from untrusted sources.",
          "Severity": "CRITICAL",
          "CweIDs": [
            "CWE-59",
            "CWE-22",
            "CWE-434"
          ],
          "VendorSeverity": {
            "alma": 3,
            "amazon": 3,
            "azure": 4,
            "bitnami": 4,
            "cbl-mariner": 4,
            "nvd": 4,
            "oracle-oval": 3,
            "photon": 4,
            "redhat": 3,
            "rocky": 3,
            "ubuntu": 2
          },
          "CVSS": {
            "bitnami": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H",
              "V3Score": 9.1
            },
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H",
              "V3Score": 9
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H",
              "V3Score": 9
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2024/05/14/2",
            "https://access.redhat.com/errata/RHSA-2024:4083",
            "https://access.redhat.com/security/cve/CVE-2024-32002",
            "https://bugzilla.redhat.com/2280421",
            "https://bugzilla.redhat.com/2280428",
            "https://bugzilla.redhat.com/2280446",
            "https://bugzilla.redhat.com/2280466",
            "https://bugzilla.redhat.com/2280484",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2280421",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2280428",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2280446",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2280466",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2280484",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-32002",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-32004",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-32020",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-32021",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-32465",
            "https://errata.almalinux.org/9/ALSA-2024-4083.html",
            "https://errata.rockylinux.org/RLSA-2024:4083",
            "https://git-scm.com/docs/git-clone#Documentation/git-clone.txt---recurse-submodulesltpathspecgt",
            "https://git-scm.com/docs/git-config#Documentation/git-config.txt-coresymlinks",
            "https://github.com/git/git/commit/97065761333fd62db1912d81b489db938d8c991d",
            "https://github.com/git/git/security/advisories/GHSA-8h77-4q3w-gfgv",
            "https://linux.oracle.com/cve/CVE-2024-32002.html",
            "https://linux.oracle.com/errata/ELSA-2024-4084.html",
            "https://lists.debian.org/debian-lts-announce/2024/06/msg00018.html",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/S4CK4IYTXEOBZTEM5K3T6LWOIZ3S44AR/",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-32002",
            "https://ubuntu.com/security/notices/USN-6793-1",
            "https://ubuntu.com/security/notices/USN-6793-2",
            "https://www.cve.org/CVERecord?id=CVE-2024-32002"
          ],
          "PublishedDate": "2024-05-14T19:15:10.81Z",
          "LastModifiedDate": "2024-06-26T10:15:11.863Z"
        },
        {
          "VulnerabilityID": "CVE-2024-32004",
          "PkgID": "git@2.43.0-r0",
          "PkgName": "git",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/git@2.43.0-r0?arch=aarch64\u0026distro=3.19.1",
            "UID": "73b808d2adf25d38"
          },
          "InstalledVersion": "2.43.0-r0",
          "FixedVersion": "2.43.4-r0",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:5ea2e59d5bc556b78ceb30c39b0b7be8e6a7c511150811cf7c445275c485c502",
            "DiffID": "sha256:53a2763a2f061ad8aa06c347fd3029b89e1b7d6b56be8d0df8e63fc8da00ef02"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-32004",
          "DataSource": {
            "ID": "alpine",
            "Name": "Alpine Secdb",
            "URL": "https://secdb.alpinelinux.org/"
          },
          "Title": "git: RCE while cloning local repos",
          "Description": "Git is a revision control system. Prior to versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4, an attacker can prepare a local repository in such a way that, when cloned, will execute arbitrary code during the operation. The problem has been patched in versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4. As a workaround, avoid cloning repositories from untrusted sources.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-114"
          ],
          "VendorSeverity": {
            "alma": 3,
            "amazon": 3,
            "azure": 3,
            "bitnami": 3,
            "cbl-mariner": 3,
            "oracle-oval": 3,
            "photon": 3,
            "redhat": 3,
            "rocky": 3,
            "ubuntu": 2
          },
          "CVSS": {
            "bitnami": {
              "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H",
              "V3Score": 8.2
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H",
              "V3Score": 8.1
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2024/05/14/2",
            "https://access.redhat.com/errata/RHSA-2024:4083",
            "https://access.redhat.com/security/cve/CVE-2024-32004",
            "https://bugzilla.redhat.com/2280421",
            "https://bugzilla.redhat.com/2280428",
            "https://bugzilla.redhat.com/2280446",
            "https://bugzilla.redhat.com/2280466",
            "https://bugzilla.redhat.com/2280484",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2280421",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2280428",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2280446",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2280466",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2280484",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-32002",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-32004",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-32020",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-32021",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-32465",
            "https://errata.almalinux.org/9/ALSA-2024-4083.html",
            "https://errata.rockylinux.org/RLSA-2024:4083",
            "https://git-scm.com/docs/git-clone",
            "https://github.com/git/git/commit/f4aa8c8bb11dae6e769cd930565173808cbb69c8",
            "https://github.com/git/git/security/advisories/GHSA-xfc6-vwr8-r389",
            "https://linux.oracle.com/cve/CVE-2024-32004.html",
            "https://linux.oracle.com/errata/ELSA-2024-4084.html",
            "https://lists.debian.org/debian-lts-announce/2024/06/msg00018.html",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/S4CK4IYTXEOBZTEM5K3T6LWOIZ3S44AR/",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-32004",
            "https://ubuntu.com/security/notices/USN-6793-1",
            "https://www.cve.org/CVERecord?id=CVE-2024-32004"
          ],
          "PublishedDate": "2024-05-14T19:15:11.377Z",
          "LastModifiedDate": "2024-06-26T10:15:12.05Z"
        },
        {
          "VulnerabilityID": "CVE-2024-32465",
          "PkgID": "git@2.43.0-r0",
          "PkgName": "git",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/git@2.43.0-r0?arch=aarch64\u0026distro=3.19.1",
            "UID": "73b808d2adf25d38"
          },
          "InstalledVersion": "2.43.0-r0",
          "FixedVersion": "2.43.4-r0",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:5ea2e59d5bc556b78ceb30c39b0b7be8e6a7c511150811cf7c445275c485c502",
            "DiffID": "sha256:53a2763a2f061ad8aa06c347fd3029b89e1b7d6b56be8d0df8e63fc8da00ef02"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-32465",
          "DataSource": {
            "ID": "alpine",
            "Name": "Alpine Secdb",
            "URL": "https://secdb.alpinelinux.org/"
          },
          "Title": "git: additional local RCE",
          "Description": "Git is a revision control system. The Git project recommends to avoid working in untrusted repositories, and instead to clone it first with `git clone --no-local` to obtain a clean copy. Git has specific protections to make that a safe operation even with an untrusted source repository, but vulnerabilities allow those protections to be bypassed. In the context of cloning local repositories owned by other users, this vulnerability has been covered in CVE-2024-32004. But there are circumstances where the fixes for CVE-2024-32004 are not enough: For example, when obtaining a `.zip` file containing a full copy of a Git repository, it should not be trusted by default to be safe, as e.g. hooks could be configured to run within the context of that repository. The problem has been patched in versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4. As a workaround, avoid using Git in repositories that have been obtained via archives from untrusted sources.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-22"
          ],
          "VendorSeverity": {
            "alma": 3,
            "amazon": 3,
            "azure": 3,
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
              "V3Vector": "CVSS:3.1/AV:P/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H",
              "V3Score": 7.4
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:P/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H",
              "V3Score": 7.3
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2024/05/14/2",
            "https://access.redhat.com/errata/RHSA-2024:4083",
            "https://access.redhat.com/security/cve/CVE-2024-32465",
            "https://bugzilla.redhat.com/2280421",
            "https://bugzilla.redhat.com/2280428",
            "https://bugzilla.redhat.com/2280446",
            "https://bugzilla.redhat.com/2280466",
            "https://bugzilla.redhat.com/2280484",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2280421",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2280428",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2280446",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2280466",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2280484",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-32002",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-32004",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-32020",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-32021",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-32465",
            "https://errata.almalinux.org/9/ALSA-2024-4083.html",
            "https://errata.rockylinux.org/RLSA-2024:4083",
            "https://git-scm.com/docs/git#_security",
            "https://git-scm.com/docs/git-clone",
            "https://github.com/git/git/commit/7b70e9efb18c2cc3f219af399bd384c5801ba1d7",
            "https://github.com/git/git/security/advisories/GHSA-vm9j-46j9-qvq4",
            "https://linux.oracle.com/cve/CVE-2024-32465.html",
            "https://linux.oracle.com/errata/ELSA-2024-4084.html",
            "https://lists.debian.org/debian-lts-announce/2024/06/msg00018.html",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/S4CK4IYTXEOBZTEM5K3T6LWOIZ3S44AR/",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-32465",
            "https://ubuntu.com/security/notices/USN-6793-1",
            "https://www.cve.org/CVERecord?id=CVE-2024-32465"
          ],
          "PublishedDate": "2024-05-14T20:15:14.54Z",
          "LastModifiedDate": "2024-06-26T10:15:12.28Z"
        },
        {
          "VulnerabilityID": "CVE-2024-32020",
          "PkgID": "git@2.43.0-r0",
          "PkgName": "git",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/git@2.43.0-r0?arch=aarch64\u0026distro=3.19.1",
            "UID": "73b808d2adf25d38"
          },
          "InstalledVersion": "2.43.0-r0",
          "FixedVersion": "2.43.4-r0",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:5ea2e59d5bc556b78ceb30c39b0b7be8e6a7c511150811cf7c445275c485c502",
            "DiffID": "sha256:53a2763a2f061ad8aa06c347fd3029b89e1b7d6b56be8d0df8e63fc8da00ef02"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-32020",
          "DataSource": {
            "ID": "alpine",
            "Name": "Alpine Secdb",
            "URL": "https://secdb.alpinelinux.org/"
          },
          "Title": "git: insecure hardlinks",
          "Description": "Git is a revision control system. Prior to versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4, local clones may end up hardlinking files into the target repository's object database when source and target repository reside on the same disk. If the source repository is owned by a different user, then those hardlinked files may be rewritten at any point in time by the untrusted user. Cloning local repositories will cause Git to either copy or hardlink files of the source repository into the target repository. This significantly speeds up such local clones compared to doing a \"proper\" clone and saves both disk space and compute time. When cloning a repository located on the same disk that is owned by a different user than the current user we also end up creating such hardlinks. These files will continue to be owned and controlled by the potentially-untrusted user and can be rewritten by them at will in the future. The problem has been patched in versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-281"
          ],
          "VendorSeverity": {
            "alma": 3,
            "amazon": 3,
            "azure": 1,
            "bitnami": 1,
            "cbl-mariner": 1,
            "oracle-oval": 3,
            "photon": 1,
            "redhat": 1,
            "rocky": 3,
            "ubuntu": 2
          },
          "CVSS": {
            "bitnami": {
              "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:C/C:N/I:L/A:L",
              "V3Score": 3.9
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:C/C:N/I:L/A:L",
              "V3Score": 3.9
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2024/05/14/2",
            "https://access.redhat.com/errata/RHSA-2024:4083",
            "https://access.redhat.com/security/cve/CVE-2024-32020",
            "https://bugzilla.redhat.com/2280421",
            "https://bugzilla.redhat.com/2280428",
            "https://bugzilla.redhat.com/2280446",
            "https://bugzilla.redhat.com/2280466",
            "https://bugzilla.redhat.com/2280484",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2280421",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2280428",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2280446",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2280466",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2280484",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-32002",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-32004",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-32020",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-32021",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-32465",
            "https://errata.almalinux.org/9/ALSA-2024-4083.html",
            "https://errata.rockylinux.org/RLSA-2024:4083",
            "https://github.com/git/git/commit/1204e1a824c34071019fe106348eaa6d88f9528d",
            "https://github.com/git/git/commit/9e65df5eab274bf74c7b570107aacd1303a1e703",
            "https://github.com/git/git/security/advisories/GHSA-5rfh-556j-fhgj",
            "https://linux.oracle.com/cve/CVE-2024-32020.html",
            "https://linux.oracle.com/errata/ELSA-2024-4084.html",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/S4CK4IYTXEOBZTEM5K3T6LWOIZ3S44AR/",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-32020",
            "https://ubuntu.com/security/notices/USN-6793-1",
            "https://www.cve.org/CVERecord?id=CVE-2024-32020"
          ],
          "PublishedDate": "2024-05-14T19:15:12.24Z",
          "LastModifiedDate": "2024-06-10T18:15:32.08Z"
        },
        {
          "VulnerabilityID": "CVE-2024-32021",
          "PkgID": "git@2.43.0-r0",
          "PkgName": "git",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/git@2.43.0-r0?arch=aarch64\u0026distro=3.19.1",
            "UID": "73b808d2adf25d38"
          },
          "InstalledVersion": "2.43.0-r0",
          "FixedVersion": "2.43.4-r0",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:5ea2e59d5bc556b78ceb30c39b0b7be8e6a7c511150811cf7c445275c485c502",
            "DiffID": "sha256:53a2763a2f061ad8aa06c347fd3029b89e1b7d6b56be8d0df8e63fc8da00ef02"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-32021",
          "DataSource": {
            "ID": "alpine",
            "Name": "Alpine Secdb",
            "URL": "https://secdb.alpinelinux.org/"
          },
          "Title": "git: symlink bypass",
          "Description": "Git is a revision control system. Prior to versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4, when cloning a local source repository that contains symlinks via the filesystem, Git may create hardlinks to arbitrary user-readable files on the same filesystem as the target repository in the `objects/` directory. Cloning a local repository over the filesystem may creating hardlinks to arbitrary user-owned files on the same filesystem in the target Git repository's `objects/` directory. When cloning a repository over the filesystem (without explicitly specifying the `file://` protocol or `--no-local`), the optimizations for local cloning\nwill be used, which include attempting to hard link the object files instead of copying them. While the code includes checks against symbolic links in the source repository, which were added during the fix for CVE-2022-39253, these checks can still be raced because the hard link operation ultimately follows symlinks. If the object on the filesystem appears as a file during the check, and then a symlink during the operation, this will allow the adversary to bypass the check and create hardlinks in the destination objects directory to arbitrary, user-readable files. The problem has been patched in versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-547"
          ],
          "VendorSeverity": {
            "alma": 3,
            "amazon": 3,
            "azure": 1,
            "bitnami": 1,
            "cbl-mariner": 1,
            "oracle-oval": 3,
            "photon": 1,
            "redhat": 1,
            "rocky": 3,
            "ubuntu": 2
          },
          "CVSS": {
            "bitnami": {
              "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:C/C:N/I:L/A:L",
              "V3Score": 3.9
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:C/C:N/I:L/A:L",
              "V3Score": 3.9
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2024/05/14/2",
            "https://access.redhat.com/errata/RHSA-2024:4083",
            "https://access.redhat.com/security/cve/CVE-2024-32021",
            "https://bugzilla.redhat.com/2280421",
            "https://bugzilla.redhat.com/2280428",
            "https://bugzilla.redhat.com/2280446",
            "https://bugzilla.redhat.com/2280466",
            "https://bugzilla.redhat.com/2280484",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2280421",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2280428",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2280446",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2280466",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2280484",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-32002",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-32004",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-32020",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-32021",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-32465",
            "https://errata.almalinux.org/9/ALSA-2024-4083.html",
            "https://errata.rockylinux.org/RLSA-2024:4083",
            "https://github.com/git/git/security/advisories/GHSA-mvxm-9j2h-qjx7",
            "https://linux.oracle.com/cve/CVE-2024-32021.html",
            "https://linux.oracle.com/errata/ELSA-2024-4084.html",
            "https://lists.debian.org/debian-lts-announce/2024/06/msg00018.html",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/S4CK4IYTXEOBZTEM5K3T6LWOIZ3S44AR/",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-32021",
            "https://ubuntu.com/security/notices/USN-6793-1",
            "https://www.cve.org/CVERecord?id=CVE-2024-32021"
          ],
          "PublishedDate": "2024-05-14T20:15:13.63Z",
          "LastModifiedDate": "2024-06-26T10:15:12.167Z"
        },
        {
          "VulnerabilityID": "CVE-2024-4603",
          "PkgID": "libcrypto3@3.1.4-r6",
          "PkgName": "libcrypto3",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/libcrypto3@3.1.4-r6?arch=aarch64\u0026distro=3.19.1",
            "UID": "bb7dddaed8fc27aa"
          },
          "InstalledVersion": "3.1.4-r6",
          "FixedVersion": "3.1.5-r0",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:2382f499efd6a239346d1f41dd0010ef2e0974766faeff351ee66d0ad6a99311",
            "DiffID": "sha256:1fe037e9153d3390f9f6f775c05084cc49c55877b3785a00de5510f977aae8aa"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-4603",
          "DataSource": {
            "ID": "alpine",
            "Name": "Alpine Secdb",
            "URL": "https://secdb.alpinelinux.org/"
          },
          "Title": "openssl: Excessive time spent checking DSA keys and parameters",
          "Description": "Issue summary: Checking excessively long DSA keys or parameters may be very\nslow.\n\nImpact summary: Applications that use the functions EVP_PKEY_param_check()\nor EVP_PKEY_public_check() to check a DSA public key or DSA parameters may\nexperience long delays. Where the key or parameters that are being checked\nhave been obtained from an untrusted source this may lead to a Denial of\nService.\n\nThe functions EVP_PKEY_param_check() or EVP_PKEY_public_check() perform\nvarious checks on DSA parameters. Some of those computations take a long time\nif the modulus (`p` parameter) is too large.\n\nTrying to use a very large modulus is slow and OpenSSL will not allow using\npublic keys with a modulus which is over 10,000 bits in length for signature\nverification. However the key and parameter check functions do not limit\nthe modulus size when performing the checks.\n\nAn application that calls EVP_PKEY_param_check() or EVP_PKEY_public_check()\nand supplies a key or parameters obtained from an untrusted source could be\nvulnerable to a Denial of Service attack.\n\nThese functions are not called by OpenSSL itself on untrusted DSA keys so\nonly applications that directly call these functions may be vulnerable.\n\nAlso vulnerable are the OpenSSL pkey and pkeyparam command line applications\nwhen using the `-check` option.\n\nThe OpenSSL SSL/TLS implementation is not affected by this issue.\n\nThe OpenSSL 3.0 and 3.1 FIPS providers are affected by this issue.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-834"
          ],
          "VendorSeverity": {
            "amazon": 2,
            "azure": 2,
            "cbl-mariner": 2,
            "redhat": 1,
            "ubuntu": 1
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
              "V3Score": 5.3
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2024/05/16/2",
            "https://access.redhat.com/security/cve/CVE-2024-4603",
            "https://github.com/openssl/openssl/commit/3559e868e58005d15c6013a0c1fd832e51c73397",
            "https://github.com/openssl/openssl/commit/53ea06486d296b890d565fb971b2764fcd826e7e",
            "https://github.com/openssl/openssl/commit/9c39b3858091c152f52513c066ff2c5a47969f0d",
            "https://github.com/openssl/openssl/commit/da343d0605c826ef197aceedc67e8e04f065f740",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-4603",
            "https://security.netapp.com/advisory/ntap-20240621-0001/",
            "https://ubuntu.com/security/notices/USN-6937-1",
            "https://www.cve.org/CVERecord?id=CVE-2024-4603",
            "https://www.openssl.org/news/secadv/20240516.txt"
          ],
          "PublishedDate": "2024-05-16T16:15:10.643Z",
          "LastModifiedDate": "2024-08-13T16:35:05.013Z"
        },
        {
          "VulnerabilityID": "CVE-2024-4741",
          "PkgID": "libcrypto3@3.1.4-r6",
          "PkgName": "libcrypto3",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/libcrypto3@3.1.4-r6?arch=aarch64\u0026distro=3.19.1",
            "UID": "bb7dddaed8fc27aa"
          },
          "InstalledVersion": "3.1.4-r6",
          "FixedVersion": "3.1.6-r0",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:2382f499efd6a239346d1f41dd0010ef2e0974766faeff351ee66d0ad6a99311",
            "DiffID": "sha256:1fe037e9153d3390f9f6f775c05084cc49c55877b3785a00de5510f977aae8aa"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-4741",
          "DataSource": {
            "ID": "alpine",
            "Name": "Alpine Secdb",
            "URL": "https://secdb.alpinelinux.org/"
          },
          "Title": "openssl: Use After Free with SSL_free_buffers",
          "Description": "A use-after-free vulnerability was found in OpenSSL. Calling the OpenSSL API SSL_free_buffers function may cause memory to be accessed that was previously freed in some situations.",
          "Severity": "MEDIUM",
          "VendorSeverity": {
            "amazon": 2,
            "cbl-mariner": 3,
            "photon": 2,
            "redhat": 1,
            "ubuntu": 1
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L",
              "V3Score": 5.6
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2024-4741",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-4741",
            "https://ubuntu.com/security/notices/USN-6937-1",
            "https://www.cve.org/CVERecord?id=CVE-2024-4741",
            "https://www.openssl.org/news/secadv/20240528.txt"
          ]
        },
        {
          "VulnerabilityID": "CVE-2024-5535",
          "PkgID": "libcrypto3@3.1.4-r6",
          "PkgName": "libcrypto3",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/libcrypto3@3.1.4-r6?arch=aarch64\u0026distro=3.19.1",
            "UID": "bb7dddaed8fc27aa"
          },
          "InstalledVersion": "3.1.4-r6",
          "FixedVersion": "3.1.6-r0",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:2382f499efd6a239346d1f41dd0010ef2e0974766faeff351ee66d0ad6a99311",
            "DiffID": "sha256:1fe037e9153d3390f9f6f775c05084cc49c55877b3785a00de5510f977aae8aa"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-5535",
          "DataSource": {
            "ID": "alpine",
            "Name": "Alpine Secdb",
            "URL": "https://secdb.alpinelinux.org/"
          },
          "Title": "openssl: SSL_select_next_proto buffer overread",
          "Description": "Issue summary: Calling the OpenSSL API function SSL_select_next_proto with an\nempty supported client protocols buffer may cause a crash or memory contents to\nbe sent to the peer.\n\nImpact summary: A buffer overread can have a range of potential consequences\nsuch as unexpected application beahviour or a crash. In particular this issue\ncould result in up to 255 bytes of arbitrary private data from memory being sent\nto the peer leading to a loss of confidentiality. However, only applications\nthat directly call the SSL_select_next_proto function with a 0 length list of\nsupported client protocols are affected by this issue. This would normally never\nbe a valid scenario and is typically not under attacker control but may occur by\naccident in the case of a configuration or programming error in the calling\napplication.\n\nThe OpenSSL API function SSL_select_next_proto is typically used by TLS\napplications that support ALPN (Application Layer Protocol Negotiation) or NPN\n(Next Protocol Negotiation). NPN is older, was never standardised and\nis deprecated in favour of ALPN. We believe that ALPN is significantly more\nwidely deployed than NPN. The SSL_select_next_proto function accepts a list of\nprotocols from the server and a list of protocols from the client and returns\nthe first protocol that appears in the server list that also appears in the\nclient list. In the case of no overlap between the two lists it returns the\nfirst item in the client list. In either case it will signal whether an overlap\nbetween the two lists was found. In the case where SSL_select_next_proto is\ncalled with a zero length client list it fails to notice this condition and\nreturns the memory immediately following the client list pointer (and reports\nthat there was no overlap in the lists).\n\nThis function is typically called from a server side application callback for\nALPN or a client side application callback for NPN. In the case of ALPN the list\nof protocols supplied by the client is guaranteed by libssl to never be zero in\nlength. The list of server protocols comes from the application and should never\nnormally be expected to be of zero length. In this case if the\nSSL_select_next_proto function has been called as expected (with the list\nsupplied by the client passed in the client/client_len parameters), then the\napplication will not be vulnerable to this issue. If the application has\naccidentally been configured with a zero length server list, and has\naccidentally passed that zero length server list in the client/client_len\nparameters, and has additionally failed to correctly handle a \"no overlap\"\nresponse (which would normally result in a handshake failure in ALPN) then it\nwill be vulnerable to this problem.\n\nIn the case of NPN, the protocol permits the client to opportunistically select\na protocol when there is no overlap. OpenSSL returns the first client protocol\nin the no overlap case in support of this. The list of client protocols comes\nfrom the application and should never normally be expected to be of zero length.\nHowever if the SSL_select_next_proto function is accidentally called with a\nclient_len of 0 then an invalid memory pointer will be returned instead. If the\napplication uses this output as the opportunistic protocol then the loss of\nconfidentiality will occur.\n\nThis issue has been assessed as Low severity because applications are most\nlikely to be vulnerable if they are using NPN instead of ALPN - but NPN is not\nwidely used. It also requires an application configuration or programming error.\nFinally, this issue would not typically be under attacker control making active\nexploitation unlikely.\n\nThe FIPS modules in 3.3, 3.2, 3.1 and 3.0 are not affected by this issue.\n\nDue to the low severity of this issue we are not issuing new releases of\nOpenSSL at this time. The fix will be included in the next releases when they\nbecome available.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-200"
          ],
          "VendorSeverity": {
            "amazon": 2,
            "azure": 2,
            "cbl-mariner": 4,
            "photon": 4,
            "redhat": 1,
            "ubuntu": 1
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 5.9
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2024/06/27/1",
            "http://www.openwall.com/lists/oss-security/2024/06/28/4",
            "https://access.redhat.com/security/cve/CVE-2024-5535",
            "https://github.com/openssl/openssl/commit/4ada436a1946cbb24db5ab4ca082b69c1bc10f37",
            "https://github.com/openssl/openssl/commit/99fb785a5f85315b95288921a321a935ea29a51e",
            "https://github.com/openssl/openssl/commit/cf6f91f6121f4db167405db2f0de410a456f260c",
            "https://github.com/openssl/openssl/commit/e86ac436f0bd54d4517745483e2315650fae7b2c",
            "https://github.openssl.org/openssl/extended-releases/commit/9947251413065a05189a63c9b7a6c1d4e224c21c",
            "https://github.openssl.org/openssl/extended-releases/commit/b78ec0824da857223486660177d3b1f255c65d87",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-5535",
            "https://openssl.org/news/secadv/20240627.txt",
            "https://security.netapp.com/advisory/ntap-20240712-0005/",
            "https://ubuntu.com/security/notices/USN-6937-1",
            "https://www.cve.org/CVERecord?id=CVE-2024-5535",
            "https://www.openssl.org/news/secadv/20240627.txt"
          ],
          "PublishedDate": "2024-06-27T11:15:24.447Z",
          "LastModifiedDate": "2024-07-12T14:15:16.79Z"
        },
        {
          "VulnerabilityID": "CVE-2024-6119",
          "PkgID": "libcrypto3@3.1.4-r6",
          "PkgName": "libcrypto3",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/libcrypto3@3.1.4-r6?arch=aarch64\u0026distro=3.19.1",
            "UID": "bb7dddaed8fc27aa"
          },
          "InstalledVersion": "3.1.4-r6",
          "FixedVersion": "3.1.7-r0",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:2382f499efd6a239346d1f41dd0010ef2e0974766faeff351ee66d0ad6a99311",
            "DiffID": "sha256:1fe037e9153d3390f9f6f775c05084cc49c55877b3785a00de5510f977aae8aa"
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
          "VulnerabilityID": "CVE-2024-2398",
          "PkgID": "libcurl@8.5.0-r0",
          "PkgName": "libcurl",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/libcurl@8.5.0-r0?arch=aarch64\u0026distro=3.19.1",
            "UID": "667d9078ceac1329"
          },
          "InstalledVersion": "8.5.0-r0",
          "FixedVersion": "8.7.1-r0",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:5ea2e59d5bc556b78ceb30c39b0b7be8e6a7c511150811cf7c445275c485c502",
            "DiffID": "sha256:53a2763a2f061ad8aa06c347fd3029b89e1b7d6b56be8d0df8e63fc8da00ef02"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-2398",
          "DataSource": {
            "ID": "alpine",
            "Name": "Alpine Secdb",
            "URL": "https://secdb.alpinelinux.org/"
          },
          "Title": "curl: HTTP/2 push headers memory-leak",
          "Description": "When an application tells libcurl it wants to allow HTTP/2 server push, and the amount of received headers for the push surpasses the maximum allowed limit (1000), libcurl aborts the server push. When aborting, libcurl inadvertently does not free all the previously allocated headers and instead leaks the memory.  Further, this error condition fails silently and is therefore not easily detected by an application.",
          "Severity": "HIGH",
          "VendorSeverity": {
            "alma": 2,
            "amazon": 2,
            "azure": 3,
            "cbl-mariner": 3,
            "oracle-oval": 2,
            "photon": 3,
            "redhat": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
              "V3Score": 7.5
            }
          },
          "References": [
            "http://seclists.org/fulldisclosure/2024/Jul/18",
            "http://seclists.org/fulldisclosure/2024/Jul/19",
            "http://seclists.org/fulldisclosure/2024/Jul/20",
            "http://www.openwall.com/lists/oss-security/2024/03/27/3",
            "https://access.redhat.com/errata/RHSA-2024:5529",
            "https://access.redhat.com/security/cve/CVE-2024-2398",
            "https://bugzilla.redhat.com/2270498",
            "https://curl.se/docs/CVE-2024-2398.html",
            "https://curl.se/docs/CVE-2024-2398.json",
            "https://errata.almalinux.org/9/ALSA-2024-5529.html",
            "https://hackerone.com/reports/2402845",
            "https://linux.oracle.com/cve/CVE-2024-2398.html",
            "https://linux.oracle.com/errata/ELSA-2024-5654.html",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/2D44YLAUFJU6BZ4XFG2FYV7SBKXB5IZ6/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/GMD6UYKCCRCYETWQZUJ65ZRFULT6SHLI/",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-2398",
            "https://security.netapp.com/advisory/ntap-20240503-0009/",
            "https://support.apple.com/kb/HT214118",
            "https://support.apple.com/kb/HT214119",
            "https://support.apple.com/kb/HT214120",
            "https://ubuntu.com/security/notices/USN-6718-1",
            "https://ubuntu.com/security/notices/USN-6718-2",
            "https://ubuntu.com/security/notices/USN-6718-3",
            "https://www.cve.org/CVERecord?id=CVE-2024-2398"
          ],
          "PublishedDate": "2024-03-27T08:15:41.283Z",
          "LastModifiedDate": "2024-07-30T02:15:05.45Z"
        },
        {
          "VulnerabilityID": "CVE-2024-6197",
          "PkgID": "libcurl@8.5.0-r0",
          "PkgName": "libcurl",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/libcurl@8.5.0-r0?arch=aarch64\u0026distro=3.19.1",
            "UID": "667d9078ceac1329"
          },
          "InstalledVersion": "8.5.0-r0",
          "FixedVersion": "8.9.0-r0",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:5ea2e59d5bc556b78ceb30c39b0b7be8e6a7c511150811cf7c445275c485c502",
            "DiffID": "sha256:53a2763a2f061ad8aa06c347fd3029b89e1b7d6b56be8d0df8e63fc8da00ef02"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-6197",
          "DataSource": {
            "ID": "alpine",
            "Name": "Alpine Secdb",
            "URL": "https://secdb.alpinelinux.org/"
          },
          "Title": "curl: freeing stack buffer in utf8asn1str",
          "Description": "libcurl's ASN1 parser has this utf8asn1str() function used for parsing an ASN.1 UTF-8 string. Itcan detect an invalid field and return error. Unfortunately, when doing so it also invokes `free()` on a 4 byte localstack buffer.  Most modern malloc implementations detect this error and immediately abort. Some however accept the input pointer and add that memory to its list of available chunks. This leads to the overwriting of nearby stack memory. The content of the overwrite is decided by the `free()` implementation; likely to be memory pointers and a set of flags.  The most likely outcome of exploting this flaw is a crash, although it cannot be ruled out that more serious results can be had in special circumstances.",
          "Severity": "HIGH",
          "VendorSeverity": {
            "cbl-mariner": 3,
            "nvd": 3,
            "photon": 3,
            "redhat": 2
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 7.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:H",
              "V3Score": 6.5
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2024/07/24/1",
            "http://www.openwall.com/lists/oss-security/2024/07/24/5",
            "https://access.redhat.com/security/cve/CVE-2024-6197",
            "https://curl.se/docs/CVE-2024-6197.html",
            "https://curl.se/docs/CVE-2024-6197.json",
            "https://hackerone.com/reports/2559516",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-6197",
            "https://www.cve.org/CVERecord?id=CVE-2024-6197"
          ],
          "PublishedDate": "2024-07-24T08:15:03.34Z",
          "LastModifiedDate": "2024-08-26T15:25:59.96Z"
        },
        {
          "VulnerabilityID": "CVE-2024-0853",
          "PkgID": "libcurl@8.5.0-r0",
          "PkgName": "libcurl",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/libcurl@8.5.0-r0?arch=aarch64\u0026distro=3.19.1",
            "UID": "667d9078ceac1329"
          },
          "InstalledVersion": "8.5.0-r0",
          "FixedVersion": "8.6.0-r0",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:5ea2e59d5bc556b78ceb30c39b0b7be8e6a7c511150811cf7c445275c485c502",
            "DiffID": "sha256:53a2763a2f061ad8aa06c347fd3029b89e1b7d6b56be8d0df8e63fc8da00ef02"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-0853",
          "DataSource": {
            "ID": "alpine",
            "Name": "Alpine Secdb",
            "URL": "https://secdb.alpinelinux.org/"
          },
          "Title": "curl: OCSP verification bypass with TLS session reuse",
          "Description": "curl inadvertently kept the SSL session ID for connections in its cache even when the verify status (*OCSP stapling*) test failed. A subsequent transfer to\nthe same hostname could then succeed if the session ID cache was still fresh, which then skipped the verify status check.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-295"
          ],
          "VendorSeverity": {
            "amazon": 1,
            "azure": 2,
            "cbl-mariner": 2,
            "nvd": 2,
            "redhat": 1,
            "ubuntu": 1
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
              "V3Score": 5.3
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N",
              "V3Score": 3.8
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2024-0853",
            "https://curl.se/docs/CVE-2024-0853.html",
            "https://curl.se/docs/CVE-2024-0853.json",
            "https://hackerone.com/reports/2298922",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-0853",
            "https://security.netapp.com/advisory/ntap-20240307-0004/",
            "https://security.netapp.com/advisory/ntap-20240426-0009/",
            "https://security.netapp.com/advisory/ntap-20240503-0012/",
            "https://www.cve.org/CVERecord?id=CVE-2024-0853"
          ],
          "PublishedDate": "2024-02-03T14:15:50.85Z",
          "LastModifiedDate": "2024-05-03T13:15:21.32Z"
        },
        {
          "VulnerabilityID": "CVE-2024-2004",
          "PkgID": "libcurl@8.5.0-r0",
          "PkgName": "libcurl",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/libcurl@8.5.0-r0?arch=aarch64\u0026distro=3.19.1",
            "UID": "667d9078ceac1329"
          },
          "InstalledVersion": "8.5.0-r0",
          "FixedVersion": "8.7.1-r0",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:5ea2e59d5bc556b78ceb30c39b0b7be8e6a7c511150811cf7c445275c485c502",
            "DiffID": "sha256:53a2763a2f061ad8aa06c347fd3029b89e1b7d6b56be8d0df8e63fc8da00ef02"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-2004",
          "DataSource": {
            "ID": "alpine",
            "Name": "Alpine Secdb",
            "URL": "https://secdb.alpinelinux.org/"
          },
          "Title": "curl: Usage of disabled protocol",
          "Description": "When a protocol selection parameter option disables all protocols without adding any then the default set of protocols would remain in the allowed set due to an error in the logic for removing protocols. The below command would perform a request to curl.se with a plaintext protocol which has been explicitly disabled.      curl --proto -all,-http http://curl.se  The flaw is only present if the set of selected protocols disables the entire set of available protocols, in itself a command with no practical use and therefore unlikely to be encountered in real situations. The curl security team has thus assessed this to be low severity bug.",
          "Severity": "MEDIUM",
          "VendorSeverity": {
            "amazon": 2,
            "azure": 1,
            "cbl-mariner": 1,
            "photon": 2,
            "redhat": 1,
            "ubuntu": 1
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L",
              "V3Score": 5.3
            }
          },
          "References": [
            "http://seclists.org/fulldisclosure/2024/Jul/18",
            "http://seclists.org/fulldisclosure/2024/Jul/19",
            "http://seclists.org/fulldisclosure/2024/Jul/20",
            "http://www.openwall.com/lists/oss-security/2024/03/27/1",
            "https://access.redhat.com/security/cve/CVE-2024-2004",
            "https://curl.se/docs/CVE-2024-2004.html",
            "https://curl.se/docs/CVE-2024-2004.json",
            "https://hackerone.com/reports/2384833",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/2D44YLAUFJU6BZ4XFG2FYV7SBKXB5IZ6/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/GMD6UYKCCRCYETWQZUJ65ZRFULT6SHLI/",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-2004",
            "https://security.netapp.com/advisory/ntap-20240524-0006/",
            "https://support.apple.com/kb/HT214118",
            "https://support.apple.com/kb/HT214119",
            "https://support.apple.com/kb/HT214120",
            "https://ubuntu.com/security/notices/USN-6718-1",
            "https://ubuntu.com/security/notices/USN-6718-3",
            "https://www.cve.org/CVERecord?id=CVE-2024-2004"
          ],
          "PublishedDate": "2024-03-27T08:15:41.173Z",
          "LastModifiedDate": "2024-07-30T02:15:05.32Z"
        },
        {
          "VulnerabilityID": "CVE-2024-2379",
          "PkgID": "libcurl@8.5.0-r0",
          "PkgName": "libcurl",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/libcurl@8.5.0-r0?arch=aarch64\u0026distro=3.19.1",
            "UID": "667d9078ceac1329"
          },
          "InstalledVersion": "8.5.0-r0",
          "FixedVersion": "8.7.1-r0",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:5ea2e59d5bc556b78ceb30c39b0b7be8e6a7c511150811cf7c445275c485c502",
            "DiffID": "sha256:53a2763a2f061ad8aa06c347fd3029b89e1b7d6b56be8d0df8e63fc8da00ef02"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-2379",
          "DataSource": {
            "ID": "alpine",
            "Name": "Alpine Secdb",
            "URL": "https://secdb.alpinelinux.org/"
          },
          "Title": "curl: QUIC certificate check bypass with wolfSSL",
          "Description": "libcurl skips the certificate verification for a QUIC connection under certain conditions, when built to use wolfSSL. If told to use an unknown/bad cipher or curve, the error path accidentally skips the verification and returns OK, thus ignoring any certificate problems.",
          "Severity": "MEDIUM",
          "VendorSeverity": {
            "redhat": 1
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
              "V3Score": 5.4
            }
          },
          "References": [
            "http://seclists.org/fulldisclosure/2024/Jul/18",
            "http://seclists.org/fulldisclosure/2024/Jul/19",
            "http://seclists.org/fulldisclosure/2024/Jul/20",
            "http://www.openwall.com/lists/oss-security/2024/03/27/2",
            "https://access.redhat.com/security/cve/CVE-2024-2379",
            "https://curl.se/docs/CVE-2024-2379.html",
            "https://curl.se/docs/CVE-2024-2379.json",
            "https://hackerone.com/reports/2410774",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-2379",
            "https://security.netapp.com/advisory/ntap-20240531-0001/",
            "https://support.apple.com/kb/HT214118",
            "https://support.apple.com/kb/HT214119",
            "https://support.apple.com/kb/HT214120",
            "https://www.cve.org/CVERecord?id=CVE-2024-2379"
          ],
          "PublishedDate": "2024-03-27T08:15:41.23Z",
          "LastModifiedDate": "2024-07-30T02:15:05.397Z"
        },
        {
          "VulnerabilityID": "CVE-2024-2466",
          "PkgID": "libcurl@8.5.0-r0",
          "PkgName": "libcurl",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/libcurl@8.5.0-r0?arch=aarch64\u0026distro=3.19.1",
            "UID": "667d9078ceac1329"
          },
          "InstalledVersion": "8.5.0-r0",
          "FixedVersion": "8.7.1-r0",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:5ea2e59d5bc556b78ceb30c39b0b7be8e6a7c511150811cf7c445275c485c502",
            "DiffID": "sha256:53a2763a2f061ad8aa06c347fd3029b89e1b7d6b56be8d0df8e63fc8da00ef02"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-2466",
          "DataSource": {
            "ID": "alpine",
            "Name": "Alpine Secdb",
            "URL": "https://secdb.alpinelinux.org/"
          },
          "Title": "curl: TLS certificate check bypass with mbedTLS",
          "Description": "libcurl did not check the server certificate of TLS connections done to a host specified as an IP address, when built to use mbedTLS.  libcurl would wrongly avoid using the set hostname function when the specified hostname was given as an IP address, therefore completely skipping the certificate check. This affects all uses of TLS protocols (HTTPS, FTPS, IMAPS, POPS3, SMTPS, etc).",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-297"
          ],
          "VendorSeverity": {
            "azure": 2,
            "cbl-mariner": 2,
            "redhat": 2
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:H/A:N",
              "V3Score": 5.3
            }
          },
          "References": [
            "http://seclists.org/fulldisclosure/2024/Jul/18",
            "http://seclists.org/fulldisclosure/2024/Jul/19",
            "http://seclists.org/fulldisclosure/2024/Jul/20",
            "http://www.openwall.com/lists/oss-security/2024/03/27/4",
            "https://access.redhat.com/security/cve/CVE-2024-2466",
            "https://curl.se/docs/CVE-2024-2466.html",
            "https://curl.se/docs/CVE-2024-2466.json",
            "https://hackerone.com/reports/2416725",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-2466",
            "https://security.netapp.com/advisory/ntap-20240503-0010/",
            "https://support.apple.com/kb/HT214118",
            "https://support.apple.com/kb/HT214119",
            "https://support.apple.com/kb/HT214120",
            "https://www.cve.org/CVERecord?id=CVE-2024-2466"
          ],
          "PublishedDate": "2024-03-27T08:15:41.343Z",
          "LastModifiedDate": "2024-08-23T19:35:12.65Z"
        },
        {
          "VulnerabilityID": "CVE-2024-6874",
          "PkgID": "libcurl@8.5.0-r0",
          "PkgName": "libcurl",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/libcurl@8.5.0-r0?arch=aarch64\u0026distro=3.19.1",
            "UID": "667d9078ceac1329"
          },
          "InstalledVersion": "8.5.0-r0",
          "FixedVersion": "8.9.0-r0",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:5ea2e59d5bc556b78ceb30c39b0b7be8e6a7c511150811cf7c445275c485c502",
            "DiffID": "sha256:53a2763a2f061ad8aa06c347fd3029b89e1b7d6b56be8d0df8e63fc8da00ef02"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-6874",
          "DataSource": {
            "ID": "alpine",
            "Name": "Alpine Secdb",
            "URL": "https://secdb.alpinelinux.org/"
          },
          "Title": "curl: macidn punycode buffer overread",
          "Description": "libcurl's URL API function\n[curl_url_get()](https://curl.se/libcurl/c/curl_url_get.html) offers punycode\nconversions, to and from IDN. Asking to convert a name that is exactly 256\nbytes, libcurl ends up reading outside of a stack based buffer when built to\nuse the *macidn* IDN backend. The conversion function then fills up the\nprovided buffer exactly - but does not null terminate the string.\n\nThis flaw can lead to stack contents accidently getting returned as part of\nthe converted string.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-125"
          ],
          "VendorSeverity": {
            "nvd": 2,
            "redhat": 1
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
              "V3Score": 4.3
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
              "V3Score": 5.3
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2024/07/24/2",
            "https://access.redhat.com/security/cve/CVE-2024-6874",
            "https://curl.se/docs/CVE-2024-6874.html",
            "https://curl.se/docs/CVE-2024-6874.json",
            "https://hackerone.com/reports/2604391",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-6874",
            "https://www.cve.org/CVERecord?id=CVE-2024-6874"
          ],
          "PublishedDate": "2024-07-24T08:15:03.413Z",
          "LastModifiedDate": "2024-09-10T15:27:04.19Z"
        },
        {
          "VulnerabilityID": "CVE-2024-45490",
          "PkgID": "libexpat@2.6.2-r0",
          "PkgName": "libexpat",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/libexpat@2.6.2-r0?arch=aarch64\u0026distro=3.19.1",
            "UID": "8b6fba159a7b0a60"
          },
          "InstalledVersion": "2.6.2-r0",
          "FixedVersion": "2.6.3-r0",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:2382f499efd6a239346d1f41dd0010ef2e0974766faeff351ee66d0ad6a99311",
            "DiffID": "sha256:1fe037e9153d3390f9f6f775c05084cc49c55877b3785a00de5510f977aae8aa"
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
            "PURL": "pkg:apk/alpine/libexpat@2.6.2-r0?arch=aarch64\u0026distro=3.19.1",
            "UID": "8b6fba159a7b0a60"
          },
          "InstalledVersion": "2.6.2-r0",
          "FixedVersion": "2.6.3-r0",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:2382f499efd6a239346d1f41dd0010ef2e0974766faeff351ee66d0ad6a99311",
            "DiffID": "sha256:1fe037e9153d3390f9f6f775c05084cc49c55877b3785a00de5510f977aae8aa"
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
            "PURL": "pkg:apk/alpine/libexpat@2.6.2-r0?arch=aarch64\u0026distro=3.19.1",
            "UID": "8b6fba159a7b0a60"
          },
          "InstalledVersion": "2.6.2-r0",
          "FixedVersion": "2.6.3-r0",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:2382f499efd6a239346d1f41dd0010ef2e0974766faeff351ee66d0ad6a99311",
            "DiffID": "sha256:1fe037e9153d3390f9f6f775c05084cc49c55877b3785a00de5510f977aae8aa"
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
          "VulnerabilityID": "CVE-2024-4603",
          "PkgID": "libssl3@3.1.4-r6",
          "PkgName": "libssl3",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/libssl3@3.1.4-r6?arch=aarch64\u0026distro=3.19.1",
            "UID": "4893f57f9128332"
          },
          "InstalledVersion": "3.1.4-r6",
          "FixedVersion": "3.1.5-r0",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:2382f499efd6a239346d1f41dd0010ef2e0974766faeff351ee66d0ad6a99311",
            "DiffID": "sha256:1fe037e9153d3390f9f6f775c05084cc49c55877b3785a00de5510f977aae8aa"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-4603",
          "DataSource": {
            "ID": "alpine",
            "Name": "Alpine Secdb",
            "URL": "https://secdb.alpinelinux.org/"
          },
          "Title": "openssl: Excessive time spent checking DSA keys and parameters",
          "Description": "Issue summary: Checking excessively long DSA keys or parameters may be very\nslow.\n\nImpact summary: Applications that use the functions EVP_PKEY_param_check()\nor EVP_PKEY_public_check() to check a DSA public key or DSA parameters may\nexperience long delays. Where the key or parameters that are being checked\nhave been obtained from an untrusted source this may lead to a Denial of\nService.\n\nThe functions EVP_PKEY_param_check() or EVP_PKEY_public_check() perform\nvarious checks on DSA parameters. Some of those computations take a long time\nif the modulus (`p` parameter) is too large.\n\nTrying to use a very large modulus is slow and OpenSSL will not allow using\npublic keys with a modulus which is over 10,000 bits in length for signature\nverification. However the key and parameter check functions do not limit\nthe modulus size when performing the checks.\n\nAn application that calls EVP_PKEY_param_check() or EVP_PKEY_public_check()\nand supplies a key or parameters obtained from an untrusted source could be\nvulnerable to a Denial of Service attack.\n\nThese functions are not called by OpenSSL itself on untrusted DSA keys so\nonly applications that directly call these functions may be vulnerable.\n\nAlso vulnerable are the OpenSSL pkey and pkeyparam command line applications\nwhen using the `-check` option.\n\nThe OpenSSL SSL/TLS implementation is not affected by this issue.\n\nThe OpenSSL 3.0 and 3.1 FIPS providers are affected by this issue.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-834"
          ],
          "VendorSeverity": {
            "amazon": 2,
            "azure": 2,
            "cbl-mariner": 2,
            "redhat": 1,
            "ubuntu": 1
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
              "V3Score": 5.3
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2024/05/16/2",
            "https://access.redhat.com/security/cve/CVE-2024-4603",
            "https://github.com/openssl/openssl/commit/3559e868e58005d15c6013a0c1fd832e51c73397",
            "https://github.com/openssl/openssl/commit/53ea06486d296b890d565fb971b2764fcd826e7e",
            "https://github.com/openssl/openssl/commit/9c39b3858091c152f52513c066ff2c5a47969f0d",
            "https://github.com/openssl/openssl/commit/da343d0605c826ef197aceedc67e8e04f065f740",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-4603",
            "https://security.netapp.com/advisory/ntap-20240621-0001/",
            "https://ubuntu.com/security/notices/USN-6937-1",
            "https://www.cve.org/CVERecord?id=CVE-2024-4603",
            "https://www.openssl.org/news/secadv/20240516.txt"
          ],
          "PublishedDate": "2024-05-16T16:15:10.643Z",
          "LastModifiedDate": "2024-08-13T16:35:05.013Z"
        },
        {
          "VulnerabilityID": "CVE-2024-4741",
          "PkgID": "libssl3@3.1.4-r6",
          "PkgName": "libssl3",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/libssl3@3.1.4-r6?arch=aarch64\u0026distro=3.19.1",
            "UID": "4893f57f9128332"
          },
          "InstalledVersion": "3.1.4-r6",
          "FixedVersion": "3.1.6-r0",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:2382f499efd6a239346d1f41dd0010ef2e0974766faeff351ee66d0ad6a99311",
            "DiffID": "sha256:1fe037e9153d3390f9f6f775c05084cc49c55877b3785a00de5510f977aae8aa"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-4741",
          "DataSource": {
            "ID": "alpine",
            "Name": "Alpine Secdb",
            "URL": "https://secdb.alpinelinux.org/"
          },
          "Title": "openssl: Use After Free with SSL_free_buffers",
          "Description": "A use-after-free vulnerability was found in OpenSSL. Calling the OpenSSL API SSL_free_buffers function may cause memory to be accessed that was previously freed in some situations.",
          "Severity": "MEDIUM",
          "VendorSeverity": {
            "amazon": 2,
            "cbl-mariner": 3,
            "photon": 2,
            "redhat": 1,
            "ubuntu": 1
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L",
              "V3Score": 5.6
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2024-4741",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-4741",
            "https://ubuntu.com/security/notices/USN-6937-1",
            "https://www.cve.org/CVERecord?id=CVE-2024-4741",
            "https://www.openssl.org/news/secadv/20240528.txt"
          ]
        },
        {
          "VulnerabilityID": "CVE-2024-5535",
          "PkgID": "libssl3@3.1.4-r6",
          "PkgName": "libssl3",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/libssl3@3.1.4-r6?arch=aarch64\u0026distro=3.19.1",
            "UID": "4893f57f9128332"
          },
          "InstalledVersion": "3.1.4-r6",
          "FixedVersion": "3.1.6-r0",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:2382f499efd6a239346d1f41dd0010ef2e0974766faeff351ee66d0ad6a99311",
            "DiffID": "sha256:1fe037e9153d3390f9f6f775c05084cc49c55877b3785a00de5510f977aae8aa"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-5535",
          "DataSource": {
            "ID": "alpine",
            "Name": "Alpine Secdb",
            "URL": "https://secdb.alpinelinux.org/"
          },
          "Title": "openssl: SSL_select_next_proto buffer overread",
          "Description": "Issue summary: Calling the OpenSSL API function SSL_select_next_proto with an\nempty supported client protocols buffer may cause a crash or memory contents to\nbe sent to the peer.\n\nImpact summary: A buffer overread can have a range of potential consequences\nsuch as unexpected application beahviour or a crash. In particular this issue\ncould result in up to 255 bytes of arbitrary private data from memory being sent\nto the peer leading to a loss of confidentiality. However, only applications\nthat directly call the SSL_select_next_proto function with a 0 length list of\nsupported client protocols are affected by this issue. This would normally never\nbe a valid scenario and is typically not under attacker control but may occur by\naccident in the case of a configuration or programming error in the calling\napplication.\n\nThe OpenSSL API function SSL_select_next_proto is typically used by TLS\napplications that support ALPN (Application Layer Protocol Negotiation) or NPN\n(Next Protocol Negotiation). NPN is older, was never standardised and\nis deprecated in favour of ALPN. We believe that ALPN is significantly more\nwidely deployed than NPN. The SSL_select_next_proto function accepts a list of\nprotocols from the server and a list of protocols from the client and returns\nthe first protocol that appears in the server list that also appears in the\nclient list. In the case of no overlap between the two lists it returns the\nfirst item in the client list. In either case it will signal whether an overlap\nbetween the two lists was found. In the case where SSL_select_next_proto is\ncalled with a zero length client list it fails to notice this condition and\nreturns the memory immediately following the client list pointer (and reports\nthat there was no overlap in the lists).\n\nThis function is typically called from a server side application callback for\nALPN or a client side application callback for NPN. In the case of ALPN the list\nof protocols supplied by the client is guaranteed by libssl to never be zero in\nlength. The list of server protocols comes from the application and should never\nnormally be expected to be of zero length. In this case if the\nSSL_select_next_proto function has been called as expected (with the list\nsupplied by the client passed in the client/client_len parameters), then the\napplication will not be vulnerable to this issue. If the application has\naccidentally been configured with a zero length server list, and has\naccidentally passed that zero length server list in the client/client_len\nparameters, and has additionally failed to correctly handle a \"no overlap\"\nresponse (which would normally result in a handshake failure in ALPN) then it\nwill be vulnerable to this problem.\n\nIn the case of NPN, the protocol permits the client to opportunistically select\na protocol when there is no overlap. OpenSSL returns the first client protocol\nin the no overlap case in support of this. The list of client protocols comes\nfrom the application and should never normally be expected to be of zero length.\nHowever if the SSL_select_next_proto function is accidentally called with a\nclient_len of 0 then an invalid memory pointer will be returned instead. If the\napplication uses this output as the opportunistic protocol then the loss of\nconfidentiality will occur.\n\nThis issue has been assessed as Low severity because applications are most\nlikely to be vulnerable if they are using NPN instead of ALPN - but NPN is not\nwidely used. It also requires an application configuration or programming error.\nFinally, this issue would not typically be under attacker control making active\nexploitation unlikely.\n\nThe FIPS modules in 3.3, 3.2, 3.1 and 3.0 are not affected by this issue.\n\nDue to the low severity of this issue we are not issuing new releases of\nOpenSSL at this time. The fix will be included in the next releases when they\nbecome available.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-200"
          ],
          "VendorSeverity": {
            "amazon": 2,
            "azure": 2,
            "cbl-mariner": 4,
            "photon": 4,
            "redhat": 1,
            "ubuntu": 1
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 5.9
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2024/06/27/1",
            "http://www.openwall.com/lists/oss-security/2024/06/28/4",
            "https://access.redhat.com/security/cve/CVE-2024-5535",
            "https://github.com/openssl/openssl/commit/4ada436a1946cbb24db5ab4ca082b69c1bc10f37",
            "https://github.com/openssl/openssl/commit/99fb785a5f85315b95288921a321a935ea29a51e",
            "https://github.com/openssl/openssl/commit/cf6f91f6121f4db167405db2f0de410a456f260c",
            "https://github.com/openssl/openssl/commit/e86ac436f0bd54d4517745483e2315650fae7b2c",
            "https://github.openssl.org/openssl/extended-releases/commit/9947251413065a05189a63c9b7a6c1d4e224c21c",
            "https://github.openssl.org/openssl/extended-releases/commit/b78ec0824da857223486660177d3b1f255c65d87",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-5535",
            "https://openssl.org/news/secadv/20240627.txt",
            "https://security.netapp.com/advisory/ntap-20240712-0005/",
            "https://ubuntu.com/security/notices/USN-6937-1",
            "https://www.cve.org/CVERecord?id=CVE-2024-5535",
            "https://www.openssl.org/news/secadv/20240627.txt"
          ],
          "PublishedDate": "2024-06-27T11:15:24.447Z",
          "LastModifiedDate": "2024-07-12T14:15:16.79Z"
        },
        {
          "VulnerabilityID": "CVE-2024-6119",
          "PkgID": "libssl3@3.1.4-r6",
          "PkgName": "libssl3",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/libssl3@3.1.4-r6?arch=aarch64\u0026distro=3.19.1",
            "UID": "4893f57f9128332"
          },
          "InstalledVersion": "3.1.4-r6",
          "FixedVersion": "3.1.7-r0",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:2382f499efd6a239346d1f41dd0010ef2e0974766faeff351ee66d0ad6a99311",
            "DiffID": "sha256:1fe037e9153d3390f9f6f775c05084cc49c55877b3785a00de5510f977aae8aa"
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
          "VulnerabilityID": "CVE-2024-34459",
          "PkgID": "libxml2@2.11.7-r0",
          "PkgName": "libxml2",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/libxml2@2.11.7-r0?arch=aarch64\u0026distro=3.19.1",
            "UID": "c84826888c50e4a1"
          },
          "InstalledVersion": "2.11.7-r0",
          "FixedVersion": "2.11.8-r0",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:5ea2e59d5bc556b78ceb30c39b0b7be8e6a7c511150811cf7c445275c485c502",
            "DiffID": "sha256:53a2763a2f061ad8aa06c347fd3029b89e1b7d6b56be8d0df8e63fc8da00ef02"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-34459",
          "DataSource": {
            "ID": "alpine",
            "Name": "Alpine Secdb",
            "URL": "https://secdb.alpinelinux.org/"
          },
          "Title": "libxml2: buffer over-read in xmlHTMLPrintFileContext in xmllint.c",
          "Description": "An issue was discovered in xmllint (from libxml2) before 2.11.8 and 2.12.x before 2.12.7. Formatting error messages with xmllint --htmlout can result in a buffer over-read in xmlHTMLPrintFileContext in xmllint.c.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-122"
          ],
          "VendorSeverity": {
            "cbl-mariner": 2,
            "photon": 2,
            "redhat": 1
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
              "V3Score": 5.5
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2024-34459",
            "https://gitlab.gnome.org/GNOME/libxml2/-/issues/720",
            "https://gitlab.gnome.org/GNOME/libxml2/-/releases/v2.11.8",
            "https://gitlab.gnome.org/GNOME/libxml2/-/releases/v2.12.7",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/5HVUXKYTBWT3G5DEEQX62STJQBY367NL/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/INKSSLW5VMZIXHRPZBAW4TJUX5SQKARG/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/VRDJCNQP32LV56KESUQ5SNZKAJWSZZRI/",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-34459",
            "https://www.cve.org/CVERecord?id=CVE-2024-34459"
          ],
          "PublishedDate": "2024-05-14T15:39:11.917Z",
          "LastModifiedDate": "2024-08-22T18:35:08.623Z"
        },
        {
          "VulnerabilityID": "CVE-2024-22020",
          "PkgID": "nodejs@20.12.1-r0",
          "PkgName": "nodejs",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/nodejs@20.12.1-r0?arch=aarch64\u0026distro=3.19.1",
            "UID": "f905448cbd0cf29b"
          },
          "InstalledVersion": "20.12.1-r0",
          "FixedVersion": "20.15.1-r0",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:5ea2e59d5bc556b78ceb30c39b0b7be8e6a7c511150811cf7c445275c485c502",
            "DiffID": "sha256:53a2763a2f061ad8aa06c347fd3029b89e1b7d6b56be8d0df8e63fc8da00ef02"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-22020",
          "DataSource": {
            "ID": "alpine",
            "Name": "Alpine Secdb",
            "URL": "https://secdb.alpinelinux.org/"
          },
          "Title": "nodejs: Bypass network import restriction via data URL",
          "Description": "A security flaw in Node.js  allows a bypass of network import restrictions.\nBy embedding non-network imports in data URLs, an attacker can execute arbitrary code, compromising system security.\nVerified on various platforms, the vulnerability is mitigated by forbidding data URLs in network imports.\nExploiting this flaw can violate network import security, posing a risk to developers and servers.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-284"
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
              "V3Vector": "CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:L/I:H/A:H",
              "V3Score": 6.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:L/I:H/A:H",
              "V3Score": 6.5
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2024/07/11/6",
            "http://www.openwall.com/lists/oss-security/2024/07/19/3",
            "https://access.redhat.com/errata/RHSA-2024:6147",
            "https://access.redhat.com/security/cve/CVE-2024-22020",
            "https://bugzilla.redhat.com/2293200",
            "https://bugzilla.redhat.com/2296417",
            "https://errata.almalinux.org/9/ALSA-2024-6147.html",
            "https://hackerone.com/reports/2092749",
            "https://linux.oracle.com/cve/CVE-2024-22020.html",
            "https://linux.oracle.com/errata/ELSA-2024-6148.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-22020",
            "https://www.cve.org/CVERecord?id=CVE-2024-22020"
          ],
          "PublishedDate": "2024-07-09T02:15:09.973Z",
          "LastModifiedDate": "2024-07-19T14:15:05.863Z"
        },
        {
          "VulnerabilityID": "CVE-2024-22018",
          "PkgID": "nodejs@20.12.1-r0",
          "PkgName": "nodejs",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/nodejs@20.12.1-r0?arch=aarch64\u0026distro=3.19.1",
            "UID": "f905448cbd0cf29b"
          },
          "InstalledVersion": "20.12.1-r0",
          "FixedVersion": "20.15.1-r0",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:5ea2e59d5bc556b78ceb30c39b0b7be8e6a7c511150811cf7c445275c485c502",
            "DiffID": "sha256:53a2763a2f061ad8aa06c347fd3029b89e1b7d6b56be8d0df8e63fc8da00ef02"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-22018",
          "DataSource": {
            "ID": "alpine",
            "Name": "Alpine Secdb",
            "URL": "https://secdb.alpinelinux.org/"
          },
          "Title": "nodejs: fs.lstat bypasses permission model",
          "Description": "A vulnerability has been identified in Node.js, affecting users of the experimental permission model when the --allow-fs-read flag is used.\nThis flaw arises from an inadequate permission model that fails to restrict file stats through the fs.lstat API. As a result, malicious actors can retrieve stats from files that they do not have explicit read access to.\nThis vulnerability affects all users using the experimental permission model in Node.js 20 and Node.js 21.\nPlease note that at the time this CVE was issued, the permission model is an experimental feature of Node.js.",
          "Severity": "LOW",
          "VendorSeverity": {
            "alma": 2,
            "bitnami": 1,
            "oracle-oval": 2,
            "photon": 1,
            "redhat": 1
          },
          "CVSS": {
            "bitnami": {
              "V3Vector": "CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
              "V3Score": 2.9
            },
            "redhat": {
              "V3Vector": "CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
              "V3Score": 2.9
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2024/07/11/6",
            "http://www.openwall.com/lists/oss-security/2024/07/19/3",
            "https://access.redhat.com/errata/RHSA-2024:5815",
            "https://access.redhat.com/security/cve/CVE-2024-22018",
            "https://bugzilla.redhat.com/2296417",
            "https://bugzilla.redhat.com/2296990",
            "https://bugzilla.redhat.com/2299281",
            "https://errata.almalinux.org/9/ALSA-2024-5815.html",
            "https://hackerone.com/reports/2145862",
            "https://linux.oracle.com/cve/CVE-2024-22018.html",
            "https://linux.oracle.com/errata/ELSA-2024-5815.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-22018",
            "https://www.cve.org/CVERecord?id=CVE-2024-22018"
          ],
          "PublishedDate": "2024-07-10T02:15:03.16Z",
          "LastModifiedDate": "2024-07-19T14:15:05.763Z"
        },
        {
          "VulnerabilityID": "CVE-2024-36137",
          "PkgID": "nodejs@20.12.1-r0",
          "PkgName": "nodejs",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/nodejs@20.12.1-r0?arch=aarch64\u0026distro=3.19.1",
            "UID": "f905448cbd0cf29b"
          },
          "InstalledVersion": "20.12.1-r0",
          "FixedVersion": "20.15.1-r0",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:5ea2e59d5bc556b78ceb30c39b0b7be8e6a7c511150811cf7c445275c485c502",
            "DiffID": "sha256:53a2763a2f061ad8aa06c347fd3029b89e1b7d6b56be8d0df8e63fc8da00ef02"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-36137",
          "DataSource": {
            "ID": "alpine",
            "Name": "Alpine Secdb",
            "URL": "https://secdb.alpinelinux.org/"
          },
          "Title": "nodejs: fs.fchown/fchmod bypasses permission model",
          "Description": "A vulnerability has been identified in Node.js, affecting users of the experimental permission model when the --allow-fs-write flag is used.\r\n\r\nNode.js Permission Model do not operate on file descriptors, however, operations such as fs.fchown or fs.fchmod can use a \"read-only\" file descriptor to change the owner and permissions of a file.",
          "Severity": "LOW",
          "VendorSeverity": {
            "alma": 2,
            "bitnami": 1,
            "oracle-oval": 2,
            "photon": 2,
            "redhat": 1
          },
          "CVSS": {
            "bitnami": {
              "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N",
              "V3Score": 3.3
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N",
              "V3Score": 3.9
            }
          },
          "References": [
            "https://access.redhat.com/errata/RHSA-2024:5815",
            "https://access.redhat.com/security/cve/CVE-2024-36137",
            "https://bugzilla.redhat.com/2296417",
            "https://bugzilla.redhat.com/2296990",
            "https://bugzilla.redhat.com/2299281",
            "https://errata.almalinux.org/9/ALSA-2024-5815.html",
            "https://linux.oracle.com/cve/CVE-2024-36137.html",
            "https://linux.oracle.com/errata/ELSA-2024-5815.html",
            "https://nodejs.org/en/blog/vulnerability/july-2024-security-releases",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-36137",
            "https://www.cve.org/CVERecord?id=CVE-2024-36137"
          ],
          "PublishedDate": "2024-09-07T16:15:02.41Z",
          "LastModifiedDate": "2024-09-09T13:03:38.303Z"
        },
        {
          "VulnerabilityID": "CVE-2024-4603",
          "PkgID": "openssl@3.1.4-r6",
          "PkgName": "openssl",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/openssl@3.1.4-r6?arch=aarch64\u0026distro=3.19.1",
            "UID": "fb2ba1d906603dc"
          },
          "InstalledVersion": "3.1.4-r6",
          "FixedVersion": "3.1.5-r0",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:5ea2e59d5bc556b78ceb30c39b0b7be8e6a7c511150811cf7c445275c485c502",
            "DiffID": "sha256:53a2763a2f061ad8aa06c347fd3029b89e1b7d6b56be8d0df8e63fc8da00ef02"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-4603",
          "DataSource": {
            "ID": "alpine",
            "Name": "Alpine Secdb",
            "URL": "https://secdb.alpinelinux.org/"
          },
          "Title": "openssl: Excessive time spent checking DSA keys and parameters",
          "Description": "Issue summary: Checking excessively long DSA keys or parameters may be very\nslow.\n\nImpact summary: Applications that use the functions EVP_PKEY_param_check()\nor EVP_PKEY_public_check() to check a DSA public key or DSA parameters may\nexperience long delays. Where the key or parameters that are being checked\nhave been obtained from an untrusted source this may lead to a Denial of\nService.\n\nThe functions EVP_PKEY_param_check() or EVP_PKEY_public_check() perform\nvarious checks on DSA parameters. Some of those computations take a long time\nif the modulus (`p` parameter) is too large.\n\nTrying to use a very large modulus is slow and OpenSSL will not allow using\npublic keys with a modulus which is over 10,000 bits in length for signature\nverification. However the key and parameter check functions do not limit\nthe modulus size when performing the checks.\n\nAn application that calls EVP_PKEY_param_check() or EVP_PKEY_public_check()\nand supplies a key or parameters obtained from an untrusted source could be\nvulnerable to a Denial of Service attack.\n\nThese functions are not called by OpenSSL itself on untrusted DSA keys so\nonly applications that directly call these functions may be vulnerable.\n\nAlso vulnerable are the OpenSSL pkey and pkeyparam command line applications\nwhen using the `-check` option.\n\nThe OpenSSL SSL/TLS implementation is not affected by this issue.\n\nThe OpenSSL 3.0 and 3.1 FIPS providers are affected by this issue.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-834"
          ],
          "VendorSeverity": {
            "amazon": 2,
            "azure": 2,
            "cbl-mariner": 2,
            "redhat": 1,
            "ubuntu": 1
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
              "V3Score": 5.3
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2024/05/16/2",
            "https://access.redhat.com/security/cve/CVE-2024-4603",
            "https://github.com/openssl/openssl/commit/3559e868e58005d15c6013a0c1fd832e51c73397",
            "https://github.com/openssl/openssl/commit/53ea06486d296b890d565fb971b2764fcd826e7e",
            "https://github.com/openssl/openssl/commit/9c39b3858091c152f52513c066ff2c5a47969f0d",
            "https://github.com/openssl/openssl/commit/da343d0605c826ef197aceedc67e8e04f065f740",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-4603",
            "https://security.netapp.com/advisory/ntap-20240621-0001/",
            "https://ubuntu.com/security/notices/USN-6937-1",
            "https://www.cve.org/CVERecord?id=CVE-2024-4603",
            "https://www.openssl.org/news/secadv/20240516.txt"
          ],
          "PublishedDate": "2024-05-16T16:15:10.643Z",
          "LastModifiedDate": "2024-08-13T16:35:05.013Z"
        },
        {
          "VulnerabilityID": "CVE-2024-4741",
          "PkgID": "openssl@3.1.4-r6",
          "PkgName": "openssl",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/openssl@3.1.4-r6?arch=aarch64\u0026distro=3.19.1",
            "UID": "fb2ba1d906603dc"
          },
          "InstalledVersion": "3.1.4-r6",
          "FixedVersion": "3.1.6-r0",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:5ea2e59d5bc556b78ceb30c39b0b7be8e6a7c511150811cf7c445275c485c502",
            "DiffID": "sha256:53a2763a2f061ad8aa06c347fd3029b89e1b7d6b56be8d0df8e63fc8da00ef02"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-4741",
          "DataSource": {
            "ID": "alpine",
            "Name": "Alpine Secdb",
            "URL": "https://secdb.alpinelinux.org/"
          },
          "Title": "openssl: Use After Free with SSL_free_buffers",
          "Description": "A use-after-free vulnerability was found in OpenSSL. Calling the OpenSSL API SSL_free_buffers function may cause memory to be accessed that was previously freed in some situations.",
          "Severity": "MEDIUM",
          "VendorSeverity": {
            "amazon": 2,
            "cbl-mariner": 3,
            "photon": 2,
            "redhat": 1,
            "ubuntu": 1
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L",
              "V3Score": 5.6
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2024-4741",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-4741",
            "https://ubuntu.com/security/notices/USN-6937-1",
            "https://www.cve.org/CVERecord?id=CVE-2024-4741",
            "https://www.openssl.org/news/secadv/20240528.txt"
          ]
        },
        {
          "VulnerabilityID": "CVE-2024-5535",
          "PkgID": "openssl@3.1.4-r6",
          "PkgName": "openssl",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/openssl@3.1.4-r6?arch=aarch64\u0026distro=3.19.1",
            "UID": "fb2ba1d906603dc"
          },
          "InstalledVersion": "3.1.4-r6",
          "FixedVersion": "3.1.6-r0",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:5ea2e59d5bc556b78ceb30c39b0b7be8e6a7c511150811cf7c445275c485c502",
            "DiffID": "sha256:53a2763a2f061ad8aa06c347fd3029b89e1b7d6b56be8d0df8e63fc8da00ef02"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-5535",
          "DataSource": {
            "ID": "alpine",
            "Name": "Alpine Secdb",
            "URL": "https://secdb.alpinelinux.org/"
          },
          "Title": "openssl: SSL_select_next_proto buffer overread",
          "Description": "Issue summary: Calling the OpenSSL API function SSL_select_next_proto with an\nempty supported client protocols buffer may cause a crash or memory contents to\nbe sent to the peer.\n\nImpact summary: A buffer overread can have a range of potential consequences\nsuch as unexpected application beahviour or a crash. In particular this issue\ncould result in up to 255 bytes of arbitrary private data from memory being sent\nto the peer leading to a loss of confidentiality. However, only applications\nthat directly call the SSL_select_next_proto function with a 0 length list of\nsupported client protocols are affected by this issue. This would normally never\nbe a valid scenario and is typically not under attacker control but may occur by\naccident in the case of a configuration or programming error in the calling\napplication.\n\nThe OpenSSL API function SSL_select_next_proto is typically used by TLS\napplications that support ALPN (Application Layer Protocol Negotiation) or NPN\n(Next Protocol Negotiation). NPN is older, was never standardised and\nis deprecated in favour of ALPN. We believe that ALPN is significantly more\nwidely deployed than NPN. The SSL_select_next_proto function accepts a list of\nprotocols from the server and a list of protocols from the client and returns\nthe first protocol that appears in the server list that also appears in the\nclient list. In the case of no overlap between the two lists it returns the\nfirst item in the client list. In either case it will signal whether an overlap\nbetween the two lists was found. In the case where SSL_select_next_proto is\ncalled with a zero length client list it fails to notice this condition and\nreturns the memory immediately following the client list pointer (and reports\nthat there was no overlap in the lists).\n\nThis function is typically called from a server side application callback for\nALPN or a client side application callback for NPN. In the case of ALPN the list\nof protocols supplied by the client is guaranteed by libssl to never be zero in\nlength. The list of server protocols comes from the application and should never\nnormally be expected to be of zero length. In this case if the\nSSL_select_next_proto function has been called as expected (with the list\nsupplied by the client passed in the client/client_len parameters), then the\napplication will not be vulnerable to this issue. If the application has\naccidentally been configured with a zero length server list, and has\naccidentally passed that zero length server list in the client/client_len\nparameters, and has additionally failed to correctly handle a \"no overlap\"\nresponse (which would normally result in a handshake failure in ALPN) then it\nwill be vulnerable to this problem.\n\nIn the case of NPN, the protocol permits the client to opportunistically select\na protocol when there is no overlap. OpenSSL returns the first client protocol\nin the no overlap case in support of this. The list of client protocols comes\nfrom the application and should never normally be expected to be of zero length.\nHowever if the SSL_select_next_proto function is accidentally called with a\nclient_len of 0 then an invalid memory pointer will be returned instead. If the\napplication uses this output as the opportunistic protocol then the loss of\nconfidentiality will occur.\n\nThis issue has been assessed as Low severity because applications are most\nlikely to be vulnerable if they are using NPN instead of ALPN - but NPN is not\nwidely used. It also requires an application configuration or programming error.\nFinally, this issue would not typically be under attacker control making active\nexploitation unlikely.\n\nThe FIPS modules in 3.3, 3.2, 3.1 and 3.0 are not affected by this issue.\n\nDue to the low severity of this issue we are not issuing new releases of\nOpenSSL at this time. The fix will be included in the next releases when they\nbecome available.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-200"
          ],
          "VendorSeverity": {
            "amazon": 2,
            "azure": 2,
            "cbl-mariner": 4,
            "photon": 4,
            "redhat": 1,
            "ubuntu": 1
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 5.9
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2024/06/27/1",
            "http://www.openwall.com/lists/oss-security/2024/06/28/4",
            "https://access.redhat.com/security/cve/CVE-2024-5535",
            "https://github.com/openssl/openssl/commit/4ada436a1946cbb24db5ab4ca082b69c1bc10f37",
            "https://github.com/openssl/openssl/commit/99fb785a5f85315b95288921a321a935ea29a51e",
            "https://github.com/openssl/openssl/commit/cf6f91f6121f4db167405db2f0de410a456f260c",
            "https://github.com/openssl/openssl/commit/e86ac436f0bd54d4517745483e2315650fae7b2c",
            "https://github.openssl.org/openssl/extended-releases/commit/9947251413065a05189a63c9b7a6c1d4e224c21c",
            "https://github.openssl.org/openssl/extended-releases/commit/b78ec0824da857223486660177d3b1f255c65d87",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-5535",
            "https://openssl.org/news/secadv/20240627.txt",
            "https://security.netapp.com/advisory/ntap-20240712-0005/",
            "https://ubuntu.com/security/notices/USN-6937-1",
            "https://www.cve.org/CVERecord?id=CVE-2024-5535",
            "https://www.openssl.org/news/secadv/20240627.txt"
          ],
          "PublishedDate": "2024-06-27T11:15:24.447Z",
          "LastModifiedDate": "2024-07-12T14:15:16.79Z"
        },
        {
          "VulnerabilityID": "CVE-2024-6119",
          "PkgID": "openssl@3.1.4-r6",
          "PkgName": "openssl",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/openssl@3.1.4-r6?arch=aarch64\u0026distro=3.19.1",
            "UID": "fb2ba1d906603dc"
          },
          "InstalledVersion": "3.1.4-r6",
          "FixedVersion": "3.1.7-r0",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:5ea2e59d5bc556b78ceb30c39b0b7be8e6a7c511150811cf7c445275c485c502",
            "DiffID": "sha256:53a2763a2f061ad8aa06c347fd3029b89e1b7d6b56be8d0df8e63fc8da00ef02"
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
          "VulnerabilityID": "CVE-2023-42363",
          "PkgID": "ssl_client@1.36.1-r15",
          "PkgName": "ssl_client",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/ssl_client@1.36.1-r15?arch=aarch64\u0026distro=3.19.1",
            "UID": "10600a189507edea"
          },
          "InstalledVersion": "1.36.1-r15",
          "FixedVersion": "1.36.1-r17",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:bca4290a96390d7a6fc6f2f9929370d06f8dfcacba591c76e3d5c5044e7f420c",
            "DiffID": "sha256:b09314aec293bcd9a8ee5e643539437b3846f9e5e55f79e282e5f67e3026de5e"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-42363",
          "DataSource": {
            "ID": "alpine",
            "Name": "Alpine Secdb",
            "URL": "https://secdb.alpinelinux.org/"
          },
          "Title": "busybox: use-after-free in awk",
          "Description": "A use-after-free vulnerability was discovered in xasprintf function in xfuncs_printf.c:344 in BusyBox v.1.36.1.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-416"
          ],
          "VendorSeverity": {
            "azure": 2,
            "cbl-mariner": 2,
            "nvd": 2,
            "redhat": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
              "V3Score": 5.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
              "V3Score": 7.8
            }
          },
          "References": [
            "http://lists.busybox.net/pipermail/busybox/2024-May/090760.html",
            "https://access.redhat.com/security/cve/CVE-2023-42363",
            "https://bugs.busybox.net/show_bug.cgi?id=15865",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-42363",
            "https://ubuntu.com/security/notices/USN-6961-1",
            "https://www.cve.org/CVERecord?id=CVE-2023-42363"
          ],
          "PublishedDate": "2023-11-27T22:15:07.94Z",
          "LastModifiedDate": "2023-11-30T05:06:49.523Z"
        },
        {
          "VulnerabilityID": "CVE-2023-42364",
          "PkgID": "ssl_client@1.36.1-r15",
          "PkgName": "ssl_client",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/ssl_client@1.36.1-r15?arch=aarch64\u0026distro=3.19.1",
            "UID": "10600a189507edea"
          },
          "InstalledVersion": "1.36.1-r15",
          "FixedVersion": "1.36.1-r19",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:bca4290a96390d7a6fc6f2f9929370d06f8dfcacba591c76e3d5c5044e7f420c",
            "DiffID": "sha256:b09314aec293bcd9a8ee5e643539437b3846f9e5e55f79e282e5f67e3026de5e"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-42364",
          "DataSource": {
            "ID": "alpine",
            "Name": "Alpine Secdb",
            "URL": "https://secdb.alpinelinux.org/"
          },
          "Title": "busybox: use-after-free",
          "Description": "A use-after-free vulnerability in BusyBox v.1.36.1 allows attackers to cause a denial of service via a crafted awk pattern in the awk.c evaluate function.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-416"
          ],
          "VendorSeverity": {
            "nvd": 2,
            "redhat": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
              "V3Score": 5.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
              "V3Score": 7.8
            }
          },
          "References": [
            "http://lists.busybox.net/pipermail/busybox/2024-May/090762.html",
            "https://access.redhat.com/security/cve/CVE-2023-42364",
            "https://bugs.busybox.net/show_bug.cgi?id=15868",
            "https://gitlab.alpinelinux.org/alpine/aports/-/blob/master/main/busybox/CVE-2023-42364-CVE-2023-42365.patch",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-42364",
            "https://ubuntu.com/security/notices/USN-6961-1",
            "https://www.cve.org/CVERecord?id=CVE-2023-42364"
          ],
          "PublishedDate": "2023-11-27T23:15:07.313Z",
          "LastModifiedDate": "2023-11-30T05:07:10.827Z"
        },
        {
          "VulnerabilityID": "CVE-2023-42365",
          "PkgID": "ssl_client@1.36.1-r15",
          "PkgName": "ssl_client",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/ssl_client@1.36.1-r15?arch=aarch64\u0026distro=3.19.1",
            "UID": "10600a189507edea"
          },
          "InstalledVersion": "1.36.1-r15",
          "FixedVersion": "1.36.1-r19",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:bca4290a96390d7a6fc6f2f9929370d06f8dfcacba591c76e3d5c5044e7f420c",
            "DiffID": "sha256:b09314aec293bcd9a8ee5e643539437b3846f9e5e55f79e282e5f67e3026de5e"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-42365",
          "DataSource": {
            "ID": "alpine",
            "Name": "Alpine Secdb",
            "URL": "https://secdb.alpinelinux.org/"
          },
          "Title": "busybox: use-after-free",
          "Description": "A use-after-free vulnerability was discovered in BusyBox v.1.36.1 via a crafted awk pattern in the awk.c copyvar function.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-416"
          ],
          "VendorSeverity": {
            "azure": 2,
            "cbl-mariner": 2,
            "nvd": 2,
            "redhat": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
              "V3Score": 5.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
              "V3Score": 7.8
            }
          },
          "References": [
            "http://lists.busybox.net/pipermail/busybox/2024-May/090762.html",
            "https://access.redhat.com/security/cve/CVE-2023-42365",
            "https://bugs.busybox.net/show_bug.cgi?id=15871",
            "https://gitlab.alpinelinux.org/alpine/aports/-/blob/master/main/busybox/CVE-2023-42364-CVE-2023-42365.patch",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-42365",
            "https://ubuntu.com/security/notices/USN-6961-1",
            "https://www.cve.org/CVERecord?id=CVE-2023-42365"
          ],
          "PublishedDate": "2023-11-27T23:15:07.373Z",
          "LastModifiedDate": "2023-11-30T05:08:08.77Z"
        },
        {
          "VulnerabilityID": "CVE-2023-42366",
          "PkgID": "ssl_client@1.36.1-r15",
          "PkgName": "ssl_client",
          "PkgIdentifier": {
            "PURL": "pkg:apk/alpine/ssl_client@1.36.1-r15?arch=aarch64\u0026distro=3.19.1",
            "UID": "10600a189507edea"
          },
          "InstalledVersion": "1.36.1-r15",
          "FixedVersion": "1.36.1-r16",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:bca4290a96390d7a6fc6f2f9929370d06f8dfcacba591c76e3d5c5044e7f420c",
            "DiffID": "sha256:b09314aec293bcd9a8ee5e643539437b3846f9e5e55f79e282e5f67e3026de5e"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-42366",
          "DataSource": {
            "ID": "alpine",
            "Name": "Alpine Secdb",
            "URL": "https://secdb.alpinelinux.org/"
          },
          "Title": "busybox: A heap-buffer-overflow",
          "Description": "A heap-buffer-overflow was discovered in BusyBox v.1.36.1 in the next_token function at awk.c:1159.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-787"
          ],
          "VendorSeverity": {
            "nvd": 2,
            "redhat": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
              "V3Score": 5.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H",
              "V3Score": 7.1
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2023-42366",
            "https://bugs.busybox.net/show_bug.cgi?id=15874",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-42366",
            "https://www.cve.org/CVERecord?id=CVE-2023-42366"
          ],
          "PublishedDate": "2023-11-27T23:15:07.42Z",
          "LastModifiedDate": "2023-11-30T05:08:23.197Z"
        }
      ]
    },
    {
      "Target": "Node.js",
      "Class": "lang-pkgs",
      "Type": "node-pkg"
    },
    {
      "Target": "Python",
      "Class": "lang-pkgs",
      "Type": "python-pkg",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2024-6345",
          "PkgName": "setuptools",
          "PkgPath": "usr/local/lib/python3.12/site-packages/setuptools-69.2.0.dist-info/METADATA",
          "PkgIdentifier": {
            "PURL": "pkg:pypi/setuptools@69.2.0",
            "UID": "5be61f576fa09bbf"
          },
          "InstalledVersion": "69.2.0",
          "FixedVersion": "70.0.0",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:553066bc513f979d48c0cd065283b35588c7bfed68d65f33ceb4c816bac9e427",
            "DiffID": "sha256:23b346ea16dd47905c76b6dbd5602af34324bd16ab0844b10914337226a5d193"
          },
          "SeveritySource": "ghsa",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-6345",
          "DataSource": {
            "ID": "ghsa",
            "Name": "GitHub Security Advisory pip",
            "URL": "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Apip"
          },
          "Title": "pypa/setuptools: Remote code execution via download functions in the package_index module in pypa/setuptools",
          "Description": "A vulnerability in the package_index module of pypa/setuptools versions up to 69.1.1 allows for remote code execution via its download functions. These functions, which are used to download packages from URLs provided by users or retrieved from package index servers, are susceptible to code injection. If these functions are exposed to user-controlled inputs, such as package URLs, they can execute arbitrary commands on the system. The issue is fixed in version 70.0.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-94"
          ],
          "VendorSeverity": {
            "alma": 3,
            "amazon": 3,
            "bitnami": 3,
            "ghsa": 3,
            "oracle-oval": 2,
            "photon": 3,
            "redhat": 3,
            "rocky": 3
          },
          "CVSS": {
            "bitnami": {
              "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
              "V3Score": 8.8
            },
            "ghsa": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
              "V3Score": 8.8
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
              "V3Score": 8.8
            }
          },
          "References": [
            "https://access.redhat.com/errata/RHSA-2024:5534",
            "https://access.redhat.com/security/cve/CVE-2024-6345",
            "https://bugzilla.redhat.com/2297771",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2297771",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-6345",
            "https://errata.almalinux.org/9/ALSA-2024-5534.html",
            "https://errata.rockylinux.org/RLSA-2024:5530",
            "https://github.com/pypa/setuptools",
            "https://github.com/pypa/setuptools/commit/88807c7062788254f654ea8c03427adc859321f0",
            "https://github.com/pypa/setuptools/pull/4332",
            "https://huntr.com/bounties/d6362117-ad57-4e83-951f-b8141c6e7ca5",
            "https://linux.oracle.com/cve/CVE-2024-6345.html",
            "https://linux.oracle.com/errata/ELSA-2024-6311.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-6345",
            "https://www.cve.org/CVERecord?id=CVE-2024-6345"
          ],
          "PublishedDate": "2024-07-15T01:15:01.73Z",
          "LastModifiedDate": "2024-07-15T13:00:34.853Z"
        }
      ]
    },
    {
      "Target": "usr/local/bin/helm",
      "Class": "lang-pkgs",
      "Type": "gobinary",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2024-41110",
          "PkgName": "github.com/docker/docker",
          "PkgIdentifier": {
            "PURL": "pkg:golang/github.com/docker/docker@v24.0.9%2Bincompatible",
            "UID": "30cbf44a917cec48"
          },
          "InstalledVersion": "v24.0.9+incompatible",
          "FixedVersion": "23.0.15, 26.1.5, 27.1.1, 25.0.6",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:5ea2e59d5bc556b78ceb30c39b0b7be8e6a7c511150811cf7c445275c485c502",
            "DiffID": "sha256:53a2763a2f061ad8aa06c347fd3029b89e1b7d6b56be8d0df8e63fc8da00ef02"
          },
          "SeveritySource": "ghsa",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-41110",
          "DataSource": {
            "ID": "ghsa",
            "Name": "GitHub Security Advisory Go",
            "URL": "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Ago"
          },
          "Title": "moby: Authz zero length regression",
          "Description": "Moby is an open-source project created by Docker for software containerization. A security vulnerability has been detected in certain versions of Docker Engine, which could allow an attacker to bypass authorization plugins (AuthZ) under specific circumstances. The base likelihood of this being exploited is low.\n\nUsing a specially-crafted API request, an Engine API client could make the daemon forward the request or response to an authorization plugin without the body. In certain circumstances, the authorization plugin may allow a request which it would have otherwise denied if the body had been forwarded to it.\n\nA security issue was discovered In 2018, where an attacker could bypass AuthZ plugins using a specially crafted API request. This could lead to unauthorized actions, including privilege escalation. Although this issue was fixed in Docker Engine v18.09.1 in January 2019, the fix was not carried forward to later major versions, resulting in a regression. Anyone who depends on authorization plugins that introspect the request and/or response body to make access control decisions is potentially impacted.\n\nDocker EE v19.03.x and all versions of Mirantis Container Runtime are not vulnerable.\n\ndocker-ce v27.1.1 containes patches to fix the vulnerability. Patches have also been merged into the master, 19.03, 20.0, 23.0, 24.0, 25.0, 26.0, and 26.1 release branches. If one is unable to upgrade immediately, avoid using AuthZ plugins and/or restrict access to the Docker API to trusted parties, following the principle of least privilege.",
          "Severity": "CRITICAL",
          "CweIDs": [
            "CWE-187",
            "CWE-444",
            "CWE-863"
          ],
          "VendorSeverity": {
            "amazon": 3,
            "azure": 4,
            "cbl-mariner": 4,
            "ghsa": 4,
            "redhat": 4
          },
          "CVSS": {
            "ghsa": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
              "V3Score": 10
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
              "V3Score": 9.9
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2024-41110",
            "https://github.com/moby/moby",
            "https://github.com/moby/moby/commit/411e817ddf710ff8e08fa193da80cb78af708191",
            "https://github.com/moby/moby/commit/42f40b1d6dd7562342f832b9cd2adf9e668eeb76",
            "https://github.com/moby/moby/commit/65cc597cea28cdc25bea3b8a86384b4251872919",
            "https://github.com/moby/moby/commit/852759a7df454cbf88db4e954c919becd48faa9b",
            "https://github.com/moby/moby/commit/a31260625655cff9ae226b51757915e275e304b0",
            "https://github.com/moby/moby/commit/a79fabbfe84117696a19671f4aa88b82d0f64fc1",
            "https://github.com/moby/moby/commit/ae160b4edddb72ef4bd71f66b975a1a1cc434f00",
            "https://github.com/moby/moby/commit/ae2b3666c517c96cbc2adf1af5591a6b00d4ec0f",
            "https://github.com/moby/moby/commit/cc13f952511154a2866bddbb7dddebfe9e83b801",
            "https://github.com/moby/moby/commit/fc274cd2ff4cf3b48c91697fb327dd1fb95588fb",
            "https://github.com/moby/moby/security/advisories/GHSA-v23v-6jw2-98fq",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-41110",
            "https://www.cve.org/CVERecord?id=CVE-2024-41110",
            "https://www.docker.com/blog/docker-security-advisory-docker-engine-authz-plugin"
          ],
          "PublishedDate": "2024-07-24T17:15:11.053Z",
          "LastModifiedDate": "2024-07-30T20:15:04.567Z"
        },
        {
          "VulnerabilityID": "CVE-2023-45288",
          "PkgName": "golang.org/x/net",
          "PkgIdentifier": {
            "PURL": "pkg:golang/golang.org/x/net@v0.17.0",
            "UID": "97c66980312c4136"
          },
          "InstalledVersion": "v0.17.0",
          "FixedVersion": "0.23.0",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:5ea2e59d5bc556b78ceb30c39b0b7be8e6a7c511150811cf7c445275c485c502",
            "DiffID": "sha256:53a2763a2f061ad8aa06c347fd3029b89e1b7d6b56be8d0df8e63fc8da00ef02"
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
          "VulnerabilityID": "CVE-2024-24790",
          "PkgName": "stdlib",
          "PkgIdentifier": {
            "PURL": "pkg:golang/stdlib@1.21.9",
            "UID": "3e00b425375e6e10"
          },
          "InstalledVersion": "1.21.9",
          "FixedVersion": "1.21.11, 1.22.4",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:5ea2e59d5bc556b78ceb30c39b0b7be8e6a7c511150811cf7c445275c485c502",
            "DiffID": "sha256:53a2763a2f061ad8aa06c347fd3029b89e1b7d6b56be8d0df8e63fc8da00ef02"
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
          "VulnerabilityID": "CVE-2024-34156",
          "PkgName": "stdlib",
          "PkgIdentifier": {
            "PURL": "pkg:golang/stdlib@1.21.9",
            "UID": "3e00b425375e6e10"
          },
          "InstalledVersion": "1.21.9",
          "FixedVersion": "1.22.7, 1.23.1",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:5ea2e59d5bc556b78ceb30c39b0b7be8e6a7c511150811cf7c445275c485c502",
            "DiffID": "sha256:53a2763a2f061ad8aa06c347fd3029b89e1b7d6b56be8d0df8e63fc8da00ef02"
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
          "VulnerabilityID": "CVE-2024-24789",
          "PkgName": "stdlib",
          "PkgIdentifier": {
            "PURL": "pkg:golang/stdlib@1.21.9",
            "UID": "3e00b425375e6e10"
          },
          "InstalledVersion": "1.21.9",
          "FixedVersion": "1.21.11, 1.22.4",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:5ea2e59d5bc556b78ceb30c39b0b7be8e6a7c511150811cf7c445275c485c502",
            "DiffID": "sha256:53a2763a2f061ad8aa06c347fd3029b89e1b7d6b56be8d0df8e63fc8da00ef02"
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
            "PURL": "pkg:golang/stdlib@1.21.9",
            "UID": "3e00b425375e6e10"
          },
          "InstalledVersion": "1.21.9",
          "FixedVersion": "1.21.12, 1.22.5",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:5ea2e59d5bc556b78ceb30c39b0b7be8e6a7c511150811cf7c445275c485c502",
            "DiffID": "sha256:53a2763a2f061ad8aa06c347fd3029b89e1b7d6b56be8d0df8e63fc8da00ef02"
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
            "PURL": "pkg:golang/stdlib@1.21.9",
            "UID": "3e00b425375e6e10"
          },
          "InstalledVersion": "1.21.9",
          "FixedVersion": "1.22.7, 1.23.1",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:5ea2e59d5bc556b78ceb30c39b0b7be8e6a7c511150811cf7c445275c485c502",
            "DiffID": "sha256:53a2763a2f061ad8aa06c347fd3029b89e1b7d6b56be8d0df8e63fc8da00ef02"
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
            "PURL": "pkg:golang/stdlib@1.21.9",
            "UID": "3e00b425375e6e10"
          },
          "InstalledVersion": "1.21.9",
          "FixedVersion": "1.22.7, 1.23.1",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:5ea2e59d5bc556b78ceb30c39b0b7be8e6a7c511150811cf7c445275c485c502",
            "DiffID": "sha256:53a2763a2f061ad8aa06c347fd3029b89e1b7d6b56be8d0df8e63fc8da00ef02"
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
      "Target": "usr/local/bin/kubectl",
      "Class": "lang-pkgs",
      "Type": "gobinary",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2024-24790",
          "PkgName": "stdlib",
          "PkgIdentifier": {
            "PURL": "pkg:golang/stdlib@1.22.2",
            "UID": "2ac0ded2c472625e"
          },
          "InstalledVersion": "1.22.2",
          "FixedVersion": "1.21.11, 1.22.4",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:5ea2e59d5bc556b78ceb30c39b0b7be8e6a7c511150811cf7c445275c485c502",
            "DiffID": "sha256:53a2763a2f061ad8aa06c347fd3029b89e1b7d6b56be8d0df8e63fc8da00ef02"
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
          "VulnerabilityID": "CVE-2024-24788",
          "PkgName": "stdlib",
          "PkgIdentifier": {
            "PURL": "pkg:golang/stdlib@1.22.2",
            "UID": "2ac0ded2c472625e"
          },
          "InstalledVersion": "1.22.2",
          "FixedVersion": "1.22.3",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:5ea2e59d5bc556b78ceb30c39b0b7be8e6a7c511150811cf7c445275c485c502",
            "DiffID": "sha256:53a2763a2f061ad8aa06c347fd3029b89e1b7d6b56be8d0df8e63fc8da00ef02"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-24788",
          "DataSource": {
            "ID": "govulndb",
            "Name": "The Go Vulnerability Database",
            "URL": "https://pkg.go.dev/vuln/"
          },
          "Title": "golang: net: malformed DNS message can cause infinite loop",
          "Description": "A malformed DNS message in response to a query can cause the Lookup functions to get stuck in an infinite loop.",
          "Severity": "HIGH",
          "VendorSeverity": {
            "alma": 2,
            "azure": 2,
            "cbl-mariner": 2,
            "oracle-oval": 2,
            "redhat": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 7.5
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2024/05/08/3",
            "https://access.redhat.com/errata/RHSA-2024:5291",
            "https://access.redhat.com/security/cve/CVE-2024-24788",
            "https://bugzilla.redhat.com/2279814",
            "https://bugzilla.redhat.com/2292668",
            "https://bugzilla.redhat.com/2292787",
            "https://errata.almalinux.org/8/ALSA-2024-5291.html",
            "https://github.com/golang/go/commit/93d8777d244962d1b706c0b695c8b72e9702577e (1.22)",
            "https://github.com/golang/go/issues/66754",
            "https://go-review.googlesource.com/c/go/+/578375",
            "https://go.dev/cl/578375",
            "https://go.dev/issue/66754",
            "https://groups.google.com/g/golang-announce/c/wkkO4P9stm0",
            "https://linux.oracle.com/cve/CVE-2024-24788.html",
            "https://linux.oracle.com/errata/ELSA-2024-5291.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-24788",
            "https://pkg.go.dev/vuln/GO-2024-2824",
            "https://security.netapp.com/advisory/ntap-20240605-0002/",
            "https://security.netapp.com/advisory/ntap-20240614-0001/",
            "https://ubuntu.com/security/notices/USN-6886-1",
            "https://www.cve.org/CVERecord?id=CVE-2024-24788"
          ],
          "PublishedDate": "2024-05-08T16:15:08.25Z",
          "LastModifiedDate": "2024-06-14T13:15:50.67Z"
        },
        {
          "VulnerabilityID": "CVE-2024-34156",
          "PkgName": "stdlib",
          "PkgIdentifier": {
            "PURL": "pkg:golang/stdlib@1.22.2",
            "UID": "2ac0ded2c472625e"
          },
          "InstalledVersion": "1.22.2",
          "FixedVersion": "1.22.7, 1.23.1",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:5ea2e59d5bc556b78ceb30c39b0b7be8e6a7c511150811cf7c445275c485c502",
            "DiffID": "sha256:53a2763a2f061ad8aa06c347fd3029b89e1b7d6b56be8d0df8e63fc8da00ef02"
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
          "VulnerabilityID": "CVE-2024-24789",
          "PkgName": "stdlib",
          "PkgIdentifier": {
            "PURL": "pkg:golang/stdlib@1.22.2",
            "UID": "2ac0ded2c472625e"
          },
          "InstalledVersion": "1.22.2",
          "FixedVersion": "1.21.11, 1.22.4",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:5ea2e59d5bc556b78ceb30c39b0b7be8e6a7c511150811cf7c445275c485c502",
            "DiffID": "sha256:53a2763a2f061ad8aa06c347fd3029b89e1b7d6b56be8d0df8e63fc8da00ef02"
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
            "PURL": "pkg:golang/stdlib@1.22.2",
            "UID": "2ac0ded2c472625e"
          },
          "InstalledVersion": "1.22.2",
          "FixedVersion": "1.21.12, 1.22.5",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:5ea2e59d5bc556b78ceb30c39b0b7be8e6a7c511150811cf7c445275c485c502",
            "DiffID": "sha256:53a2763a2f061ad8aa06c347fd3029b89e1b7d6b56be8d0df8e63fc8da00ef02"
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
            "PURL": "pkg:golang/stdlib@1.22.2",
            "UID": "2ac0ded2c472625e"
          },
          "InstalledVersion": "1.22.2",
          "FixedVersion": "1.22.7, 1.23.1",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:5ea2e59d5bc556b78ceb30c39b0b7be8e6a7c511150811cf7c445275c485c502",
            "DiffID": "sha256:53a2763a2f061ad8aa06c347fd3029b89e1b7d6b56be8d0df8e63fc8da00ef02"
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
            "PURL": "pkg:golang/stdlib@1.22.2",
            "UID": "2ac0ded2c472625e"
          },
          "InstalledVersion": "1.22.2",
          "FixedVersion": "1.22.7, 1.23.1",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:5ea2e59d5bc556b78ceb30c39b0b7be8e6a7c511150811cf7c445275c485c502",
            "DiffID": "sha256:53a2763a2f061ad8aa06c347fd3029b89e1b7d6b56be8d0df8e63fc8da00ef02"
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
      "Target": "usr/local/bin/loft",
      "Class": "lang-pkgs",
      "Type": "gobinary",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2024-41110",
          "PkgName": "github.com/docker/docker",
          "PkgIdentifier": {
            "PURL": "pkg:golang/github.com/docker/docker@v25.0.5%2Bincompatible",
            "UID": "49655eec6e3edc48"
          },
          "InstalledVersion": "v25.0.5+incompatible",
          "FixedVersion": "23.0.15, 26.1.5, 27.1.1, 25.0.6",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:5ea2e59d5bc556b78ceb30c39b0b7be8e6a7c511150811cf7c445275c485c502",
            "DiffID": "sha256:53a2763a2f061ad8aa06c347fd3029b89e1b7d6b56be8d0df8e63fc8da00ef02"
          },
          "SeveritySource": "ghsa",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-41110",
          "DataSource": {
            "ID": "ghsa",
            "Name": "GitHub Security Advisory Go",
            "URL": "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Ago"
          },
          "Title": "moby: Authz zero length regression",
          "Description": "Moby is an open-source project created by Docker for software containerization. A security vulnerability has been detected in certain versions of Docker Engine, which could allow an attacker to bypass authorization plugins (AuthZ) under specific circumstances. The base likelihood of this being exploited is low.\n\nUsing a specially-crafted API request, an Engine API client could make the daemon forward the request or response to an authorization plugin without the body. In certain circumstances, the authorization plugin may allow a request which it would have otherwise denied if the body had been forwarded to it.\n\nA security issue was discovered In 2018, where an attacker could bypass AuthZ plugins using a specially crafted API request. This could lead to unauthorized actions, including privilege escalation. Although this issue was fixed in Docker Engine v18.09.1 in January 2019, the fix was not carried forward to later major versions, resulting in a regression. Anyone who depends on authorization plugins that introspect the request and/or response body to make access control decisions is potentially impacted.\n\nDocker EE v19.03.x and all versions of Mirantis Container Runtime are not vulnerable.\n\ndocker-ce v27.1.1 containes patches to fix the vulnerability. Patches have also been merged into the master, 19.03, 20.0, 23.0, 24.0, 25.0, 26.0, and 26.1 release branches. If one is unable to upgrade immediately, avoid using AuthZ plugins and/or restrict access to the Docker API to trusted parties, following the principle of least privilege.",
          "Severity": "CRITICAL",
          "CweIDs": [
            "CWE-187",
            "CWE-444",
            "CWE-863"
          ],
          "VendorSeverity": {
            "amazon": 3,
            "azure": 4,
            "cbl-mariner": 4,
            "ghsa": 4,
            "redhat": 4
          },
          "CVSS": {
            "ghsa": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
              "V3Score": 10
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
              "V3Score": 9.9
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2024-41110",
            "https://github.com/moby/moby",
            "https://github.com/moby/moby/commit/411e817ddf710ff8e08fa193da80cb78af708191",
            "https://github.com/moby/moby/commit/42f40b1d6dd7562342f832b9cd2adf9e668eeb76",
            "https://github.com/moby/moby/commit/65cc597cea28cdc25bea3b8a86384b4251872919",
            "https://github.com/moby/moby/commit/852759a7df454cbf88db4e954c919becd48faa9b",
            "https://github.com/moby/moby/commit/a31260625655cff9ae226b51757915e275e304b0",
            "https://github.com/moby/moby/commit/a79fabbfe84117696a19671f4aa88b82d0f64fc1",
            "https://github.com/moby/moby/commit/ae160b4edddb72ef4bd71f66b975a1a1cc434f00",
            "https://github.com/moby/moby/commit/ae2b3666c517c96cbc2adf1af5591a6b00d4ec0f",
            "https://github.com/moby/moby/commit/cc13f952511154a2866bddbb7dddebfe9e83b801",
            "https://github.com/moby/moby/commit/fc274cd2ff4cf3b48c91697fb327dd1fb95588fb",
            "https://github.com/moby/moby/security/advisories/GHSA-v23v-6jw2-98fq",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-41110",
            "https://www.cve.org/CVERecord?id=CVE-2024-41110",
            "https://www.docker.com/blog/docker-security-advisory-docker-engine-authz-plugin"
          ],
          "PublishedDate": "2024-07-24T17:15:11.053Z",
          "LastModifiedDate": "2024-07-30T20:15:04.567Z"
        },
        {
          "VulnerabilityID": "CVE-2023-45288",
          "PkgName": "golang.org/x/net",
          "PkgIdentifier": {
            "PURL": "pkg:golang/golang.org/x/net@v0.21.0",
            "UID": "4ea251706b05d427"
          },
          "InstalledVersion": "v0.21.0",
          "FixedVersion": "0.23.0",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:5ea2e59d5bc556b78ceb30c39b0b7be8e6a7c511150811cf7c445275c485c502",
            "DiffID": "sha256:53a2763a2f061ad8aa06c347fd3029b89e1b7d6b56be8d0df8e63fc8da00ef02"
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
          "VulnerabilityID": "CVE-2024-24790",
          "PkgName": "stdlib",
          "PkgIdentifier": {
            "PURL": "pkg:golang/stdlib@1.22.2",
            "UID": "6ce2c331cca3b8d2"
          },
          "InstalledVersion": "1.22.2",
          "FixedVersion": "1.21.11, 1.22.4",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:5ea2e59d5bc556b78ceb30c39b0b7be8e6a7c511150811cf7c445275c485c502",
            "DiffID": "sha256:53a2763a2f061ad8aa06c347fd3029b89e1b7d6b56be8d0df8e63fc8da00ef02"
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
          "VulnerabilityID": "CVE-2024-24788",
          "PkgName": "stdlib",
          "PkgIdentifier": {
            "PURL": "pkg:golang/stdlib@1.22.2",
            "UID": "6ce2c331cca3b8d2"
          },
          "InstalledVersion": "1.22.2",
          "FixedVersion": "1.22.3",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:5ea2e59d5bc556b78ceb30c39b0b7be8e6a7c511150811cf7c445275c485c502",
            "DiffID": "sha256:53a2763a2f061ad8aa06c347fd3029b89e1b7d6b56be8d0df8e63fc8da00ef02"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-24788",
          "DataSource": {
            "ID": "govulndb",
            "Name": "The Go Vulnerability Database",
            "URL": "https://pkg.go.dev/vuln/"
          },
          "Title": "golang: net: malformed DNS message can cause infinite loop",
          "Description": "A malformed DNS message in response to a query can cause the Lookup functions to get stuck in an infinite loop.",
          "Severity": "HIGH",
          "VendorSeverity": {
            "alma": 2,
            "azure": 2,
            "cbl-mariner": 2,
            "oracle-oval": 2,
            "redhat": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 7.5
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2024/05/08/3",
            "https://access.redhat.com/errata/RHSA-2024:5291",
            "https://access.redhat.com/security/cve/CVE-2024-24788",
            "https://bugzilla.redhat.com/2279814",
            "https://bugzilla.redhat.com/2292668",
            "https://bugzilla.redhat.com/2292787",
            "https://errata.almalinux.org/8/ALSA-2024-5291.html",
            "https://github.com/golang/go/commit/93d8777d244962d1b706c0b695c8b72e9702577e (1.22)",
            "https://github.com/golang/go/issues/66754",
            "https://go-review.googlesource.com/c/go/+/578375",
            "https://go.dev/cl/578375",
            "https://go.dev/issue/66754",
            "https://groups.google.com/g/golang-announce/c/wkkO4P9stm0",
            "https://linux.oracle.com/cve/CVE-2024-24788.html",
            "https://linux.oracle.com/errata/ELSA-2024-5291.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-24788",
            "https://pkg.go.dev/vuln/GO-2024-2824",
            "https://security.netapp.com/advisory/ntap-20240605-0002/",
            "https://security.netapp.com/advisory/ntap-20240614-0001/",
            "https://ubuntu.com/security/notices/USN-6886-1",
            "https://www.cve.org/CVERecord?id=CVE-2024-24788"
          ],
          "PublishedDate": "2024-05-08T16:15:08.25Z",
          "LastModifiedDate": "2024-06-14T13:15:50.67Z"
        },
        {
          "VulnerabilityID": "CVE-2024-34156",
          "PkgName": "stdlib",
          "PkgIdentifier": {
            "PURL": "pkg:golang/stdlib@1.22.2",
            "UID": "6ce2c331cca3b8d2"
          },
          "InstalledVersion": "1.22.2",
          "FixedVersion": "1.22.7, 1.23.1",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:5ea2e59d5bc556b78ceb30c39b0b7be8e6a7c511150811cf7c445275c485c502",
            "DiffID": "sha256:53a2763a2f061ad8aa06c347fd3029b89e1b7d6b56be8d0df8e63fc8da00ef02"
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
          "VulnerabilityID": "CVE-2024-24789",
          "PkgName": "stdlib",
          "PkgIdentifier": {
            "PURL": "pkg:golang/stdlib@1.22.2",
            "UID": "6ce2c331cca3b8d2"
          },
          "InstalledVersion": "1.22.2",
          "FixedVersion": "1.21.11, 1.22.4",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:5ea2e59d5bc556b78ceb30c39b0b7be8e6a7c511150811cf7c445275c485c502",
            "DiffID": "sha256:53a2763a2f061ad8aa06c347fd3029b89e1b7d6b56be8d0df8e63fc8da00ef02"
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
            "PURL": "pkg:golang/stdlib@1.22.2",
            "UID": "6ce2c331cca3b8d2"
          },
          "InstalledVersion": "1.22.2",
          "FixedVersion": "1.21.12, 1.22.5",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:5ea2e59d5bc556b78ceb30c39b0b7be8e6a7c511150811cf7c445275c485c502",
            "DiffID": "sha256:53a2763a2f061ad8aa06c347fd3029b89e1b7d6b56be8d0df8e63fc8da00ef02"
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
            "PURL": "pkg:golang/stdlib@1.22.2",
            "UID": "6ce2c331cca3b8d2"
          },
          "InstalledVersion": "1.22.2",
          "FixedVersion": "1.22.7, 1.23.1",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:5ea2e59d5bc556b78ceb30c39b0b7be8e6a7c511150811cf7c445275c485c502",
            "DiffID": "sha256:53a2763a2f061ad8aa06c347fd3029b89e1b7d6b56be8d0df8e63fc8da00ef02"
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
            "PURL": "pkg:golang/stdlib@1.22.2",
            "UID": "6ce2c331cca3b8d2"
          },
          "InstalledVersion": "1.22.2",
          "FixedVersion": "1.22.7, 1.23.1",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:5ea2e59d5bc556b78ceb30c39b0b7be8e6a7c511150811cf7c445275c485c502",
            "DiffID": "sha256:53a2763a2f061ad8aa06c347fd3029b89e1b7d6b56be8d0df8e63fc8da00ef02"
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
