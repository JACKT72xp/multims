2024-09-15T11:52:43+02:00	INFO	[vuln] Vulnerability scanning is enabled
2024-09-15T11:52:43+02:00	INFO	[secret] Secret scanning is enabled
2024-09-15T11:52:43+02:00	INFO	[secret] If your scanning is slow, please try '--scanners vuln' to disable secret scanning
2024-09-15T11:52:43+02:00	INFO	[secret] Please see also https://aquasecurity.github.io/trivy/v0.55/docs/scanner/secret#recommendation for faster secret detection
2024-09-15T11:52:43+02:00	INFO	Detected OS	family="debian" version="10.13"
2024-09-15T11:52:43+02:00	INFO	[debian] Detecting vulnerabilities...	os_version="10" pkg_num=93
2024-09-15T11:52:43+02:00	INFO	Number of language-specific files	num=1
2024-09-15T11:52:43+02:00	INFO	[python-pkg] Detecting vulnerabilities...
2024-09-15T11:52:43+02:00	WARN	Using severities from other vendors for some vulnerabilities. Read https://aquasecurity.github.io/trivy/v0.55/docs/scanner/vulnerability#severity-selection for details.
2024-09-15T11:52:43+02:00	WARN	This OS version is no longer supported by the distribution	family="debian" version="10.13"
2024-09-15T11:52:43+02:00	WARN	The vulnerability detection may be insufficient because security updates are not provided
{
  "SchemaVersion": 2,
  "CreatedAt": "2024-09-15T11:52:43.335029+02:00",
  "ArtifactName": "621849652964.dkr.ecr.us-east-1.amazonaws.com/ms-0021-bifrost_auth:dev36",
  "ArtifactType": "container_image",
  "Metadata": {
    "OS": {
      "Family": "debian",
      "Name": "10.13",
      "EOSL": true
    },
    "ImageID": "sha256:f5dd0dca75f73d7c67a01a69171627015439a1ade10f202028f07540d43bc63a",
    "DiffIDs": [
      "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9",
      "sha256:ae2d55769c5efcb6230d27c88eef033128fa1d238bdafe50812402f471152bb7",
      "sha256:3054512b6f71055cacea93ed12462e1ddc7f54988d9c7b51d10a5144d99ff501",
      "sha256:997b8e79e84fa9e7b9785408364770acca5261ff5cf450e3628b305e27a51a7e",
      "sha256:e6c5004ee77f450910ca26a9ef2e476ce766b3e4c83d034edfc28ff3736297a1",
      "sha256:8acd8cb60d6b8a58ac03389fa23612f455c46508e9d592a98b270632d04680e8",
      "sha256:e2aaa4e4c568333a05f3226adb7ac0b3ab7b9aff564f035776955d2541b350e0",
      "sha256:581dc61be3f191c3f6d38ab7dc849818f4628cd351389bde1ef6283ea8303f32",
      "sha256:b9417271bdacb17935d774c807076f33b0de23f5311a76a1561903124e424eb0",
      "sha256:ec2e06a3423bd608da6821e3f495f5a3194b1d398b80483f74ae8ae97d71a5f6"
    ],
    "RepoTags": [
      "621849652964.dkr.ecr.us-east-1.amazonaws.com/ms-0021-bifrost_auth:dev36"
    ],
    "RepoDigests": [
      "621849652964.dkr.ecr.us-east-1.amazonaws.com/ms-0021-bifrost_auth@sha256:f5dd0dca75f73d7c67a01a69171627015439a1ade10f202028f07540d43bc63a"
    ],
    "ImageConfig": {
      "architecture": "amd64",
      "created": "2024-09-14T16:32:42.139683838Z",
      "docker_version": "26.1.1",
      "history": [
        {
          "created": "2023-06-12T23:21:32Z",
          "created_by": "/bin/sh -c #(nop) ADD file:2818e508d01da2188fb234b38fb19aa1ea9eeeae92d361ecdf49318d949f51a9 in / "
        },
        {
          "created": "2023-06-12T23:21:32Z",
          "created_by": "/bin/sh -c #(nop)  CMD [\"bash\"]",
          "empty_layer": true
        },
        {
          "created": "2023-06-06T15:50:21Z",
          "created_by": "ENV PATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
          "comment": "buildkit.dockerfile.v0",
          "empty_layer": true
        },
        {
          "created": "2023-06-06T15:50:21Z",
          "created_by": "ENV LANG=C.UTF-8",
          "comment": "buildkit.dockerfile.v0",
          "empty_layer": true
        },
        {
          "created": "2023-06-06T15:50:21Z",
          "created_by": "RUN /bin/sh -c set -eux; \tapt-get update; \tapt-get install -y --no-install-recommends \t\tca-certificates \t\tnetbase \t\ttzdata \t; \trm -rf /var/lib/apt/lists/* # buildkit",
          "comment": "buildkit.dockerfile.v0"
        },
        {
          "created": "2023-06-06T15:50:21Z",
          "created_by": "ENV GPG_KEY=E3FF2839C048B25C084DEBE9B26995E310250568",
          "comment": "buildkit.dockerfile.v0",
          "empty_layer": true
        },
        {
          "created": "2023-06-06T15:50:21Z",
          "created_by": "ENV PYTHON_VERSION=3.8.17",
          "comment": "buildkit.dockerfile.v0",
          "empty_layer": true
        },
        {
          "created": "2023-06-06T15:50:21Z",
          "created_by": "RUN /bin/sh -c set -eux; \t\tsavedAptMark=\"$(apt-mark showmanual)\"; \tapt-get update; \tapt-get install -y --no-install-recommends \t\tdpkg-dev \t\tgcc \t\tgnupg \t\tlibbluetooth-dev \t\tlibbz2-dev \t\tlibc6-dev \t\tlibdb-dev \t\tlibexpat1-dev \t\tlibffi-dev \t\tlibgdbm-dev \t\tliblzma-dev \t\tlibncursesw5-dev \t\tlibreadline-dev \t\tlibsqlite3-dev \t\tlibssl-dev \t\tmake \t\ttk-dev \t\tuuid-dev \t\twget \t\txz-utils \t\tzlib1g-dev \t; \t\twget -O python.tar.xz \"https://www.python.org/ftp/python/${PYTHON_VERSION%%[a-z]*}/Python-$PYTHON_VERSION.tar.xz\"; \twget -O python.tar.xz.asc \"https://www.python.org/ftp/python/${PYTHON_VERSION%%[a-z]*}/Python-$PYTHON_VERSION.tar.xz.asc\"; \tGNUPGHOME=\"$(mktemp -d)\"; export GNUPGHOME; \tgpg --batch --keyserver hkps://keys.openpgp.org --recv-keys \"$GPG_KEY\"; \tgpg --batch --verify python.tar.xz.asc python.tar.xz; \tgpgconf --kill all; \trm -rf \"$GNUPGHOME\" python.tar.xz.asc; \tmkdir -p /usr/src/python; \ttar --extract --directory /usr/src/python --strip-components=1 --file python.tar.xz; \trm python.tar.xz; \t\tcd /usr/src/python; \tgnuArch=\"$(dpkg-architecture --query DEB_BUILD_GNU_TYPE)\"; \t./configure \t\t--build=\"$gnuArch\" \t\t--enable-loadable-sqlite-extensions \t\t--enable-optimizations \t\t--enable-option-checking=fatal \t\t--enable-shared \t\t--with-system-expat \t\t--without-ensurepip \t; \tnproc=\"$(nproc)\"; \tEXTRA_CFLAGS=\"$(dpkg-buildflags --get CFLAGS)\"; \tLDFLAGS=\"$(dpkg-buildflags --get LDFLAGS)\"; \tLDFLAGS=\"${LDFLAGS:--Wl},--strip-all\"; \tmake -j \"$nproc\" \t\t\"EXTRA_CFLAGS=${EXTRA_CFLAGS:-}\" \t\t\"LDFLAGS=${LDFLAGS:-}\" \t\t\"PROFILE_TASK=${PROFILE_TASK:-}\" \t; \trm python; \tmake -j \"$nproc\" \t\t\"EXTRA_CFLAGS=${EXTRA_CFLAGS:-}\" \t\t\"LDFLAGS=${LDFLAGS:--Wl},-rpath='\\$\\$ORIGIN/../lib'\" \t\t\"PROFILE_TASK=${PROFILE_TASK:-}\" \t\tpython \t; \tmake install; \t\tcd /; \trm -rf /usr/src/python; \t\tfind /usr/local -depth \t\t\\( \t\t\t\\( -type d -a \\( -name test -o -name tests -o -name idle_test \\) \\) \t\t\t-o \\( -type f -a \\( -name '*.pyc' -o -name '*.pyo' -o -name 'libpython*.a' \\) \\) \t\t\t-o \\( -type f -a -name 'wininst-*.exe' \\) \t\t\\) -exec rm -rf '{}' + \t; \t\tldconfig; \t\tapt-mark auto '.*' \u003e /dev/null; \tapt-mark manual $savedAptMark; \tfind /usr/local -type f -executable -not \\( -name '*tkinter*' \\) -exec ldd '{}' ';' \t\t| awk '/=\u003e/ { print $(NF-1) }' \t\t| sort -u \t\t| xargs -r dpkg-query --search \t\t| cut -d: -f1 \t\t| sort -u \t\t| xargs -r apt-mark manual \t; \tapt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false; \trm -rf /var/lib/apt/lists/*; \t\tpython3 --version # buildkit",
          "comment": "buildkit.dockerfile.v0"
        },
        {
          "created": "2023-06-06T15:50:21Z",
          "created_by": "RUN /bin/sh -c set -eux; \tfor src in idle3 pydoc3 python3 python3-config; do \t\tdst=\"$(echo \"$src\" | tr -d 3)\"; \t\t[ -s \"/usr/local/bin/$src\" ]; \t\t[ ! -e \"/usr/local/bin/$dst\" ]; \t\tln -svT \"$src\" \"/usr/local/bin/$dst\"; \tdone # buildkit",
          "comment": "buildkit.dockerfile.v0"
        },
        {
          "created": "2023-06-06T15:50:21Z",
          "created_by": "ENV PYTHON_PIP_VERSION=23.0.1",
          "comment": "buildkit.dockerfile.v0",
          "empty_layer": true
        },
        {
          "created": "2023-06-06T15:50:21Z",
          "created_by": "ENV PYTHON_SETUPTOOLS_VERSION=57.5.0",
          "comment": "buildkit.dockerfile.v0",
          "empty_layer": true
        },
        {
          "created": "2023-06-06T15:50:21Z",
          "created_by": "ENV PYTHON_GET_PIP_URL=https://github.com/pypa/get-pip/raw/0d8570dc44796f4369b652222cf176b3db6ac70e/public/get-pip.py",
          "comment": "buildkit.dockerfile.v0",
          "empty_layer": true
        },
        {
          "created": "2023-06-06T15:50:21Z",
          "created_by": "ENV PYTHON_GET_PIP_SHA256=96461deced5c2a487ddc65207ec5a9cffeca0d34e7af7ea1afc470ff0d746207",
          "comment": "buildkit.dockerfile.v0",
          "empty_layer": true
        },
        {
          "created": "2023-06-06T15:50:21Z",
          "created_by": "RUN /bin/sh -c set -eux; \t\tsavedAptMark=\"$(apt-mark showmanual)\"; \tapt-get update; \tapt-get install -y --no-install-recommends wget; \t\twget -O get-pip.py \"$PYTHON_GET_PIP_URL\"; \techo \"$PYTHON_GET_PIP_SHA256 *get-pip.py\" | sha256sum -c -; \t\tapt-mark auto '.*' \u003e /dev/null; \t[ -z \"$savedAptMark\" ] || apt-mark manual $savedAptMark \u003e /dev/null; \tapt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false; \trm -rf /var/lib/apt/lists/*; \t\texport PYTHONDONTWRITEBYTECODE=1; \t\tpython get-pip.py \t\t--disable-pip-version-check \t\t--no-cache-dir \t\t--no-compile \t\t\"pip==$PYTHON_PIP_VERSION\" \t\t\"setuptools==$PYTHON_SETUPTOOLS_VERSION\" \t; \trm -f get-pip.py; \t\tpip --version # buildkit",
          "comment": "buildkit.dockerfile.v0"
        },
        {
          "created": "2023-06-06T15:50:21Z",
          "created_by": "CMD [\"python3\"]",
          "comment": "buildkit.dockerfile.v0",
          "empty_layer": true
        },
        {
          "created": "2024-09-14T16:32:29Z",
          "created_by": "WORKDIR /app",
          "comment": "buildkit.dockerfile.v0"
        },
        {
          "created": "2024-09-14T16:32:29Z",
          "created_by": "COPY requirements.txt . # buildkit",
          "comment": "buildkit.dockerfile.v0"
        },
        {
          "created": "2024-09-14T16:32:41Z",
          "created_by": "RUN /bin/sh -c pip install -r requirements.txt # buildkit",
          "comment": "buildkit.dockerfile.v0"
        },
        {
          "created": "2024-09-14T16:32:42Z",
          "created_by": "COPY . . # buildkit",
          "comment": "buildkit.dockerfile.v0"
        },
        {
          "created": "2024-09-14T16:32:42Z",
          "created_by": "COPY .env.development .env # buildkit",
          "comment": "buildkit.dockerfile.v0"
        },
        {
          "created": "2024-09-14T16:32:42Z",
          "created_by": "EXPOSE map[8080/tcp:{}]",
          "comment": "buildkit.dockerfile.v0",
          "empty_layer": true
        },
        {
          "created": "2024-09-14T16:32:42Z",
          "created_by": "CMD [\"gunicorn\" \"-w\" \"4\" \"-b\" \"0.0.0.0:8080\" \"app:app\"]",
          "comment": "buildkit.dockerfile.v0",
          "empty_layer": true
        }
      ],
      "os": "linux",
      "rootfs": {
        "type": "layers",
        "diff_ids": [
          "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9",
          "sha256:ae2d55769c5efcb6230d27c88eef033128fa1d238bdafe50812402f471152bb7",
          "sha256:3054512b6f71055cacea93ed12462e1ddc7f54988d9c7b51d10a5144d99ff501",
          "sha256:997b8e79e84fa9e7b9785408364770acca5261ff5cf450e3628b305e27a51a7e",
          "sha256:e6c5004ee77f450910ca26a9ef2e476ce766b3e4c83d034edfc28ff3736297a1",
          "sha256:8acd8cb60d6b8a58ac03389fa23612f455c46508e9d592a98b270632d04680e8",
          "sha256:e2aaa4e4c568333a05f3226adb7ac0b3ab7b9aff564f035776955d2541b350e0",
          "sha256:581dc61be3f191c3f6d38ab7dc849818f4628cd351389bde1ef6283ea8303f32",
          "sha256:b9417271bdacb17935d774c807076f33b0de23f5311a76a1561903124e424eb0",
          "sha256:ec2e06a3423bd608da6821e3f495f5a3194b1d398b80483f74ae8ae97d71a5f6"
        ]
      },
      "config": {
        "Cmd": [
          "gunicorn",
          "-w",
          "4",
          "-b",
          "0.0.0.0:8080",
          "app:app"
        ],
        "Env": [
          "PATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
          "LANG=C.UTF-8",
          "GPG_KEY=E3FF2839C048B25C084DEBE9B26995E310250568",
          "PYTHON_VERSION=3.8.17",
          "PYTHON_PIP_VERSION=23.0.1",
          "PYTHON_SETUPTOOLS_VERSION=57.5.0",
          "PYTHON_GET_PIP_URL=https://github.com/pypa/get-pip/raw/0d8570dc44796f4369b652222cf176b3db6ac70e/public/get-pip.py",
          "PYTHON_GET_PIP_SHA256=96461deced5c2a487ddc65207ec5a9cffeca0d34e7af7ea1afc470ff0d746207"
        ],
        "WorkingDir": "/app",
        "ArgsEscaped": true
      }
    }
  },
  "Results": [
    {
      "Target": "621849652964.dkr.ecr.us-east-1.amazonaws.com/ms-0021-bifrost_auth:dev36 (debian 10.13)",
      "Class": "os-pkgs",
      "Type": "debian",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2011-3374",
          "PkgID": "apt@1.8.2.3",
          "PkgName": "apt",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/apt@1.8.2.3?arch=amd64\u0026distro=debian-10.13",
            "UID": "d087f1e560e9e598"
          },
          "InstalledVersion": "1.8.2.3",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2011-3374",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "It was found that apt-key in apt, all versions, do not correctly valid ...",
          "Description": "It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyring, leading to a potential man-in-the-middle attack.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-347"
          ],
          "VendorSeverity": {
            "debian": 1,
            "nvd": 1
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:M/Au:N/C:N/I:P/A:N",
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
              "V2Score": 4.3,
              "V3Score": 3.7
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/cve-2011-3374",
            "https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=642480",
            "https://people.canonical.com/~ubuntu-security/cve/2011/CVE-2011-3374.html",
            "https://seclists.org/fulldisclosure/2011/Sep/221",
            "https://security-tracker.debian.org/tracker/CVE-2011-3374",
            "https://snyk.io/vuln/SNYK-LINUX-APT-116518",
            "https://ubuntu.com/security/CVE-2011-3374"
          ],
          "PublishedDate": "2019-11-26T00:15:11.03Z",
          "LastModifiedDate": "2021-02-09T16:08:18.683Z"
        },
        {
          "VulnerabilityID": "CVE-2019-18276",
          "PkgID": "bash@5.0-4",
          "PkgName": "bash",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/bash@5.0-4?arch=amd64\u0026distro=debian-10.13",
            "UID": "10473d559babd9cb"
          },
          "InstalledVersion": "5.0-4",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2019-18276",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "bash: when effective UID is not equal to its real UID the saved UID is not dropped",
          "Description": "An issue was discovered in disable_priv_mode in shell.c in GNU Bash through 5.0 patch 11. By default, if Bash is run with its effective UID not equal to its real UID, it will drop privileges by setting its effective UID to its real UID. However, it does so incorrectly. On Linux and other systems that support \"saved UID\" functionality, the saved UID is not dropped. An attacker with command execution in the shell can use \"enable -f\" for runtime loading of a new builtin, which can be a shared object that calls setuid() and therefore regains privileges. However, binaries running with an effective UID of 0 are unaffected.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-273"
          ],
          "VendorSeverity": {
            "cbl-mariner": 3,
            "debian": 1,
            "nvd": 3,
            "oracle-oval": 1,
            "photon": 3,
            "redhat": 1,
            "ubuntu": 1
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:L/AC:L/Au:N/C:C/I:C/A:C",
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
              "V2Score": 7.2,
              "V3Score": 7.8
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
              "V3Score": 7.8
            }
          },
          "References": [
            "http://packetstormsecurity.com/files/155498/Bash-5.0-Patch-11-Privilege-Escalation.html",
            "https://access.redhat.com/security/cve/CVE-2019-18276",
            "https://github.com/bminor/bash/commit/951bdaad7a18cc0dc1036bba86b18b90874d39ff",
            "https://linux.oracle.com/cve/CVE-2019-18276.html",
            "https://linux.oracle.com/errata/ELSA-2021-1679.html",
            "https://lists.apache.org/thread.html/rf9fa47ab66495c78bb4120b0754dd9531ca2ff0430f6685ac9b07772%40%3Cdev.mina.apache.org%3E",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-18276",
            "https://security.gentoo.org/glsa/202105-34",
            "https://security.netapp.com/advisory/ntap-20200430-0003/",
            "https://ubuntu.com/security/notices/USN-5380-1",
            "https://www.cve.org/CVERecord?id=CVE-2019-18276",
            "https://www.oracle.com/security-alerts/cpuapr2022.html",
            "https://www.youtube.com/watch?v=-wGtxJ8opa8"
          ],
          "PublishedDate": "2019-11-28T01:15:10.603Z",
          "LastModifiedDate": "2023-11-07T03:06:25.3Z"
        },
        {
          "VulnerabilityID": "TEMP-0841856-B18BAF",
          "PkgID": "bash@5.0-4",
          "PkgName": "bash",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/bash@5.0-4?arch=amd64\u0026distro=debian-10.13",
            "UID": "10473d559babd9cb"
          },
          "InstalledVersion": "5.0-4",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://security-tracker.debian.org/tracker/TEMP-0841856-B18BAF",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "[Privilege escalation possible to other user than root]",
          "Severity": "LOW",
          "VendorSeverity": {
            "debian": 1
          }
        },
        {
          "VulnerabilityID": "CVE-2024-28085",
          "VendorIDs": [
            "DLA-3782-1"
          ],
          "PkgID": "bsdutils@1:2.33.1-0.1",
          "PkgName": "bsdutils",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/bsdutils@2.33.1-0.1?arch=amd64\u0026distro=debian-10.13\u0026epoch=1",
            "UID": "af9a94224e8ff53c"
          },
          "InstalledVersion": "1:2.33.1-0.1",
          "FixedVersion": "2.33.1-0.1+deb10u1",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-28085",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "util-linux: CVE-2024-28085: wall: escape sequence injection",
          "Description": "wall in util-linux through 2.40, often installed with setgid tty permissions, allows escape sequences to be sent to other users' terminals through argv. (Specifically, escape sequences received from stdin are blocked, but escape sequences received from argv are not blocked.) There may be plausible scenarios where this leads to account takeover.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-150"
          ],
          "VendorSeverity": {
            "cbl-mariner": 4,
            "photon": 3,
            "redhat": 3,
            "ubuntu": 2
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N",
              "V3Score": 8.4
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2024/03/27/5",
            "http://www.openwall.com/lists/oss-security/2024/03/27/6",
            "http://www.openwall.com/lists/oss-security/2024/03/27/7",
            "http://www.openwall.com/lists/oss-security/2024/03/27/8",
            "http://www.openwall.com/lists/oss-security/2024/03/27/9",
            "http://www.openwall.com/lists/oss-security/2024/03/28/1",
            "http://www.openwall.com/lists/oss-security/2024/03/28/2",
            "http://www.openwall.com/lists/oss-security/2024/03/28/3",
            "https://access.redhat.com/security/cve/CVE-2024-28085",
            "https://github.com/skyler-ferrante/CVE-2024-28085",
            "https://github.com/util-linux/util-linux/security/advisories/GHSA-xv2h-c6ww-mrjq",
            "https://lists.debian.org/debian-lts-announce/2024/04/msg00005.html",
            "https://mirrors.edge.kernel.org/pub/linux/utils/util-linux/",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-28085",
            "https://people.rit.edu/sjf5462/6831711781/wall_2_27_2024.txt",
            "https://security.netapp.com/advisory/ntap-20240531-0003/",
            "https://ubuntu.com/security/notices/USN-6719-1",
            "https://ubuntu.com/security/notices/USN-6719-2",
            "https://www.cve.org/CVERecord?id=CVE-2024-28085",
            "https://www.openwall.com/lists/oss-security/2024/03/27/5"
          ],
          "PublishedDate": "2024-03-27T19:15:48.367Z",
          "LastModifiedDate": "2024-08-26T21:35:09.31Z"
        },
        {
          "VulnerabilityID": "CVE-2021-37600",
          "VendorIDs": [
            "DLA-3782-1"
          ],
          "PkgID": "bsdutils@1:2.33.1-0.1",
          "PkgName": "bsdutils",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/bsdutils@2.33.1-0.1?arch=amd64\u0026distro=debian-10.13\u0026epoch=1",
            "UID": "af9a94224e8ff53c"
          },
          "InstalledVersion": "1:2.33.1-0.1",
          "FixedVersion": "2.33.1-0.1+deb10u1",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2021-37600",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "util-linux: integer overflow can lead to buffer overflow in get_sem_elements() in sys-utils/ipcutils.c",
          "Description": "An integer overflow in util-linux through 2.37.1 can potentially cause a buffer overflow if an attacker were able to use system resources in a way that leads to a large number in the /proc/sysvipc/sem file. NOTE: this is unexploitable in GNU C Library environments, and possibly in all realistic environments.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-190"
          ],
          "VendorSeverity": {
            "amazon": 1,
            "cbl-mariner": 2,
            "nvd": 2,
            "photon": 2,
            "redhat": 1,
            "ubuntu": 1
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:L/AC:H/Au:N/C:N/I:N/A:P",
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
              "V2Score": 1.2,
              "V3Score": 5.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:H",
              "V3Score": 4.7
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2021-37600",
            "https://github.com/karelzak/util-linux/commit/1c9143d0c1f979c3daf10e1c37b5b1e916c22a1c",
            "https://github.com/karelzak/util-linux/issues/1395",
            "https://lists.debian.org/debian-lts-announce/2024/04/msg00005.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-37600",
            "https://security.gentoo.org/glsa/202401-08",
            "https://security.netapp.com/advisory/ntap-20210902-0002/",
            "https://www.cve.org/CVERecord?id=CVE-2021-37600"
          ],
          "PublishedDate": "2021-07-30T14:15:18.737Z",
          "LastModifiedDate": "2024-08-04T02:15:24.44Z"
        },
        {
          "VulnerabilityID": "CVE-2022-0563",
          "PkgID": "bsdutils@1:2.33.1-0.1",
          "PkgName": "bsdutils",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/bsdutils@2.33.1-0.1?arch=amd64\u0026distro=debian-10.13\u0026epoch=1",
            "UID": "af9a94224e8ff53c"
          },
          "InstalledVersion": "1:2.33.1-0.1",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2022-0563",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "util-linux: partial disclosure of arbitrary files in chfn and chsh when compiled with libreadline",
          "Description": "A flaw was found in the util-linux chfn and chsh utilities when compiled with Readline support. The Readline library uses an \"INPUTRC\" environment variable to get a path to the library config file. When the library cannot parse the specified file, it prints an error message containing data from the file. This flaw allows an unprivileged user to read root-owned files, potentially leading to privilege escalation. This flaw affects util-linux versions prior to 2.37.4.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-209"
          ],
          "VendorSeverity": {
            "amazon": 2,
            "cbl-mariner": 2,
            "debian": 1,
            "nvd": 2,
            "photon": 2,
            "redhat": 2
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:L/AC:M/Au:N/C:P/I:N/A:N",
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
              "V2Score": 1.9,
              "V3Score": 5.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
              "V3Score": 5.5
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2022-0563",
            "https://blog.trailofbits.com/2023/02/16/suid-logic-bug-linux-readline/",
            "https://lore.kernel.org/util-linux/20220214110609.msiwlm457ngoic6w%40ws.net.home/T/#u",
            "https://lore.kernel.org/util-linux/20220214110609.msiwlm457ngoic6w@ws.net.home/T/#u",
            "https://nvd.nist.gov/vuln/detail/CVE-2022-0563",
            "https://security.gentoo.org/glsa/202401-08",
            "https://security.netapp.com/advisory/ntap-20220331-0002/",
            "https://www.cve.org/CVERecord?id=CVE-2022-0563"
          ],
          "PublishedDate": "2022-02-21T19:15:08.393Z",
          "LastModifiedDate": "2024-01-07T09:15:08.713Z"
        },
        {
          "VulnerabilityID": "CVE-2016-2781",
          "PkgID": "coreutils@8.30-3",
          "PkgName": "coreutils",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/coreutils@8.30-3?arch=amd64\u0026distro=debian-10.13",
            "UID": "cb368d56bc45b06b"
          },
          "InstalledVersion": "8.30-3",
          "Status": "will_not_fix",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2016-2781",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "coreutils: Non-privileged session can escape to the parent session in chroot",
          "Description": "chroot in GNU coreutils, when used with --userspec, allows local users to escape to the parent session via a crafted TIOCSTI ioctl call, which pushes characters to the terminal's input buffer.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-20"
          ],
          "VendorSeverity": {
            "azure": 2,
            "cbl-mariner": 2,
            "debian": 1,
            "nvd": 2,
            "redhat": 2,
            "ubuntu": 1
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:L/AC:L/Au:N/C:N/I:P/A:N",
              "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:N",
              "V2Score": 2.1,
              "V3Score": 6.5
            },
            "redhat": {
              "V2Vector": "AV:L/AC:H/Au:N/C:C/I:C/A:C",
              "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H",
              "V2Score": 6.2,
              "V3Score": 8.6
            }
          },
          "References": [
            "http://seclists.org/oss-sec/2016/q1/452",
            "http://www.openwall.com/lists/oss-security/2016/02/28/2",
            "http://www.openwall.com/lists/oss-security/2016/02/28/3",
            "https://access.redhat.com/security/cve/CVE-2016-2781",
            "https://lists.apache.org/thread.html/rf9fa47ab66495c78bb4120b0754dd9531ca2ff0430f6685ac9b07772%40%3Cdev.mina.apache.org%3E",
            "https://lore.kernel.org/patchwork/patch/793178/",
            "https://nvd.nist.gov/vuln/detail/CVE-2016-2781",
            "https://www.cve.org/CVERecord?id=CVE-2016-2781"
          ],
          "PublishedDate": "2017-02-07T15:59:00.333Z",
          "LastModifiedDate": "2023-11-07T02:32:03.347Z"
        },
        {
          "VulnerabilityID": "CVE-2017-18018",
          "PkgID": "coreutils@8.30-3",
          "PkgName": "coreutils",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/coreutils@8.30-3?arch=amd64\u0026distro=debian-10.13",
            "UID": "cb368d56bc45b06b"
          },
          "InstalledVersion": "8.30-3",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2017-18018",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "coreutils: race condition vulnerability in chown and chgrp",
          "Description": "In GNU Coreutils through 8.29, chown-core.c in chown and chgrp does not prevent replacement of a plain file with a symlink during use of the POSIX \"-R -L\" options, which allows local users to modify the ownership of arbitrary files by leveraging a race condition.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-362"
          ],
          "VendorSeverity": {
            "debian": 1,
            "nvd": 2,
            "redhat": 2
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:L/AC:M/Au:N/C:N/I:P/A:N",
              "V3Vector": "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N",
              "V2Score": 1.9,
              "V3Score": 4.7
            },
            "redhat": {
              "V3Vector": "CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:L",
              "V3Score": 4.2
            }
          },
          "References": [
            "http://lists.gnu.org/archive/html/coreutils/2017-12/msg00045.html",
            "https://access.redhat.com/security/cve/CVE-2017-18018",
            "https://nvd.nist.gov/vuln/detail/CVE-2017-18018",
            "https://www.cve.org/CVERecord?id=CVE-2017-18018"
          ],
          "PublishedDate": "2018-01-04T04:29:00.19Z",
          "LastModifiedDate": "2018-01-19T15:46:46.05Z"
        },
        {
          "VulnerabilityID": "DLA-3482-1",
          "VendorIDs": [
            "DLA-3482-1"
          ],
          "PkgID": "debian-archive-keyring@2019.1+deb10u1",
          "PkgName": "debian-archive-keyring",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/debian-archive-keyring@2019.1%2Bdeb10u1?arch=all\u0026distro=debian-10.13",
            "UID": "6e0d032a9bac0431"
          },
          "InstalledVersion": "2019.1+deb10u1",
          "FixedVersion": "2019.1+deb10u2",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "debian-archive-keyring - security update",
          "Severity": "UNKNOWN"
        },
        {
          "VulnerabilityID": "CVE-2022-1304",
          "PkgID": "e2fsprogs@1.44.5-1+deb10u3",
          "PkgName": "e2fsprogs",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/e2fsprogs@1.44.5-1%2Bdeb10u3?arch=amd64\u0026distro=debian-10.13",
            "UID": "d5a8f485188eb07c"
          },
          "InstalledVersion": "1.44.5-1+deb10u3",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2022-1304",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "e2fsprogs: out-of-bounds read/write via crafted filesystem",
          "Description": "An out-of-bounds read/write vulnerability was found in e2fsprogs 1.46.5. This issue leads to a segmentation fault and possibly arbitrary code execution via a specially crafted filesystem.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-125",
            "CWE-787"
          ],
          "VendorSeverity": {
            "alma": 2,
            "amazon": 2,
            "cbl-mariner": 3,
            "nvd": 3,
            "oracle-oval": 2,
            "photon": 3,
            "redhat": 2,
            "rocky": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
              "V2Score": 6.8,
              "V3Score": 7.8
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:H",
              "V3Score": 5.8
            }
          },
          "References": [
            "https://access.redhat.com/errata/RHSA-2022:8361",
            "https://access.redhat.com/security/cve/CVE-2022-1304",
            "https://bugzilla.redhat.com/2069726",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2069726",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-1304",
            "https://errata.almalinux.org/9/ALSA-2022-8361.html",
            "https://errata.rockylinux.org/RLSA-2022:8361",
            "https://linux.oracle.com/cve/CVE-2022-1304.html",
            "https://linux.oracle.com/errata/ELSA-2022-8361.html",
            "https://marc.info/?l=linux-ext4\u0026m=165056234501732\u0026w=2",
            "https://nvd.nist.gov/vuln/detail/CVE-2022-1304",
            "https://ubuntu.com/security/notices/USN-5464-1",
            "https://www.cve.org/CVERecord?id=CVE-2022-1304"
          ],
          "PublishedDate": "2022-04-14T21:15:08.49Z",
          "LastModifiedDate": "2023-11-07T03:41:53.02Z"
        },
        {
          "VulnerabilityID": "CVE-2024-28085",
          "VendorIDs": [
            "DLA-3782-1"
          ],
          "PkgID": "fdisk@2.33.1-0.1",
          "PkgName": "fdisk",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/fdisk@2.33.1-0.1?arch=amd64\u0026distro=debian-10.13",
            "UID": "5144f8b86e2b5045"
          },
          "InstalledVersion": "2.33.1-0.1",
          "FixedVersion": "2.33.1-0.1+deb10u1",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-28085",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "util-linux: CVE-2024-28085: wall: escape sequence injection",
          "Description": "wall in util-linux through 2.40, often installed with setgid tty permissions, allows escape sequences to be sent to other users' terminals through argv. (Specifically, escape sequences received from stdin are blocked, but escape sequences received from argv are not blocked.) There may be plausible scenarios where this leads to account takeover.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-150"
          ],
          "VendorSeverity": {
            "cbl-mariner": 4,
            "photon": 3,
            "redhat": 3,
            "ubuntu": 2
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N",
              "V3Score": 8.4
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2024/03/27/5",
            "http://www.openwall.com/lists/oss-security/2024/03/27/6",
            "http://www.openwall.com/lists/oss-security/2024/03/27/7",
            "http://www.openwall.com/lists/oss-security/2024/03/27/8",
            "http://www.openwall.com/lists/oss-security/2024/03/27/9",
            "http://www.openwall.com/lists/oss-security/2024/03/28/1",
            "http://www.openwall.com/lists/oss-security/2024/03/28/2",
            "http://www.openwall.com/lists/oss-security/2024/03/28/3",
            "https://access.redhat.com/security/cve/CVE-2024-28085",
            "https://github.com/skyler-ferrante/CVE-2024-28085",
            "https://github.com/util-linux/util-linux/security/advisories/GHSA-xv2h-c6ww-mrjq",
            "https://lists.debian.org/debian-lts-announce/2024/04/msg00005.html",
            "https://mirrors.edge.kernel.org/pub/linux/utils/util-linux/",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-28085",
            "https://people.rit.edu/sjf5462/6831711781/wall_2_27_2024.txt",
            "https://security.netapp.com/advisory/ntap-20240531-0003/",
            "https://ubuntu.com/security/notices/USN-6719-1",
            "https://ubuntu.com/security/notices/USN-6719-2",
            "https://www.cve.org/CVERecord?id=CVE-2024-28085",
            "https://www.openwall.com/lists/oss-security/2024/03/27/5"
          ],
          "PublishedDate": "2024-03-27T19:15:48.367Z",
          "LastModifiedDate": "2024-08-26T21:35:09.31Z"
        },
        {
          "VulnerabilityID": "CVE-2021-37600",
          "VendorIDs": [
            "DLA-3782-1"
          ],
          "PkgID": "fdisk@2.33.1-0.1",
          "PkgName": "fdisk",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/fdisk@2.33.1-0.1?arch=amd64\u0026distro=debian-10.13",
            "UID": "5144f8b86e2b5045"
          },
          "InstalledVersion": "2.33.1-0.1",
          "FixedVersion": "2.33.1-0.1+deb10u1",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2021-37600",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "util-linux: integer overflow can lead to buffer overflow in get_sem_elements() in sys-utils/ipcutils.c",
          "Description": "An integer overflow in util-linux through 2.37.1 can potentially cause a buffer overflow if an attacker were able to use system resources in a way that leads to a large number in the /proc/sysvipc/sem file. NOTE: this is unexploitable in GNU C Library environments, and possibly in all realistic environments.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-190"
          ],
          "VendorSeverity": {
            "amazon": 1,
            "cbl-mariner": 2,
            "nvd": 2,
            "photon": 2,
            "redhat": 1,
            "ubuntu": 1
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:L/AC:H/Au:N/C:N/I:N/A:P",
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
              "V2Score": 1.2,
              "V3Score": 5.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:H",
              "V3Score": 4.7
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2021-37600",
            "https://github.com/karelzak/util-linux/commit/1c9143d0c1f979c3daf10e1c37b5b1e916c22a1c",
            "https://github.com/karelzak/util-linux/issues/1395",
            "https://lists.debian.org/debian-lts-announce/2024/04/msg00005.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-37600",
            "https://security.gentoo.org/glsa/202401-08",
            "https://security.netapp.com/advisory/ntap-20210902-0002/",
            "https://www.cve.org/CVERecord?id=CVE-2021-37600"
          ],
          "PublishedDate": "2021-07-30T14:15:18.737Z",
          "LastModifiedDate": "2024-08-04T02:15:24.44Z"
        },
        {
          "VulnerabilityID": "CVE-2022-0563",
          "PkgID": "fdisk@2.33.1-0.1",
          "PkgName": "fdisk",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/fdisk@2.33.1-0.1?arch=amd64\u0026distro=debian-10.13",
            "UID": "5144f8b86e2b5045"
          },
          "InstalledVersion": "2.33.1-0.1",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2022-0563",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "util-linux: partial disclosure of arbitrary files in chfn and chsh when compiled with libreadline",
          "Description": "A flaw was found in the util-linux chfn and chsh utilities when compiled with Readline support. The Readline library uses an \"INPUTRC\" environment variable to get a path to the library config file. When the library cannot parse the specified file, it prints an error message containing data from the file. This flaw allows an unprivileged user to read root-owned files, potentially leading to privilege escalation. This flaw affects util-linux versions prior to 2.37.4.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-209"
          ],
          "VendorSeverity": {
            "amazon": 2,
            "cbl-mariner": 2,
            "debian": 1,
            "nvd": 2,
            "photon": 2,
            "redhat": 2
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:L/AC:M/Au:N/C:P/I:N/A:N",
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
              "V2Score": 1.9,
              "V3Score": 5.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
              "V3Score": 5.5
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2022-0563",
            "https://blog.trailofbits.com/2023/02/16/suid-logic-bug-linux-readline/",
            "https://lore.kernel.org/util-linux/20220214110609.msiwlm457ngoic6w%40ws.net.home/T/#u",
            "https://lore.kernel.org/util-linux/20220214110609.msiwlm457ngoic6w@ws.net.home/T/#u",
            "https://nvd.nist.gov/vuln/detail/CVE-2022-0563",
            "https://security.gentoo.org/glsa/202401-08",
            "https://security.netapp.com/advisory/ntap-20220331-0002/",
            "https://www.cve.org/CVERecord?id=CVE-2022-0563"
          ],
          "PublishedDate": "2022-02-21T19:15:08.393Z",
          "LastModifiedDate": "2024-01-07T09:15:08.713Z"
        },
        {
          "VulnerabilityID": "CVE-2018-12886",
          "PkgID": "gcc-8-base@8.3.0-6",
          "PkgName": "gcc-8-base",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/gcc-8-base@8.3.0-6?arch=amd64\u0026distro=debian-10.13",
            "UID": "3c316548722f2d74"
          },
          "InstalledVersion": "8.3.0-6",
          "Status": "will_not_fix",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2018-12886",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "gcc: spilling of stack protection address in cfgexpand.c and function.c leads to stack-overflow protection bypass",
          "Description": "stack_protect_prologue in cfgexpand.c and stack_protect_epilogue in function.c in GNU Compiler Collection (GCC) 4.1 through 8 (under certain circumstances) generate instruction sequences when targeting ARM targets that spill the address of the stack protector guard, which allows an attacker to bypass the protection of -fstack-protector, -fstack-protector-all, -fstack-protector-strong, and -fstack-protector-explicit against stack overflow by controlling what the stack canary is compared against.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-209"
          ],
          "VendorSeverity": {
            "nvd": 3,
            "redhat": 2,
            "ubuntu": 1
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
              "V3Vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
              "V2Score": 6.8,
              "V3Score": 8.1
            },
            "redhat": {
              "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H",
              "V3Score": 6.8
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2018-12886",
            "https://gcc.gnu.org/git/?p=gcc.git;a=commit;h=89d7557202d25a393666ac4c0f7dbdab31e452a2",
            "https://gcc.gnu.org/viewcvs/gcc/trunk/gcc/config/arm/arm-protos.h?revision=266379\u0026view=markup",
            "https://nvd.nist.gov/vuln/detail/CVE-2018-12886",
            "https://www.cve.org/CVERecord?id=CVE-2018-12886",
            "https://www.gnu.org/software/gcc/gcc-8/changes.html"
          ],
          "PublishedDate": "2019-05-22T19:29:00.297Z",
          "LastModifiedDate": "2020-08-24T17:37:01.14Z"
        },
        {
          "VulnerabilityID": "CVE-2019-15847",
          "PkgID": "gcc-8-base@8.3.0-6",
          "PkgName": "gcc-8-base",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/gcc-8-base@8.3.0-6?arch=amd64\u0026distro=debian-10.13",
            "UID": "3c316548722f2d74"
          },
          "InstalledVersion": "8.3.0-6",
          "Status": "will_not_fix",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2019-15847",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "gcc: POWER9 \"DARN\" RNG intrinsic produces repeated output",
          "Description": "The POWER9 backend in GNU Compiler Collection (GCC) before version 10 could optimize multiple calls of the __builtin_darn intrinsic into a single call, thus reducing the entropy of the random number generator. This occurred because a volatile operation was not specified. For example, within a single execution of a program, the output of every __builtin_darn() call may be the same.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-331"
          ],
          "VendorSeverity": {
            "cbl-mariner": 3,
            "nvd": 3,
            "oracle-oval": 2,
            "redhat": 2,
            "ubuntu": 1
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:P/I:N/A:N",
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
              "V2Score": 5,
              "V3Score": 7.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
              "V3Score": 7.5
            }
          },
          "References": [
            "http://lists.opensuse.org/opensuse-security-announce/2019-10/msg00056.html",
            "http://lists.opensuse.org/opensuse-security-announce/2019-10/msg00057.html",
            "http://lists.opensuse.org/opensuse-security-announce/2020-05/msg00058.html",
            "https://access.redhat.com/security/cve/CVE-2019-15847",
            "https://gcc.gnu.org/bugzilla/show_bug.cgi?id=91481",
            "https://gcc.gnu.org/git/?p=gcc.git;a=commit;h=457dac402027dd7e14543fbd59a75858422cf6c6",
            "https://gcc.gnu.org/git/?p=gcc.git;a=commit;h=e99bfdd2a8db732ea84cf0a6486707e5e821ad7e",
            "https://linux.oracle.com/cve/CVE-2019-15847.html",
            "https://linux.oracle.com/errata/ELSA-2020-1864.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-15847",
            "https://www.cve.org/CVERecord?id=CVE-2019-15847"
          ],
          "PublishedDate": "2019-09-02T23:15:10.837Z",
          "LastModifiedDate": "2020-09-17T13:38:06.51Z"
        },
        {
          "VulnerabilityID": "CVE-2023-4039",
          "PkgID": "gcc-8-base@8.3.0-6",
          "PkgName": "gcc-8-base",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/gcc-8-base@8.3.0-6?arch=amd64\u0026distro=debian-10.13",
            "UID": "3c316548722f2d74"
          },
          "InstalledVersion": "8.3.0-6",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-4039",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "gcc: -fstack-protector fails to guard dynamic stack allocations on ARM64",
          "Description": "\n\n**DISPUTED**A failure in the -fstack-protector feature in GCC-based toolchains \nthat target AArch64 allows an attacker to exploit an existing buffer \noverflow in dynamically-sized local variables in your application \nwithout this being detected. This stack-protector failure only applies \nto C99-style dynamically-sized local variables or those created using \nalloca(). The stack-protector operates as intended for statically-sized \nlocal variables.\n\nThe default behavior when the stack-protector \ndetects an overflow is to terminate your application, resulting in \ncontrolled loss of availability. An attacker who can exploit a buffer \noverflow without triggering the stack-protector might be able to change \nprogram flow control to cause an uncontrolled loss of availability or to\n go further and affect confidentiality or integrity. NOTE: The GCC project argues that this is a missed hardening bug and not a vulnerability by itself.\n\n\n\n\n\n",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-693"
          ],
          "VendorSeverity": {
            "amazon": 2,
            "azure": 2,
            "cbl-mariner": 2,
            "nvd": 2,
            "oracle-oval": 1,
            "ubuntu": 2
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
              "V3Score": 4.8
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2023-4039",
            "https://developer.arm.com/Arm%20Security%20Center/GCC%20Stack%20Protector%20Vulnerability%20AArch64",
            "https://gcc.gnu.org/git/?p=gcc.git;a=blob_plain;f=SECURITY.txt",
            "https://gcc.gnu.org/pipermail/gcc-patches/2023-October/634066.html",
            "https://github.com/metaredteam/external-disclosures/security/advisories/GHSA-x7ch-h5rf-w2mf",
            "https://inbox.sourceware.org/gcc-patches/46cfa37b-56eb-344d-0745-e0d35393392d@gotplt.org",
            "https://linux.oracle.com/cve/CVE-2023-4039.html",
            "https://linux.oracle.com/errata/ELSA-2023-28766.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-4039",
            "https://rtx.meta.security/mitigation/2023/09/12/CVE-2023-4039.html",
            "https://www.cve.org/CVERecord?id=CVE-2023-4039"
          ],
          "PublishedDate": "2023-09-13T09:15:15.69Z",
          "LastModifiedDate": "2024-08-02T08:15:14.993Z"
        },
        {
          "VulnerabilityID": "CVE-2019-14855",
          "PkgID": "gpgv@2.2.12-1+deb10u2",
          "PkgName": "gpgv",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/gpgv@2.2.12-1%2Bdeb10u2?arch=amd64\u0026distro=debian-10.13",
            "UID": "93e020dac0e230fc"
          },
          "InstalledVersion": "2.2.12-1+deb10u2",
          "Status": "will_not_fix",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2019-14855",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "gnupg2: OpenPGP Key Certification Forgeries with SHA-1",
          "Description": "A flaw was found in the way certificate signatures could be forged using collisions found in the SHA-1 algorithm. An attacker could use this weakness to create forged certificate signatures. This issue affects GnuPG versions before 2.2.18.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-326"
          ],
          "VendorSeverity": {
            "debian": 1,
            "nvd": 3,
            "photon": 3,
            "redhat": 1,
            "ubuntu": 1
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:P/I:N/A:N",
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
              "V2Score": 5,
              "V3Score": 7.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N",
              "V3Score": 5.3
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2019-14855",
            "https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2019-14855",
            "https://dev.gnupg.org/T4755",
            "https://eprint.iacr.org/2020/014.pdf",
            "https://lists.gnupg.org/pipermail/gnupg-announce/2019q4/000442.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-14855",
            "https://rwc.iacr.org/2020/slides/Leurent.pdf",
            "https://ubuntu.com/security/notices/USN-4516-1",
            "https://usn.ubuntu.com/4516-1/",
            "https://www.cve.org/CVERecord?id=CVE-2019-14855"
          ],
          "PublishedDate": "2020-03-20T16:15:14.68Z",
          "LastModifiedDate": "2022-11-08T02:28:51.273Z"
        },
        {
          "VulnerabilityID": "CVE-2022-3219",
          "PkgID": "gpgv@2.2.12-1+deb10u2",
          "PkgName": "gpgv",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/gpgv@2.2.12-1%2Bdeb10u2?arch=amd64\u0026distro=debian-10.13",
            "UID": "93e020dac0e230fc"
          },
          "InstalledVersion": "2.2.12-1+deb10u2",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2022-3219",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "gnupg: denial of service issue (resource consumption) using compressed packets",
          "Description": "GnuPG can be made to spin on a relatively small input by (for example) crafting a public key with thousands of signatures attached, compressed down to just a few KB.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-787"
          ],
          "VendorSeverity": {
            "debian": 1,
            "nvd": 1,
            "redhat": 1,
            "ubuntu": 1
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L",
              "V3Score": 3.3
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 6.2
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2022-3219",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2127010",
            "https://dev.gnupg.org/D556",
            "https://dev.gnupg.org/T5993",
            "https://marc.info/?l=oss-security\u0026m=165696590211434\u0026w=4",
            "https://nvd.nist.gov/vuln/detail/CVE-2022-3219",
            "https://security.netapp.com/advisory/ntap-20230324-0001/",
            "https://www.cve.org/CVERecord?id=CVE-2022-3219"
          ],
          "PublishedDate": "2023-02-23T20:15:12.393Z",
          "LastModifiedDate": "2023-05-26T16:31:34.07Z"
        },
        {
          "VulnerabilityID": "CVE-2011-3374",
          "PkgID": "libapt-pkg5.0@1.8.2.3",
          "PkgName": "libapt-pkg5.0",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libapt-pkg5.0@1.8.2.3?arch=amd64\u0026distro=debian-10.13",
            "UID": "e84fe827b48a8fd7"
          },
          "InstalledVersion": "1.8.2.3",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2011-3374",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "It was found that apt-key in apt, all versions, do not correctly valid ...",
          "Description": "It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyring, leading to a potential man-in-the-middle attack.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-347"
          ],
          "VendorSeverity": {
            "debian": 1,
            "nvd": 1
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:M/Au:N/C:N/I:P/A:N",
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
              "V2Score": 4.3,
              "V3Score": 3.7
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/cve-2011-3374",
            "https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=642480",
            "https://people.canonical.com/~ubuntu-security/cve/2011/CVE-2011-3374.html",
            "https://seclists.org/fulldisclosure/2011/Sep/221",
            "https://security-tracker.debian.org/tracker/CVE-2011-3374",
            "https://snyk.io/vuln/SNYK-LINUX-APT-116518",
            "https://ubuntu.com/security/CVE-2011-3374"
          ],
          "PublishedDate": "2019-11-26T00:15:11.03Z",
          "LastModifiedDate": "2021-02-09T16:08:18.683Z"
        },
        {
          "VulnerabilityID": "CVE-2024-28085",
          "VendorIDs": [
            "DLA-3782-1"
          ],
          "PkgID": "libblkid1@2.33.1-0.1",
          "PkgName": "libblkid1",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libblkid1@2.33.1-0.1?arch=amd64\u0026distro=debian-10.13",
            "UID": "655d8182c873f5c2"
          },
          "InstalledVersion": "2.33.1-0.1",
          "FixedVersion": "2.33.1-0.1+deb10u1",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-28085",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "util-linux: CVE-2024-28085: wall: escape sequence injection",
          "Description": "wall in util-linux through 2.40, often installed with setgid tty permissions, allows escape sequences to be sent to other users' terminals through argv. (Specifically, escape sequences received from stdin are blocked, but escape sequences received from argv are not blocked.) There may be plausible scenarios where this leads to account takeover.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-150"
          ],
          "VendorSeverity": {
            "cbl-mariner": 4,
            "photon": 3,
            "redhat": 3,
            "ubuntu": 2
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N",
              "V3Score": 8.4
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2024/03/27/5",
            "http://www.openwall.com/lists/oss-security/2024/03/27/6",
            "http://www.openwall.com/lists/oss-security/2024/03/27/7",
            "http://www.openwall.com/lists/oss-security/2024/03/27/8",
            "http://www.openwall.com/lists/oss-security/2024/03/27/9",
            "http://www.openwall.com/lists/oss-security/2024/03/28/1",
            "http://www.openwall.com/lists/oss-security/2024/03/28/2",
            "http://www.openwall.com/lists/oss-security/2024/03/28/3",
            "https://access.redhat.com/security/cve/CVE-2024-28085",
            "https://github.com/skyler-ferrante/CVE-2024-28085",
            "https://github.com/util-linux/util-linux/security/advisories/GHSA-xv2h-c6ww-mrjq",
            "https://lists.debian.org/debian-lts-announce/2024/04/msg00005.html",
            "https://mirrors.edge.kernel.org/pub/linux/utils/util-linux/",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-28085",
            "https://people.rit.edu/sjf5462/6831711781/wall_2_27_2024.txt",
            "https://security.netapp.com/advisory/ntap-20240531-0003/",
            "https://ubuntu.com/security/notices/USN-6719-1",
            "https://ubuntu.com/security/notices/USN-6719-2",
            "https://www.cve.org/CVERecord?id=CVE-2024-28085",
            "https://www.openwall.com/lists/oss-security/2024/03/27/5"
          ],
          "PublishedDate": "2024-03-27T19:15:48.367Z",
          "LastModifiedDate": "2024-08-26T21:35:09.31Z"
        },
        {
          "VulnerabilityID": "CVE-2021-37600",
          "VendorIDs": [
            "DLA-3782-1"
          ],
          "PkgID": "libblkid1@2.33.1-0.1",
          "PkgName": "libblkid1",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libblkid1@2.33.1-0.1?arch=amd64\u0026distro=debian-10.13",
            "UID": "655d8182c873f5c2"
          },
          "InstalledVersion": "2.33.1-0.1",
          "FixedVersion": "2.33.1-0.1+deb10u1",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2021-37600",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "util-linux: integer overflow can lead to buffer overflow in get_sem_elements() in sys-utils/ipcutils.c",
          "Description": "An integer overflow in util-linux through 2.37.1 can potentially cause a buffer overflow if an attacker were able to use system resources in a way that leads to a large number in the /proc/sysvipc/sem file. NOTE: this is unexploitable in GNU C Library environments, and possibly in all realistic environments.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-190"
          ],
          "VendorSeverity": {
            "amazon": 1,
            "cbl-mariner": 2,
            "nvd": 2,
            "photon": 2,
            "redhat": 1,
            "ubuntu": 1
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:L/AC:H/Au:N/C:N/I:N/A:P",
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
              "V2Score": 1.2,
              "V3Score": 5.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:H",
              "V3Score": 4.7
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2021-37600",
            "https://github.com/karelzak/util-linux/commit/1c9143d0c1f979c3daf10e1c37b5b1e916c22a1c",
            "https://github.com/karelzak/util-linux/issues/1395",
            "https://lists.debian.org/debian-lts-announce/2024/04/msg00005.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-37600",
            "https://security.gentoo.org/glsa/202401-08",
            "https://security.netapp.com/advisory/ntap-20210902-0002/",
            "https://www.cve.org/CVERecord?id=CVE-2021-37600"
          ],
          "PublishedDate": "2021-07-30T14:15:18.737Z",
          "LastModifiedDate": "2024-08-04T02:15:24.44Z"
        },
        {
          "VulnerabilityID": "CVE-2022-0563",
          "PkgID": "libblkid1@2.33.1-0.1",
          "PkgName": "libblkid1",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libblkid1@2.33.1-0.1?arch=amd64\u0026distro=debian-10.13",
            "UID": "655d8182c873f5c2"
          },
          "InstalledVersion": "2.33.1-0.1",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2022-0563",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "util-linux: partial disclosure of arbitrary files in chfn and chsh when compiled with libreadline",
          "Description": "A flaw was found in the util-linux chfn and chsh utilities when compiled with Readline support. The Readline library uses an \"INPUTRC\" environment variable to get a path to the library config file. When the library cannot parse the specified file, it prints an error message containing data from the file. This flaw allows an unprivileged user to read root-owned files, potentially leading to privilege escalation. This flaw affects util-linux versions prior to 2.37.4.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-209"
          ],
          "VendorSeverity": {
            "amazon": 2,
            "cbl-mariner": 2,
            "debian": 1,
            "nvd": 2,
            "photon": 2,
            "redhat": 2
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:L/AC:M/Au:N/C:P/I:N/A:N",
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
              "V2Score": 1.9,
              "V3Score": 5.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
              "V3Score": 5.5
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2022-0563",
            "https://blog.trailofbits.com/2023/02/16/suid-logic-bug-linux-readline/",
            "https://lore.kernel.org/util-linux/20220214110609.msiwlm457ngoic6w%40ws.net.home/T/#u",
            "https://lore.kernel.org/util-linux/20220214110609.msiwlm457ngoic6w@ws.net.home/T/#u",
            "https://nvd.nist.gov/vuln/detail/CVE-2022-0563",
            "https://security.gentoo.org/glsa/202401-08",
            "https://security.netapp.com/advisory/ntap-20220331-0002/",
            "https://www.cve.org/CVERecord?id=CVE-2022-0563"
          ],
          "PublishedDate": "2022-02-21T19:15:08.393Z",
          "LastModifiedDate": "2024-01-07T09:15:08.713Z"
        },
        {
          "VulnerabilityID": "CVE-2020-1751",
          "PkgID": "libc-bin@2.28-10+deb10u2",
          "PkgName": "libc-bin",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libc-bin@2.28-10%2Bdeb10u2?arch=amd64\u0026distro=debian-10.13",
            "UID": "59a22f7eb2516d73"
          },
          "InstalledVersion": "2.28-10+deb10u2",
          "Status": "will_not_fix",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2020-1751",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "glibc: array overflow in backtrace functions for powerpc",
          "Description": "An out-of-bounds write vulnerability was found in glibc before 2.31 when handling signal trampolines on PowerPC. Specifically, the backtrace function did not properly check the array bounds when storing the frame address, resulting in a denial of service or potential code execution. The highest threat from this vulnerability is to system availability.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-787"
          ],
          "VendorSeverity": {
            "cbl-mariner": 3,
            "nvd": 3,
            "oracle-oval": 2,
            "redhat": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:L/AC:M/Au:N/C:P/I:P/A:C",
              "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H",
              "V2Score": 5.9,
              "V3Score": 7
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H",
              "V3Score": 7
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2020-1751",
            "https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2020-1751",
            "https://linux.oracle.com/cve/CVE-2020-1751.html",
            "https://linux.oracle.com/errata/ELSA-2020-4444.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2020-1751",
            "https://security.gentoo.org/glsa/202006-04",
            "https://security.netapp.com/advisory/ntap-20200430-0002/",
            "https://sourceware.org/bugzilla/show_bug.cgi?id=25423",
            "https://ubuntu.com/security/notices/USN-4416-1",
            "https://usn.ubuntu.com/4416-1/",
            "https://www.cve.org/CVERecord?id=CVE-2020-1751"
          ],
          "PublishedDate": "2020-04-17T19:15:14.437Z",
          "LastModifiedDate": "2023-11-07T03:19:33.177Z"
        },
        {
          "VulnerabilityID": "CVE-2024-2961",
          "VendorIDs": [
            "DLA-3807-1"
          ],
          "PkgID": "libc-bin@2.28-10+deb10u2",
          "PkgName": "libc-bin",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libc-bin@2.28-10%2Bdeb10u2?arch=amd64\u0026distro=debian-10.13",
            "UID": "59a22f7eb2516d73"
          },
          "InstalledVersion": "2.28-10+deb10u2",
          "FixedVersion": "2.28-10+deb10u3",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-2961",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "glibc: Out of bounds write in iconv may lead to remote code execution",
          "Description": "The iconv() function in the GNU C Library versions 2.39 and older may overflow the output buffer passed to it by up to 4 bytes when converting strings to the ISO-2022-CN-EXT character set, which may be used to crash an application or overwrite a neighbouring variable.\n",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-787"
          ],
          "VendorSeverity": {
            "alma": 3,
            "amazon": 3,
            "oracle-oval": 3,
            "photon": 3,
            "redhat": 3,
            "rocky": 3,
            "ubuntu": 2
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
              "V3Score": 8.8
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2024/04/17/9",
            "http://www.openwall.com/lists/oss-security/2024/04/18/4",
            "http://www.openwall.com/lists/oss-security/2024/04/24/2",
            "http://www.openwall.com/lists/oss-security/2024/05/27/1",
            "http://www.openwall.com/lists/oss-security/2024/05/27/2",
            "http://www.openwall.com/lists/oss-security/2024/05/27/3",
            "http://www.openwall.com/lists/oss-security/2024/05/27/4",
            "http://www.openwall.com/lists/oss-security/2024/05/27/5",
            "http://www.openwall.com/lists/oss-security/2024/05/27/6",
            "http://www.openwall.com/lists/oss-security/2024/07/22/5",
            "https://access.redhat.com/errata/RHSA-2024:3339",
            "https://access.redhat.com/security/cve/CVE-2024-2961",
            "https://bugzilla.redhat.com/2273404",
            "https://bugzilla.redhat.com/2277202",
            "https://bugzilla.redhat.com/2277204",
            "https://bugzilla.redhat.com/2277205",
            "https://bugzilla.redhat.com/2277206",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2273404",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2277202",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2277204",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2277205",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2277206",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-2961",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-33599",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-33600",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-33601",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-33602",
            "https://errata.almalinux.org/9/ALSA-2024-3339.html",
            "https://errata.rockylinux.org/RLSA-2024:3339",
            "https://linux.oracle.com/cve/CVE-2024-2961.html",
            "https://linux.oracle.com/errata/ELSA-2024-3588.html",
            "https://lists.debian.org/debian-lts-announce/2024/05/msg00001.html",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/BTJFBGHDYG5PEIFD5WSSSKSFZ2AZWC5N/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/P3I4KYS6EU6S7QZ47WFNTPVAHFIUQNEL/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/YAMJQI3Y6BHWV3CUTYBXOZONCUJNOB2Z/",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-2961",
            "https://security.netapp.com/advisory/ntap-20240531-0002/",
            "https://sourceware.org/git/?p=glibc.git;a=blob;f=advisories/GLIBC-SA-2024-0004",
            "https://ubuntu.com/security/notices/USN-6737-1",
            "https://ubuntu.com/security/notices/USN-6737-2",
            "https://ubuntu.com/security/notices/USN-6762-1",
            "https://www.cve.org/CVERecord?id=CVE-2024-2961",
            "https://www.openwall.com/lists/oss-security/2024/04/17/9"
          ],
          "PublishedDate": "2024-04-17T18:15:15.833Z",
          "LastModifiedDate": "2024-07-22T18:15:03.19Z"
        },
        {
          "VulnerabilityID": "CVE-2024-33599",
          "VendorIDs": [
            "DLA-3850-1"
          ],
          "PkgID": "libc-bin@2.28-10+deb10u2",
          "PkgName": "libc-bin",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libc-bin@2.28-10%2Bdeb10u2?arch=amd64\u0026distro=debian-10.13",
            "UID": "59a22f7eb2516d73"
          },
          "InstalledVersion": "2.28-10+deb10u2",
          "FixedVersion": "2.28-10+deb10u4",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-33599",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "glibc: stack-based buffer overflow in netgroup cache",
          "Description": "nscd: Stack-based buffer overflow in netgroup cache\n\nIf the Name Service Cache Daemon's (nscd) fixed size cache is exhausted\nby client requests then a subsequent client request for netgroup data\nmay result in a stack-based buffer overflow.  This flaw was introduced\nin glibc 2.15 when the cache was added to nscd.\n\nThis vulnerability is only present in the nscd binary.\n",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-121"
          ],
          "VendorSeverity": {
            "alma": 3,
            "cbl-mariner": 3,
            "oracle-oval": 3,
            "photon": 2,
            "redhat": 3,
            "rocky": 3,
            "ubuntu": 2
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:H",
              "V3Score": 7.6
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2024/07/22/5",
            "https://access.redhat.com/errata/RHSA-2024:3339",
            "https://access.redhat.com/security/cve/CVE-2024-33599",
            "https://bugzilla.redhat.com/2273404",
            "https://bugzilla.redhat.com/2277202",
            "https://bugzilla.redhat.com/2277204",
            "https://bugzilla.redhat.com/2277205",
            "https://bugzilla.redhat.com/2277206",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2273404",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2277202",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2277204",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2277205",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2277206",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-2961",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-33599",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-33600",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-33601",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-33602",
            "https://errata.almalinux.org/9/ALSA-2024-3339.html",
            "https://errata.rockylinux.org/RLSA-2024:3339",
            "https://inbox.sourceware.org/libc-alpha/cover.1713974801.git.fweimer@redhat.com/",
            "https://linux.oracle.com/cve/CVE-2024-33599.html",
            "https://linux.oracle.com/errata/ELSA-2024-3588.html",
            "https://lists.debian.org/debian-lts-announce/2024/06/msg00026.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-33599",
            "https://security.netapp.com/advisory/ntap-20240524-0011/",
            "https://sourceware.org/git/?p=glibc.git;a=blob;f=advisories/GLIBC-SA-2024-0005",
            "https://ubuntu.com/security/notices/USN-6804-1",
            "https://www.cve.org/CVERecord?id=CVE-2024-33599",
            "https://www.openwall.com/lists/oss-security/2024/04/24/2"
          ],
          "PublishedDate": "2024-05-06T20:15:11.437Z",
          "LastModifiedDate": "2024-07-22T18:15:03.323Z"
        },
        {
          "VulnerabilityID": "CVE-2023-4806",
          "PkgID": "libc-bin@2.28-10+deb10u2",
          "PkgName": "libc-bin",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libc-bin@2.28-10%2Bdeb10u2?arch=amd64\u0026distro=debian-10.13",
            "UID": "59a22f7eb2516d73"
          },
          "InstalledVersion": "2.28-10+deb10u2",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-4806",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "glibc: potential use-after-free in getaddrinfo()",
          "Description": "A flaw was found in glibc. In an extremely rare situation, the getaddrinfo function may access memory that has been freed, resulting in an application crash. This issue is only exploitable when a NSS module implements only the _nss_*_gethostbyname2_r and _nss_*_getcanonname_r hooks without implementing the _nss_*_gethostbyname3_r hook. The resolved name should return a large number of IPv6 and IPv4, and the call to the getaddrinfo function should have the AF_INET6 address family with AI_CANONNAME, AI_ALL and AI_V4MAPPED as flags.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-416"
          ],
          "VendorSeverity": {
            "alma": 3,
            "amazon": 3,
            "cbl-mariner": 2,
            "nvd": 2,
            "oracle-oval": 3,
            "photon": 2,
            "redhat": 2,
            "rocky": 3,
            "ubuntu": 1
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 5.9
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 5.9
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2023/10/03/4",
            "http://www.openwall.com/lists/oss-security/2023/10/03/5",
            "http://www.openwall.com/lists/oss-security/2023/10/03/6",
            "http://www.openwall.com/lists/oss-security/2023/10/03/8",
            "https://access.redhat.com/errata/RHSA-2023:5453",
            "https://access.redhat.com/errata/RHSA-2023:5455",
            "https://access.redhat.com/errata/RHSA-2023:7409",
            "https://access.redhat.com/security/cve/CVE-2023-4806",
            "https://bugzilla.redhat.com/2234712",
            "https://bugzilla.redhat.com/2237782",
            "https://bugzilla.redhat.com/2237798",
            "https://bugzilla.redhat.com/2238352",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2234712",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2237782",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2237798",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2238352",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4527",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4806",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4813",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4911",
            "https://errata.almalinux.org/9/ALSA-2023-5453.html",
            "https://errata.rockylinux.org/RLSA-2023:5455",
            "https://linux.oracle.com/cve/CVE-2023-4806.html",
            "https://linux.oracle.com/errata/ELSA-2023-5455.html",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/4DBUQRRPB47TC3NJOUIBVWUGFHBJAFDL/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/DFG4P76UHHZEWQ26FWBXG76N2QLKKPZA/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/NDAQWHTSVOCOZ5K6KPIWKRT3JX4RTZUR/",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-4806",
            "https://security.gentoo.org/glsa/202310-03",
            "https://security.netapp.com/advisory/ntap-20240125-0008/",
            "https://ubuntu.com/security/notices/USN-6541-1",
            "https://ubuntu.com/security/notices/USN-6541-2",
            "https://www.cve.org/CVERecord?id=CVE-2023-4806"
          ],
          "PublishedDate": "2023-09-18T17:15:55.813Z",
          "LastModifiedDate": "2024-01-25T14:15:26.36Z"
        },
        {
          "VulnerabilityID": "CVE-2023-4813",
          "PkgID": "libc-bin@2.28-10+deb10u2",
          "PkgName": "libc-bin",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libc-bin@2.28-10%2Bdeb10u2?arch=amd64\u0026distro=debian-10.13",
            "UID": "59a22f7eb2516d73"
          },
          "InstalledVersion": "2.28-10+deb10u2",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-4813",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "glibc: potential use-after-free in gaih_inet()",
          "Description": "A flaw was found in glibc. In an uncommon situation, the gaih_inet function may use memory that has been freed, resulting in an application crash. This issue is only exploitable when the getaddrinfo function is called and the hosts database in /etc/nsswitch.conf is configured with SUCCESS=continue or SUCCESS=merge.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-416"
          ],
          "VendorSeverity": {
            "alma": 3,
            "amazon": 3,
            "nvd": 2,
            "oracle-oval": 3,
            "photon": 2,
            "redhat": 2,
            "rocky": 3,
            "ubuntu": 1
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 5.9
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 5.9
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2023/10/03/8",
            "https://access.redhat.com/errata/RHSA-2023:5453",
            "https://access.redhat.com/errata/RHSA-2023:5455",
            "https://access.redhat.com/errata/RHSA-2023:7409",
            "https://access.redhat.com/security/cve/CVE-2023-4813",
            "https://bugzilla.redhat.com/2234712",
            "https://bugzilla.redhat.com/2237782",
            "https://bugzilla.redhat.com/2237798",
            "https://bugzilla.redhat.com/2238352",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2234712",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2237782",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2237798",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2238352",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4527",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4806",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4813",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4911",
            "https://errata.almalinux.org/9/ALSA-2023-5453.html",
            "https://errata.rockylinux.org/RLSA-2023:5455",
            "https://linux.oracle.com/cve/CVE-2023-4813.html",
            "https://linux.oracle.com/errata/ELSA-2023-5455.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-4813",
            "https://security.netapp.com/advisory/ntap-20231110-0003/",
            "https://ubuntu.com/security/notices/USN-6541-1",
            "https://ubuntu.com/security/notices/USN-6541-2",
            "https://www.cve.org/CVERecord?id=CVE-2023-4813"
          ],
          "PublishedDate": "2023-09-12T22:15:08.277Z",
          "LastModifiedDate": "2024-01-21T01:49:46.697Z"
        },
        {
          "VulnerabilityID": "CVE-2024-33600",
          "VendorIDs": [
            "DLA-3850-1"
          ],
          "PkgID": "libc-bin@2.28-10+deb10u2",
          "PkgName": "libc-bin",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libc-bin@2.28-10%2Bdeb10u2?arch=amd64\u0026distro=debian-10.13",
            "UID": "59a22f7eb2516d73"
          },
          "InstalledVersion": "2.28-10+deb10u2",
          "FixedVersion": "2.28-10+deb10u4",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-33600",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "glibc: null pointer dereferences after failed netgroup cache insertion",
          "Description": "nscd: Null pointer crashes after notfound response\n\nIf the Name Service Cache Daemon's (nscd) cache fails to add a not-found\nnetgroup response to the cache, the client request can result in a null\npointer dereference.  This flaw was introduced in glibc 2.15 when the\ncache was added to nscd.\n\nThis vulnerability is only present in the nscd binary.\n\n",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-476"
          ],
          "VendorSeverity": {
            "alma": 3,
            "cbl-mariner": 3,
            "oracle-oval": 3,
            "photon": 2,
            "redhat": 2,
            "rocky": 3,
            "ubuntu": 2
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
              "V3Score": 5.3
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2024/07/22/5",
            "https://access.redhat.com/errata/RHSA-2024:3339",
            "https://access.redhat.com/security/cve/CVE-2024-33600",
            "https://bugzilla.redhat.com/2273404",
            "https://bugzilla.redhat.com/2277202",
            "https://bugzilla.redhat.com/2277204",
            "https://bugzilla.redhat.com/2277205",
            "https://bugzilla.redhat.com/2277206",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2273404",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2277202",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2277204",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2277205",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2277206",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-2961",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-33599",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-33600",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-33601",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-33602",
            "https://errata.almalinux.org/9/ALSA-2024-3339.html",
            "https://errata.rockylinux.org/RLSA-2024:3339",
            "https://inbox.sourceware.org/libc-alpha/cover.1713974801.git.fweimer@redhat.com/",
            "https://linux.oracle.com/cve/CVE-2024-33600.html",
            "https://linux.oracle.com/errata/ELSA-2024-3588.html",
            "https://lists.debian.org/debian-lts-announce/2024/06/msg00026.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-33600",
            "https://security.netapp.com/advisory/ntap-20240524-0013/",
            "https://sourceware.org/git/?p=glibc.git;a=blob;f=advisories/GLIBC-SA-2024-0006",
            "https://ubuntu.com/security/notices/USN-6804-1",
            "https://www.cve.org/CVERecord?id=CVE-2024-33600",
            "https://www.openwall.com/lists/oss-security/2024/04/24/2"
          ],
          "PublishedDate": "2024-05-06T20:15:11.523Z",
          "LastModifiedDate": "2024-07-22T18:15:03.417Z"
        },
        {
          "VulnerabilityID": "CVE-2024-33601",
          "VendorIDs": [
            "DLA-3850-1"
          ],
          "PkgID": "libc-bin@2.28-10+deb10u2",
          "PkgName": "libc-bin",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libc-bin@2.28-10%2Bdeb10u2?arch=amd64\u0026distro=debian-10.13",
            "UID": "59a22f7eb2516d73"
          },
          "InstalledVersion": "2.28-10+deb10u2",
          "FixedVersion": "2.28-10+deb10u4",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-33601",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "glibc: netgroup cache may terminate daemon on memory allocation failure",
          "Description": "nscd: netgroup cache may terminate daemon on memory allocation failure\n\nThe Name Service Cache Daemon's (nscd) netgroup cache uses xmalloc or\nxrealloc and these functions may terminate the process due to a memory\nallocation failure resulting in a denial of service to the clients.  The\nflaw was introduced in glibc 2.15 when the cache was added to nscd.\n\nThis vulnerability is only present in the nscd binary.\n\n",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-617"
          ],
          "VendorSeverity": {
            "alma": 3,
            "cbl-mariner": 2,
            "oracle-oval": 3,
            "photon": 2,
            "redhat": 1,
            "rocky": 3,
            "ubuntu": 2
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
              "V3Score": 4
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2024/07/22/5",
            "https://access.redhat.com/errata/RHSA-2024:3339",
            "https://access.redhat.com/security/cve/CVE-2024-33601",
            "https://bugzilla.redhat.com/2273404",
            "https://bugzilla.redhat.com/2277202",
            "https://bugzilla.redhat.com/2277204",
            "https://bugzilla.redhat.com/2277205",
            "https://bugzilla.redhat.com/2277206",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2273404",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2277202",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2277204",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2277205",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2277206",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-2961",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-33599",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-33600",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-33601",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-33602",
            "https://errata.almalinux.org/9/ALSA-2024-3339.html",
            "https://errata.rockylinux.org/RLSA-2024:3339",
            "https://inbox.sourceware.org/libc-alpha/cover.1713974801.git.fweimer@redhat.com/",
            "https://linux.oracle.com/cve/CVE-2024-33601.html",
            "https://linux.oracle.com/errata/ELSA-2024-3588.html",
            "https://lists.debian.org/debian-lts-announce/2024/06/msg00026.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-33601",
            "https://security.netapp.com/advisory/ntap-20240524-0014/",
            "https://sourceware.org/git/?p=glibc.git;a=blob;f=advisories/GLIBC-SA-2024-0007",
            "https://ubuntu.com/security/notices/USN-6804-1",
            "https://www.cve.org/CVERecord?id=CVE-2024-33601",
            "https://www.openwall.com/lists/oss-security/2024/04/24/2"
          ],
          "PublishedDate": "2024-05-06T20:15:11.603Z",
          "LastModifiedDate": "2024-07-22T18:15:03.493Z"
        },
        {
          "VulnerabilityID": "CVE-2024-33602",
          "VendorIDs": [
            "DLA-3850-1"
          ],
          "PkgID": "libc-bin@2.28-10+deb10u2",
          "PkgName": "libc-bin",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libc-bin@2.28-10%2Bdeb10u2?arch=amd64\u0026distro=debian-10.13",
            "UID": "59a22f7eb2516d73"
          },
          "InstalledVersion": "2.28-10+deb10u2",
          "FixedVersion": "2.28-10+deb10u4",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-33602",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "glibc: netgroup cache assumes NSS callback uses in-buffer strings",
          "Description": "nscd: netgroup cache assumes NSS callback uses in-buffer strings\n\nThe Name Service Cache Daemon's (nscd) netgroup cache can corrupt memory\nwhen the NSS callback does not store all strings in the provided buffer.\nThe flaw was introduced in glibc 2.15 when the cache was added to nscd.\n\nThis vulnerability is only present in the nscd binary.\n\n",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-466"
          ],
          "VendorSeverity": {
            "alma": 3,
            "cbl-mariner": 3,
            "oracle-oval": 3,
            "photon": 2,
            "redhat": 1,
            "rocky": 3,
            "ubuntu": 2
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
              "V3Score": 4
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2024/07/22/5",
            "https://access.redhat.com/errata/RHSA-2024:3339",
            "https://access.redhat.com/security/cve/CVE-2024-33602",
            "https://bugzilla.redhat.com/2273404",
            "https://bugzilla.redhat.com/2277202",
            "https://bugzilla.redhat.com/2277204",
            "https://bugzilla.redhat.com/2277205",
            "https://bugzilla.redhat.com/2277206",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2273404",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2277202",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2277204",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2277205",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2277206",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-2961",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-33599",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-33600",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-33601",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-33602",
            "https://errata.almalinux.org/9/ALSA-2024-3339.html",
            "https://errata.rockylinux.org/RLSA-2024:3339",
            "https://inbox.sourceware.org/libc-alpha/cover.1713974801.git.fweimer@redhat.com/",
            "https://linux.oracle.com/cve/CVE-2024-33602.html",
            "https://linux.oracle.com/errata/ELSA-2024-3588.html",
            "https://lists.debian.org/debian-lts-announce/2024/06/msg00026.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-33602",
            "https://security.netapp.com/advisory/ntap-20240524-0012/",
            "https://sourceware.org/bugzilla/show_bug.cgi?id=31680",
            "https://sourceware.org/git/?p=glibc.git;a=blob;f=advisories/GLIBC-SA-2024-0008",
            "https://ubuntu.com/security/notices/USN-6804-1",
            "https://www.cve.org/CVERecord?id=CVE-2024-33602",
            "https://www.openwall.com/lists/oss-security/2024/04/24/2"
          ],
          "PublishedDate": "2024-05-06T20:15:11.68Z",
          "LastModifiedDate": "2024-07-22T18:15:03.583Z"
        },
        {
          "VulnerabilityID": "CVE-2010-4756",
          "PkgID": "libc-bin@2.28-10+deb10u2",
          "PkgName": "libc-bin",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libc-bin@2.28-10%2Bdeb10u2?arch=amd64\u0026distro=debian-10.13",
            "UID": "59a22f7eb2516d73"
          },
          "InstalledVersion": "2.28-10+deb10u2",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2010-4756",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "glibc: glob implementation can cause excessive CPU and memory consumption due to crafted glob expressions",
          "Description": "The glob implementation in the GNU C Library (aka glibc or libc6) allows remote authenticated users to cause a denial of service (CPU and memory consumption) via crafted glob expressions that do not match any pathnames, as demonstrated by glob expressions in STAT commands to an FTP daemon, a different vulnerability than CVE-2010-2632.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-399"
          ],
          "VendorSeverity": {
            "debian": 1,
            "nvd": 2,
            "redhat": 1
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:S/C:N/I:N/A:P",
              "V2Score": 4
            },
            "redhat": {
              "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
              "V2Score": 5
            }
          },
          "References": [
            "http://cxib.net/stuff/glob-0day.c",
            "http://securityreason.com/achievement_securityalert/89",
            "http://securityreason.com/exploitalert/9223",
            "https://access.redhat.com/security/cve/CVE-2010-4756",
            "https://bugzilla.redhat.com/show_bug.cgi?id=681681",
            "https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2010-4756",
            "https://nvd.nist.gov/vuln/detail/CVE-2010-4756",
            "https://www.cve.org/CVERecord?id=CVE-2010-4756"
          ],
          "PublishedDate": "2011-03-02T20:00:01.037Z",
          "LastModifiedDate": "2021-09-01T12:15:07.193Z"
        },
        {
          "VulnerabilityID": "CVE-2018-20796",
          "PkgID": "libc-bin@2.28-10+deb10u2",
          "PkgName": "libc-bin",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libc-bin@2.28-10%2Bdeb10u2?arch=amd64\u0026distro=debian-10.13",
            "UID": "59a22f7eb2516d73"
          },
          "InstalledVersion": "2.28-10+deb10u2",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2018-20796",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "glibc: uncontrolled recursion in function check_dst_limits_calc_pos_1 in posix/regexec.c",
          "Description": "In the GNU C Library (aka glibc or libc6) through 2.29, check_dst_limits_calc_pos_1 in posix/regexec.c has Uncontrolled Recursion, as demonstrated by '(\\227|)(\\\\1\\\\1|t1|\\\\\\2537)+' in grep.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-674"
          ],
          "VendorSeverity": {
            "cbl-mariner": 3,
            "debian": 1,
            "nvd": 3,
            "redhat": 2
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
              "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V2Score": 5,
              "V3Score": 7.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
              "V3Score": 5.3
            }
          },
          "References": [
            "http://www.securityfocus.com/bid/107160",
            "https://access.redhat.com/security/cve/CVE-2018-20796",
            "https://debbugs.gnu.org/cgi/bugreport.cgi?bug=34141",
            "https://lists.gnu.org/archive/html/bug-gnulib/2019-01/msg00108.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2018-20796",
            "https://security.netapp.com/advisory/ntap-20190315-0002/",
            "https://support.f5.com/csp/article/K26346590?utm_source=f5support\u0026amp%3Butm_medium=RSS",
            "https://www.cve.org/CVERecord?id=CVE-2018-20796"
          ],
          "PublishedDate": "2019-02-26T02:29:00.45Z",
          "LastModifiedDate": "2023-11-07T02:56:20.983Z"
        },
        {
          "VulnerabilityID": "CVE-2019-1010022",
          "PkgID": "libc-bin@2.28-10+deb10u2",
          "PkgName": "libc-bin",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libc-bin@2.28-10%2Bdeb10u2?arch=amd64\u0026distro=debian-10.13",
            "UID": "59a22f7eb2516d73"
          },
          "InstalledVersion": "2.28-10+deb10u2",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2019-1010022",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "glibc: stack guard protection bypass",
          "Description": "GNU Libc current is affected by: Mitigation bypass. The impact is: Attacker may bypass stack guard protection. The component is: nptl. The attack vector is: Exploit stack buffer overflow vulnerability and use this bypass vulnerability to bypass stack guard. NOTE: Upstream comments indicate \"this is being treated as a non-security bug and no real threat.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-119"
          ],
          "VendorSeverity": {
            "debian": 1,
            "nvd": 4
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
              "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
              "V2Score": 7.5,
              "V3Score": 9.8
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2019-1010022",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-1010022",
            "https://security-tracker.debian.org/tracker/CVE-2019-1010022",
            "https://sourceware.org/bugzilla/show_bug.cgi?id=22850",
            "https://sourceware.org/bugzilla/show_bug.cgi?id=22850#c3",
            "https://ubuntu.com/security/CVE-2019-1010022",
            "https://www.cve.org/CVERecord?id=CVE-2019-1010022"
          ],
          "PublishedDate": "2019-07-15T04:15:13.317Z",
          "LastModifiedDate": "2024-08-05T03:15:25.083Z"
        },
        {
          "VulnerabilityID": "CVE-2019-1010023",
          "PkgID": "libc-bin@2.28-10+deb10u2",
          "PkgName": "libc-bin",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libc-bin@2.28-10%2Bdeb10u2?arch=amd64\u0026distro=debian-10.13",
            "UID": "59a22f7eb2516d73"
          },
          "InstalledVersion": "2.28-10+deb10u2",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2019-1010023",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "glibc: running ldd on malicious ELF leads to code execution because of wrong size computation",
          "Description": "GNU Libc current is affected by: Re-mapping current loaded library with malicious ELF file. The impact is: In worst case attacker may evaluate privileges. The component is: libld. The attack vector is: Attacker sends 2 ELF files to victim and asks to run ldd on it. ldd execute code. NOTE: Upstream comments indicate \"this is being treated as a non-security bug and no real threat.",
          "Severity": "LOW",
          "VendorSeverity": {
            "debian": 1,
            "nvd": 3,
            "redhat": 1
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
              "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
              "V2Score": 6.8,
              "V3Score": 8.8
            },
            "redhat": {
              "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
              "V3Score": 7.8
            }
          },
          "References": [
            "http://www.securityfocus.com/bid/109167",
            "https://access.redhat.com/security/cve/CVE-2019-1010023",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-1010023",
            "https://security-tracker.debian.org/tracker/CVE-2019-1010023",
            "https://sourceware.org/bugzilla/show_bug.cgi?id=22851",
            "https://support.f5.com/csp/article/K11932200?utm_source=f5support\u0026amp%3Butm_medium=RSS",
            "https://ubuntu.com/security/CVE-2019-1010023",
            "https://www.cve.org/CVERecord?id=CVE-2019-1010023"
          ],
          "PublishedDate": "2019-07-15T04:15:13.397Z",
          "LastModifiedDate": "2024-08-05T03:15:25.183Z"
        },
        {
          "VulnerabilityID": "CVE-2019-1010024",
          "PkgID": "libc-bin@2.28-10+deb10u2",
          "PkgName": "libc-bin",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libc-bin@2.28-10%2Bdeb10u2?arch=amd64\u0026distro=debian-10.13",
            "UID": "59a22f7eb2516d73"
          },
          "InstalledVersion": "2.28-10+deb10u2",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2019-1010024",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "glibc: ASLR bypass using cache of thread stack and heap",
          "Description": "GNU Libc current is affected by: Mitigation bypass. The impact is: Attacker may bypass ASLR using cache of thread stack and heap. The component is: glibc. NOTE: Upstream comments indicate \"this is being treated as a non-security bug and no real threat.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-200"
          ],
          "VendorSeverity": {
            "debian": 1,
            "nvd": 2,
            "redhat": 2
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:P/I:N/A:N",
              "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
              "V2Score": 5,
              "V3Score": 5.3
            },
            "redhat": {
              "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
              "V3Score": 5.3
            }
          },
          "References": [
            "http://www.securityfocus.com/bid/109162",
            "https://access.redhat.com/security/cve/CVE-2019-1010024",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-1010024",
            "https://security-tracker.debian.org/tracker/CVE-2019-1010024",
            "https://sourceware.org/bugzilla/show_bug.cgi?id=22852",
            "https://support.f5.com/csp/article/K06046097",
            "https://support.f5.com/csp/article/K06046097?utm_source=f5support\u0026amp%3Butm_medium=RSS",
            "https://ubuntu.com/security/CVE-2019-1010024",
            "https://www.cve.org/CVERecord?id=CVE-2019-1010024"
          ],
          "PublishedDate": "2019-07-15T04:15:13.473Z",
          "LastModifiedDate": "2024-08-05T03:15:25.26Z"
        },
        {
          "VulnerabilityID": "CVE-2019-1010025",
          "PkgID": "libc-bin@2.28-10+deb10u2",
          "PkgName": "libc-bin",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libc-bin@2.28-10%2Bdeb10u2?arch=amd64\u0026distro=debian-10.13",
            "UID": "59a22f7eb2516d73"
          },
          "InstalledVersion": "2.28-10+deb10u2",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2019-1010025",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "glibc: information disclosure of heap addresses of pthread_created thread",
          "Description": "GNU Libc current is affected by: Mitigation bypass. The impact is: Attacker may guess the heap addresses of pthread_created thread. The component is: glibc. NOTE: the vendor's position is \"ASLR bypass itself is not a vulnerability.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-330"
          ],
          "VendorSeverity": {
            "debian": 1,
            "nvd": 2,
            "redhat": 1
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:P/I:N/A:N",
              "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
              "V2Score": 5,
              "V3Score": 5.3
            },
            "redhat": {
              "V3Vector": "CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
              "V3Score": 2.9
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2019-1010025",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-1010025",
            "https://security-tracker.debian.org/tracker/CVE-2019-1010025",
            "https://sourceware.org/bugzilla/show_bug.cgi?id=22853",
            "https://support.f5.com/csp/article/K06046097",
            "https://support.f5.com/csp/article/K06046097?utm_source=f5support\u0026amp%3Butm_medium=RSS",
            "https://ubuntu.com/security/CVE-2019-1010025",
            "https://www.cve.org/CVERecord?id=CVE-2019-1010025"
          ],
          "PublishedDate": "2019-07-15T04:15:13.537Z",
          "LastModifiedDate": "2024-08-05T03:15:25.333Z"
        },
        {
          "VulnerabilityID": "CVE-2019-9192",
          "PkgID": "libc-bin@2.28-10+deb10u2",
          "PkgName": "libc-bin",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libc-bin@2.28-10%2Bdeb10u2?arch=amd64\u0026distro=debian-10.13",
            "UID": "59a22f7eb2516d73"
          },
          "InstalledVersion": "2.28-10+deb10u2",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2019-9192",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "glibc: uncontrolled recursion in function check_dst_limits_calc_pos_1 in posix/regexec.c",
          "Description": "In the GNU C Library (aka glibc or libc6) through 2.29, check_dst_limits_calc_pos_1 in posix/regexec.c has Uncontrolled Recursion, as demonstrated by '(|)(\\\\1\\\\1)*' in grep, a different issue than CVE-2018-20796. NOTE: the software maintainer disputes that this is a vulnerability because the behavior occurs only with a crafted pattern",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-674"
          ],
          "VendorSeverity": {
            "cbl-mariner": 3,
            "debian": 1,
            "nvd": 3,
            "redhat": 1
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
              "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V2Score": 5,
              "V3Score": 7.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:N/I:N/A:L",
              "V3Score": 2.8
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2019-9192",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-9192",
            "https://sourceware.org/bugzilla/show_bug.cgi?id=24269",
            "https://support.f5.com/csp/article/K26346590?utm_source=f5support\u0026amp%3Butm_medium=RSS",
            "https://www.cve.org/CVERecord?id=CVE-2019-9192"
          ],
          "PublishedDate": "2019-02-26T18:29:00.34Z",
          "LastModifiedDate": "2024-08-04T22:15:34.74Z"
        },
        {
          "VulnerabilityID": "CVE-2020-1751",
          "PkgID": "libc6@2.28-10+deb10u2",
          "PkgName": "libc6",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libc6@2.28-10%2Bdeb10u2?arch=amd64\u0026distro=debian-10.13",
            "UID": "5a3be8cddcee1bcf"
          },
          "InstalledVersion": "2.28-10+deb10u2",
          "Status": "will_not_fix",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2020-1751",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "glibc: array overflow in backtrace functions for powerpc",
          "Description": "An out-of-bounds write vulnerability was found in glibc before 2.31 when handling signal trampolines on PowerPC. Specifically, the backtrace function did not properly check the array bounds when storing the frame address, resulting in a denial of service or potential code execution. The highest threat from this vulnerability is to system availability.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-787"
          ],
          "VendorSeverity": {
            "cbl-mariner": 3,
            "nvd": 3,
            "oracle-oval": 2,
            "redhat": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:L/AC:M/Au:N/C:P/I:P/A:C",
              "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H",
              "V2Score": 5.9,
              "V3Score": 7
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H",
              "V3Score": 7
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2020-1751",
            "https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2020-1751",
            "https://linux.oracle.com/cve/CVE-2020-1751.html",
            "https://linux.oracle.com/errata/ELSA-2020-4444.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2020-1751",
            "https://security.gentoo.org/glsa/202006-04",
            "https://security.netapp.com/advisory/ntap-20200430-0002/",
            "https://sourceware.org/bugzilla/show_bug.cgi?id=25423",
            "https://ubuntu.com/security/notices/USN-4416-1",
            "https://usn.ubuntu.com/4416-1/",
            "https://www.cve.org/CVERecord?id=CVE-2020-1751"
          ],
          "PublishedDate": "2020-04-17T19:15:14.437Z",
          "LastModifiedDate": "2023-11-07T03:19:33.177Z"
        },
        {
          "VulnerabilityID": "CVE-2024-2961",
          "VendorIDs": [
            "DLA-3807-1"
          ],
          "PkgID": "libc6@2.28-10+deb10u2",
          "PkgName": "libc6",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libc6@2.28-10%2Bdeb10u2?arch=amd64\u0026distro=debian-10.13",
            "UID": "5a3be8cddcee1bcf"
          },
          "InstalledVersion": "2.28-10+deb10u2",
          "FixedVersion": "2.28-10+deb10u3",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-2961",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "glibc: Out of bounds write in iconv may lead to remote code execution",
          "Description": "The iconv() function in the GNU C Library versions 2.39 and older may overflow the output buffer passed to it by up to 4 bytes when converting strings to the ISO-2022-CN-EXT character set, which may be used to crash an application or overwrite a neighbouring variable.\n",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-787"
          ],
          "VendorSeverity": {
            "alma": 3,
            "amazon": 3,
            "oracle-oval": 3,
            "photon": 3,
            "redhat": 3,
            "rocky": 3,
            "ubuntu": 2
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
              "V3Score": 8.8
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2024/04/17/9",
            "http://www.openwall.com/lists/oss-security/2024/04/18/4",
            "http://www.openwall.com/lists/oss-security/2024/04/24/2",
            "http://www.openwall.com/lists/oss-security/2024/05/27/1",
            "http://www.openwall.com/lists/oss-security/2024/05/27/2",
            "http://www.openwall.com/lists/oss-security/2024/05/27/3",
            "http://www.openwall.com/lists/oss-security/2024/05/27/4",
            "http://www.openwall.com/lists/oss-security/2024/05/27/5",
            "http://www.openwall.com/lists/oss-security/2024/05/27/6",
            "http://www.openwall.com/lists/oss-security/2024/07/22/5",
            "https://access.redhat.com/errata/RHSA-2024:3339",
            "https://access.redhat.com/security/cve/CVE-2024-2961",
            "https://bugzilla.redhat.com/2273404",
            "https://bugzilla.redhat.com/2277202",
            "https://bugzilla.redhat.com/2277204",
            "https://bugzilla.redhat.com/2277205",
            "https://bugzilla.redhat.com/2277206",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2273404",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2277202",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2277204",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2277205",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2277206",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-2961",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-33599",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-33600",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-33601",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-33602",
            "https://errata.almalinux.org/9/ALSA-2024-3339.html",
            "https://errata.rockylinux.org/RLSA-2024:3339",
            "https://linux.oracle.com/cve/CVE-2024-2961.html",
            "https://linux.oracle.com/errata/ELSA-2024-3588.html",
            "https://lists.debian.org/debian-lts-announce/2024/05/msg00001.html",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/BTJFBGHDYG5PEIFD5WSSSKSFZ2AZWC5N/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/P3I4KYS6EU6S7QZ47WFNTPVAHFIUQNEL/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/YAMJQI3Y6BHWV3CUTYBXOZONCUJNOB2Z/",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-2961",
            "https://security.netapp.com/advisory/ntap-20240531-0002/",
            "https://sourceware.org/git/?p=glibc.git;a=blob;f=advisories/GLIBC-SA-2024-0004",
            "https://ubuntu.com/security/notices/USN-6737-1",
            "https://ubuntu.com/security/notices/USN-6737-2",
            "https://ubuntu.com/security/notices/USN-6762-1",
            "https://www.cve.org/CVERecord?id=CVE-2024-2961",
            "https://www.openwall.com/lists/oss-security/2024/04/17/9"
          ],
          "PublishedDate": "2024-04-17T18:15:15.833Z",
          "LastModifiedDate": "2024-07-22T18:15:03.19Z"
        },
        {
          "VulnerabilityID": "CVE-2024-33599",
          "VendorIDs": [
            "DLA-3850-1"
          ],
          "PkgID": "libc6@2.28-10+deb10u2",
          "PkgName": "libc6",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libc6@2.28-10%2Bdeb10u2?arch=amd64\u0026distro=debian-10.13",
            "UID": "5a3be8cddcee1bcf"
          },
          "InstalledVersion": "2.28-10+deb10u2",
          "FixedVersion": "2.28-10+deb10u4",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-33599",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "glibc: stack-based buffer overflow in netgroup cache",
          "Description": "nscd: Stack-based buffer overflow in netgroup cache\n\nIf the Name Service Cache Daemon's (nscd) fixed size cache is exhausted\nby client requests then a subsequent client request for netgroup data\nmay result in a stack-based buffer overflow.  This flaw was introduced\nin glibc 2.15 when the cache was added to nscd.\n\nThis vulnerability is only present in the nscd binary.\n",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-121"
          ],
          "VendorSeverity": {
            "alma": 3,
            "cbl-mariner": 3,
            "oracle-oval": 3,
            "photon": 2,
            "redhat": 3,
            "rocky": 3,
            "ubuntu": 2
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:H",
              "V3Score": 7.6
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2024/07/22/5",
            "https://access.redhat.com/errata/RHSA-2024:3339",
            "https://access.redhat.com/security/cve/CVE-2024-33599",
            "https://bugzilla.redhat.com/2273404",
            "https://bugzilla.redhat.com/2277202",
            "https://bugzilla.redhat.com/2277204",
            "https://bugzilla.redhat.com/2277205",
            "https://bugzilla.redhat.com/2277206",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2273404",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2277202",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2277204",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2277205",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2277206",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-2961",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-33599",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-33600",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-33601",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-33602",
            "https://errata.almalinux.org/9/ALSA-2024-3339.html",
            "https://errata.rockylinux.org/RLSA-2024:3339",
            "https://inbox.sourceware.org/libc-alpha/cover.1713974801.git.fweimer@redhat.com/",
            "https://linux.oracle.com/cve/CVE-2024-33599.html",
            "https://linux.oracle.com/errata/ELSA-2024-3588.html",
            "https://lists.debian.org/debian-lts-announce/2024/06/msg00026.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-33599",
            "https://security.netapp.com/advisory/ntap-20240524-0011/",
            "https://sourceware.org/git/?p=glibc.git;a=blob;f=advisories/GLIBC-SA-2024-0005",
            "https://ubuntu.com/security/notices/USN-6804-1",
            "https://www.cve.org/CVERecord?id=CVE-2024-33599",
            "https://www.openwall.com/lists/oss-security/2024/04/24/2"
          ],
          "PublishedDate": "2024-05-06T20:15:11.437Z",
          "LastModifiedDate": "2024-07-22T18:15:03.323Z"
        },
        {
          "VulnerabilityID": "CVE-2023-4806",
          "PkgID": "libc6@2.28-10+deb10u2",
          "PkgName": "libc6",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libc6@2.28-10%2Bdeb10u2?arch=amd64\u0026distro=debian-10.13",
            "UID": "5a3be8cddcee1bcf"
          },
          "InstalledVersion": "2.28-10+deb10u2",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-4806",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "glibc: potential use-after-free in getaddrinfo()",
          "Description": "A flaw was found in glibc. In an extremely rare situation, the getaddrinfo function may access memory that has been freed, resulting in an application crash. This issue is only exploitable when a NSS module implements only the _nss_*_gethostbyname2_r and _nss_*_getcanonname_r hooks without implementing the _nss_*_gethostbyname3_r hook. The resolved name should return a large number of IPv6 and IPv4, and the call to the getaddrinfo function should have the AF_INET6 address family with AI_CANONNAME, AI_ALL and AI_V4MAPPED as flags.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-416"
          ],
          "VendorSeverity": {
            "alma": 3,
            "amazon": 3,
            "cbl-mariner": 2,
            "nvd": 2,
            "oracle-oval": 3,
            "photon": 2,
            "redhat": 2,
            "rocky": 3,
            "ubuntu": 1
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 5.9
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 5.9
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2023/10/03/4",
            "http://www.openwall.com/lists/oss-security/2023/10/03/5",
            "http://www.openwall.com/lists/oss-security/2023/10/03/6",
            "http://www.openwall.com/lists/oss-security/2023/10/03/8",
            "https://access.redhat.com/errata/RHSA-2023:5453",
            "https://access.redhat.com/errata/RHSA-2023:5455",
            "https://access.redhat.com/errata/RHSA-2023:7409",
            "https://access.redhat.com/security/cve/CVE-2023-4806",
            "https://bugzilla.redhat.com/2234712",
            "https://bugzilla.redhat.com/2237782",
            "https://bugzilla.redhat.com/2237798",
            "https://bugzilla.redhat.com/2238352",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2234712",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2237782",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2237798",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2238352",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4527",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4806",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4813",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4911",
            "https://errata.almalinux.org/9/ALSA-2023-5453.html",
            "https://errata.rockylinux.org/RLSA-2023:5455",
            "https://linux.oracle.com/cve/CVE-2023-4806.html",
            "https://linux.oracle.com/errata/ELSA-2023-5455.html",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/4DBUQRRPB47TC3NJOUIBVWUGFHBJAFDL/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/DFG4P76UHHZEWQ26FWBXG76N2QLKKPZA/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/NDAQWHTSVOCOZ5K6KPIWKRT3JX4RTZUR/",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-4806",
            "https://security.gentoo.org/glsa/202310-03",
            "https://security.netapp.com/advisory/ntap-20240125-0008/",
            "https://ubuntu.com/security/notices/USN-6541-1",
            "https://ubuntu.com/security/notices/USN-6541-2",
            "https://www.cve.org/CVERecord?id=CVE-2023-4806"
          ],
          "PublishedDate": "2023-09-18T17:15:55.813Z",
          "LastModifiedDate": "2024-01-25T14:15:26.36Z"
        },
        {
          "VulnerabilityID": "CVE-2023-4813",
          "PkgID": "libc6@2.28-10+deb10u2",
          "PkgName": "libc6",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libc6@2.28-10%2Bdeb10u2?arch=amd64\u0026distro=debian-10.13",
            "UID": "5a3be8cddcee1bcf"
          },
          "InstalledVersion": "2.28-10+deb10u2",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-4813",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "glibc: potential use-after-free in gaih_inet()",
          "Description": "A flaw was found in glibc. In an uncommon situation, the gaih_inet function may use memory that has been freed, resulting in an application crash. This issue is only exploitable when the getaddrinfo function is called and the hosts database in /etc/nsswitch.conf is configured with SUCCESS=continue or SUCCESS=merge.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-416"
          ],
          "VendorSeverity": {
            "alma": 3,
            "amazon": 3,
            "nvd": 2,
            "oracle-oval": 3,
            "photon": 2,
            "redhat": 2,
            "rocky": 3,
            "ubuntu": 1
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 5.9
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 5.9
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2023/10/03/8",
            "https://access.redhat.com/errata/RHSA-2023:5453",
            "https://access.redhat.com/errata/RHSA-2023:5455",
            "https://access.redhat.com/errata/RHSA-2023:7409",
            "https://access.redhat.com/security/cve/CVE-2023-4813",
            "https://bugzilla.redhat.com/2234712",
            "https://bugzilla.redhat.com/2237782",
            "https://bugzilla.redhat.com/2237798",
            "https://bugzilla.redhat.com/2238352",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2234712",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2237782",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2237798",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2238352",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4527",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4806",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4813",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4911",
            "https://errata.almalinux.org/9/ALSA-2023-5453.html",
            "https://errata.rockylinux.org/RLSA-2023:5455",
            "https://linux.oracle.com/cve/CVE-2023-4813.html",
            "https://linux.oracle.com/errata/ELSA-2023-5455.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-4813",
            "https://security.netapp.com/advisory/ntap-20231110-0003/",
            "https://ubuntu.com/security/notices/USN-6541-1",
            "https://ubuntu.com/security/notices/USN-6541-2",
            "https://www.cve.org/CVERecord?id=CVE-2023-4813"
          ],
          "PublishedDate": "2023-09-12T22:15:08.277Z",
          "LastModifiedDate": "2024-01-21T01:49:46.697Z"
        },
        {
          "VulnerabilityID": "CVE-2024-33600",
          "VendorIDs": [
            "DLA-3850-1"
          ],
          "PkgID": "libc6@2.28-10+deb10u2",
          "PkgName": "libc6",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libc6@2.28-10%2Bdeb10u2?arch=amd64\u0026distro=debian-10.13",
            "UID": "5a3be8cddcee1bcf"
          },
          "InstalledVersion": "2.28-10+deb10u2",
          "FixedVersion": "2.28-10+deb10u4",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-33600",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "glibc: null pointer dereferences after failed netgroup cache insertion",
          "Description": "nscd: Null pointer crashes after notfound response\n\nIf the Name Service Cache Daemon's (nscd) cache fails to add a not-found\nnetgroup response to the cache, the client request can result in a null\npointer dereference.  This flaw was introduced in glibc 2.15 when the\ncache was added to nscd.\n\nThis vulnerability is only present in the nscd binary.\n\n",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-476"
          ],
          "VendorSeverity": {
            "alma": 3,
            "cbl-mariner": 3,
            "oracle-oval": 3,
            "photon": 2,
            "redhat": 2,
            "rocky": 3,
            "ubuntu": 2
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
              "V3Score": 5.3
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2024/07/22/5",
            "https://access.redhat.com/errata/RHSA-2024:3339",
            "https://access.redhat.com/security/cve/CVE-2024-33600",
            "https://bugzilla.redhat.com/2273404",
            "https://bugzilla.redhat.com/2277202",
            "https://bugzilla.redhat.com/2277204",
            "https://bugzilla.redhat.com/2277205",
            "https://bugzilla.redhat.com/2277206",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2273404",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2277202",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2277204",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2277205",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2277206",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-2961",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-33599",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-33600",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-33601",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-33602",
            "https://errata.almalinux.org/9/ALSA-2024-3339.html",
            "https://errata.rockylinux.org/RLSA-2024:3339",
            "https://inbox.sourceware.org/libc-alpha/cover.1713974801.git.fweimer@redhat.com/",
            "https://linux.oracle.com/cve/CVE-2024-33600.html",
            "https://linux.oracle.com/errata/ELSA-2024-3588.html",
            "https://lists.debian.org/debian-lts-announce/2024/06/msg00026.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-33600",
            "https://security.netapp.com/advisory/ntap-20240524-0013/",
            "https://sourceware.org/git/?p=glibc.git;a=blob;f=advisories/GLIBC-SA-2024-0006",
            "https://ubuntu.com/security/notices/USN-6804-1",
            "https://www.cve.org/CVERecord?id=CVE-2024-33600",
            "https://www.openwall.com/lists/oss-security/2024/04/24/2"
          ],
          "PublishedDate": "2024-05-06T20:15:11.523Z",
          "LastModifiedDate": "2024-07-22T18:15:03.417Z"
        },
        {
          "VulnerabilityID": "CVE-2024-33601",
          "VendorIDs": [
            "DLA-3850-1"
          ],
          "PkgID": "libc6@2.28-10+deb10u2",
          "PkgName": "libc6",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libc6@2.28-10%2Bdeb10u2?arch=amd64\u0026distro=debian-10.13",
            "UID": "5a3be8cddcee1bcf"
          },
          "InstalledVersion": "2.28-10+deb10u2",
          "FixedVersion": "2.28-10+deb10u4",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-33601",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "glibc: netgroup cache may terminate daemon on memory allocation failure",
          "Description": "nscd: netgroup cache may terminate daemon on memory allocation failure\n\nThe Name Service Cache Daemon's (nscd) netgroup cache uses xmalloc or\nxrealloc and these functions may terminate the process due to a memory\nallocation failure resulting in a denial of service to the clients.  The\nflaw was introduced in glibc 2.15 when the cache was added to nscd.\n\nThis vulnerability is only present in the nscd binary.\n\n",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-617"
          ],
          "VendorSeverity": {
            "alma": 3,
            "cbl-mariner": 2,
            "oracle-oval": 3,
            "photon": 2,
            "redhat": 1,
            "rocky": 3,
            "ubuntu": 2
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
              "V3Score": 4
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2024/07/22/5",
            "https://access.redhat.com/errata/RHSA-2024:3339",
            "https://access.redhat.com/security/cve/CVE-2024-33601",
            "https://bugzilla.redhat.com/2273404",
            "https://bugzilla.redhat.com/2277202",
            "https://bugzilla.redhat.com/2277204",
            "https://bugzilla.redhat.com/2277205",
            "https://bugzilla.redhat.com/2277206",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2273404",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2277202",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2277204",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2277205",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2277206",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-2961",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-33599",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-33600",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-33601",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-33602",
            "https://errata.almalinux.org/9/ALSA-2024-3339.html",
            "https://errata.rockylinux.org/RLSA-2024:3339",
            "https://inbox.sourceware.org/libc-alpha/cover.1713974801.git.fweimer@redhat.com/",
            "https://linux.oracle.com/cve/CVE-2024-33601.html",
            "https://linux.oracle.com/errata/ELSA-2024-3588.html",
            "https://lists.debian.org/debian-lts-announce/2024/06/msg00026.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-33601",
            "https://security.netapp.com/advisory/ntap-20240524-0014/",
            "https://sourceware.org/git/?p=glibc.git;a=blob;f=advisories/GLIBC-SA-2024-0007",
            "https://ubuntu.com/security/notices/USN-6804-1",
            "https://www.cve.org/CVERecord?id=CVE-2024-33601",
            "https://www.openwall.com/lists/oss-security/2024/04/24/2"
          ],
          "PublishedDate": "2024-05-06T20:15:11.603Z",
          "LastModifiedDate": "2024-07-22T18:15:03.493Z"
        },
        {
          "VulnerabilityID": "CVE-2024-33602",
          "VendorIDs": [
            "DLA-3850-1"
          ],
          "PkgID": "libc6@2.28-10+deb10u2",
          "PkgName": "libc6",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libc6@2.28-10%2Bdeb10u2?arch=amd64\u0026distro=debian-10.13",
            "UID": "5a3be8cddcee1bcf"
          },
          "InstalledVersion": "2.28-10+deb10u2",
          "FixedVersion": "2.28-10+deb10u4",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-33602",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "glibc: netgroup cache assumes NSS callback uses in-buffer strings",
          "Description": "nscd: netgroup cache assumes NSS callback uses in-buffer strings\n\nThe Name Service Cache Daemon's (nscd) netgroup cache can corrupt memory\nwhen the NSS callback does not store all strings in the provided buffer.\nThe flaw was introduced in glibc 2.15 when the cache was added to nscd.\n\nThis vulnerability is only present in the nscd binary.\n\n",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-466"
          ],
          "VendorSeverity": {
            "alma": 3,
            "cbl-mariner": 3,
            "oracle-oval": 3,
            "photon": 2,
            "redhat": 1,
            "rocky": 3,
            "ubuntu": 2
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
              "V3Score": 4
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2024/07/22/5",
            "https://access.redhat.com/errata/RHSA-2024:3339",
            "https://access.redhat.com/security/cve/CVE-2024-33602",
            "https://bugzilla.redhat.com/2273404",
            "https://bugzilla.redhat.com/2277202",
            "https://bugzilla.redhat.com/2277204",
            "https://bugzilla.redhat.com/2277205",
            "https://bugzilla.redhat.com/2277206",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2273404",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2277202",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2277204",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2277205",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2277206",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-2961",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-33599",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-33600",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-33601",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-33602",
            "https://errata.almalinux.org/9/ALSA-2024-3339.html",
            "https://errata.rockylinux.org/RLSA-2024:3339",
            "https://inbox.sourceware.org/libc-alpha/cover.1713974801.git.fweimer@redhat.com/",
            "https://linux.oracle.com/cve/CVE-2024-33602.html",
            "https://linux.oracle.com/errata/ELSA-2024-3588.html",
            "https://lists.debian.org/debian-lts-announce/2024/06/msg00026.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-33602",
            "https://security.netapp.com/advisory/ntap-20240524-0012/",
            "https://sourceware.org/bugzilla/show_bug.cgi?id=31680",
            "https://sourceware.org/git/?p=glibc.git;a=blob;f=advisories/GLIBC-SA-2024-0008",
            "https://ubuntu.com/security/notices/USN-6804-1",
            "https://www.cve.org/CVERecord?id=CVE-2024-33602",
            "https://www.openwall.com/lists/oss-security/2024/04/24/2"
          ],
          "PublishedDate": "2024-05-06T20:15:11.68Z",
          "LastModifiedDate": "2024-07-22T18:15:03.583Z"
        },
        {
          "VulnerabilityID": "CVE-2010-4756",
          "PkgID": "libc6@2.28-10+deb10u2",
          "PkgName": "libc6",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libc6@2.28-10%2Bdeb10u2?arch=amd64\u0026distro=debian-10.13",
            "UID": "5a3be8cddcee1bcf"
          },
          "InstalledVersion": "2.28-10+deb10u2",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2010-4756",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "glibc: glob implementation can cause excessive CPU and memory consumption due to crafted glob expressions",
          "Description": "The glob implementation in the GNU C Library (aka glibc or libc6) allows remote authenticated users to cause a denial of service (CPU and memory consumption) via crafted glob expressions that do not match any pathnames, as demonstrated by glob expressions in STAT commands to an FTP daemon, a different vulnerability than CVE-2010-2632.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-399"
          ],
          "VendorSeverity": {
            "debian": 1,
            "nvd": 2,
            "redhat": 1
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:S/C:N/I:N/A:P",
              "V2Score": 4
            },
            "redhat": {
              "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
              "V2Score": 5
            }
          },
          "References": [
            "http://cxib.net/stuff/glob-0day.c",
            "http://securityreason.com/achievement_securityalert/89",
            "http://securityreason.com/exploitalert/9223",
            "https://access.redhat.com/security/cve/CVE-2010-4756",
            "https://bugzilla.redhat.com/show_bug.cgi?id=681681",
            "https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2010-4756",
            "https://nvd.nist.gov/vuln/detail/CVE-2010-4756",
            "https://www.cve.org/CVERecord?id=CVE-2010-4756"
          ],
          "PublishedDate": "2011-03-02T20:00:01.037Z",
          "LastModifiedDate": "2021-09-01T12:15:07.193Z"
        },
        {
          "VulnerabilityID": "CVE-2018-20796",
          "PkgID": "libc6@2.28-10+deb10u2",
          "PkgName": "libc6",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libc6@2.28-10%2Bdeb10u2?arch=amd64\u0026distro=debian-10.13",
            "UID": "5a3be8cddcee1bcf"
          },
          "InstalledVersion": "2.28-10+deb10u2",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2018-20796",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "glibc: uncontrolled recursion in function check_dst_limits_calc_pos_1 in posix/regexec.c",
          "Description": "In the GNU C Library (aka glibc or libc6) through 2.29, check_dst_limits_calc_pos_1 in posix/regexec.c has Uncontrolled Recursion, as demonstrated by '(\\227|)(\\\\1\\\\1|t1|\\\\\\2537)+' in grep.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-674"
          ],
          "VendorSeverity": {
            "cbl-mariner": 3,
            "debian": 1,
            "nvd": 3,
            "redhat": 2
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
              "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V2Score": 5,
              "V3Score": 7.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
              "V3Score": 5.3
            }
          },
          "References": [
            "http://www.securityfocus.com/bid/107160",
            "https://access.redhat.com/security/cve/CVE-2018-20796",
            "https://debbugs.gnu.org/cgi/bugreport.cgi?bug=34141",
            "https://lists.gnu.org/archive/html/bug-gnulib/2019-01/msg00108.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2018-20796",
            "https://security.netapp.com/advisory/ntap-20190315-0002/",
            "https://support.f5.com/csp/article/K26346590?utm_source=f5support\u0026amp%3Butm_medium=RSS",
            "https://www.cve.org/CVERecord?id=CVE-2018-20796"
          ],
          "PublishedDate": "2019-02-26T02:29:00.45Z",
          "LastModifiedDate": "2023-11-07T02:56:20.983Z"
        },
        {
          "VulnerabilityID": "CVE-2019-1010022",
          "PkgID": "libc6@2.28-10+deb10u2",
          "PkgName": "libc6",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libc6@2.28-10%2Bdeb10u2?arch=amd64\u0026distro=debian-10.13",
            "UID": "5a3be8cddcee1bcf"
          },
          "InstalledVersion": "2.28-10+deb10u2",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2019-1010022",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "glibc: stack guard protection bypass",
          "Description": "GNU Libc current is affected by: Mitigation bypass. The impact is: Attacker may bypass stack guard protection. The component is: nptl. The attack vector is: Exploit stack buffer overflow vulnerability and use this bypass vulnerability to bypass stack guard. NOTE: Upstream comments indicate \"this is being treated as a non-security bug and no real threat.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-119"
          ],
          "VendorSeverity": {
            "debian": 1,
            "nvd": 4
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
              "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
              "V2Score": 7.5,
              "V3Score": 9.8
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2019-1010022",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-1010022",
            "https://security-tracker.debian.org/tracker/CVE-2019-1010022",
            "https://sourceware.org/bugzilla/show_bug.cgi?id=22850",
            "https://sourceware.org/bugzilla/show_bug.cgi?id=22850#c3",
            "https://ubuntu.com/security/CVE-2019-1010022",
            "https://www.cve.org/CVERecord?id=CVE-2019-1010022"
          ],
          "PublishedDate": "2019-07-15T04:15:13.317Z",
          "LastModifiedDate": "2024-08-05T03:15:25.083Z"
        },
        {
          "VulnerabilityID": "CVE-2019-1010023",
          "PkgID": "libc6@2.28-10+deb10u2",
          "PkgName": "libc6",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libc6@2.28-10%2Bdeb10u2?arch=amd64\u0026distro=debian-10.13",
            "UID": "5a3be8cddcee1bcf"
          },
          "InstalledVersion": "2.28-10+deb10u2",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2019-1010023",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "glibc: running ldd on malicious ELF leads to code execution because of wrong size computation",
          "Description": "GNU Libc current is affected by: Re-mapping current loaded library with malicious ELF file. The impact is: In worst case attacker may evaluate privileges. The component is: libld. The attack vector is: Attacker sends 2 ELF files to victim and asks to run ldd on it. ldd execute code. NOTE: Upstream comments indicate \"this is being treated as a non-security bug and no real threat.",
          "Severity": "LOW",
          "VendorSeverity": {
            "debian": 1,
            "nvd": 3,
            "redhat": 1
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
              "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
              "V2Score": 6.8,
              "V3Score": 8.8
            },
            "redhat": {
              "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
              "V3Score": 7.8
            }
          },
          "References": [
            "http://www.securityfocus.com/bid/109167",
            "https://access.redhat.com/security/cve/CVE-2019-1010023",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-1010023",
            "https://security-tracker.debian.org/tracker/CVE-2019-1010023",
            "https://sourceware.org/bugzilla/show_bug.cgi?id=22851",
            "https://support.f5.com/csp/article/K11932200?utm_source=f5support\u0026amp%3Butm_medium=RSS",
            "https://ubuntu.com/security/CVE-2019-1010023",
            "https://www.cve.org/CVERecord?id=CVE-2019-1010023"
          ],
          "PublishedDate": "2019-07-15T04:15:13.397Z",
          "LastModifiedDate": "2024-08-05T03:15:25.183Z"
        },
        {
          "VulnerabilityID": "CVE-2019-1010024",
          "PkgID": "libc6@2.28-10+deb10u2",
          "PkgName": "libc6",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libc6@2.28-10%2Bdeb10u2?arch=amd64\u0026distro=debian-10.13",
            "UID": "5a3be8cddcee1bcf"
          },
          "InstalledVersion": "2.28-10+deb10u2",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2019-1010024",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "glibc: ASLR bypass using cache of thread stack and heap",
          "Description": "GNU Libc current is affected by: Mitigation bypass. The impact is: Attacker may bypass ASLR using cache of thread stack and heap. The component is: glibc. NOTE: Upstream comments indicate \"this is being treated as a non-security bug and no real threat.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-200"
          ],
          "VendorSeverity": {
            "debian": 1,
            "nvd": 2,
            "redhat": 2
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:P/I:N/A:N",
              "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
              "V2Score": 5,
              "V3Score": 5.3
            },
            "redhat": {
              "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
              "V3Score": 5.3
            }
          },
          "References": [
            "http://www.securityfocus.com/bid/109162",
            "https://access.redhat.com/security/cve/CVE-2019-1010024",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-1010024",
            "https://security-tracker.debian.org/tracker/CVE-2019-1010024",
            "https://sourceware.org/bugzilla/show_bug.cgi?id=22852",
            "https://support.f5.com/csp/article/K06046097",
            "https://support.f5.com/csp/article/K06046097?utm_source=f5support\u0026amp%3Butm_medium=RSS",
            "https://ubuntu.com/security/CVE-2019-1010024",
            "https://www.cve.org/CVERecord?id=CVE-2019-1010024"
          ],
          "PublishedDate": "2019-07-15T04:15:13.473Z",
          "LastModifiedDate": "2024-08-05T03:15:25.26Z"
        },
        {
          "VulnerabilityID": "CVE-2019-1010025",
          "PkgID": "libc6@2.28-10+deb10u2",
          "PkgName": "libc6",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libc6@2.28-10%2Bdeb10u2?arch=amd64\u0026distro=debian-10.13",
            "UID": "5a3be8cddcee1bcf"
          },
          "InstalledVersion": "2.28-10+deb10u2",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2019-1010025",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "glibc: information disclosure of heap addresses of pthread_created thread",
          "Description": "GNU Libc current is affected by: Mitigation bypass. The impact is: Attacker may guess the heap addresses of pthread_created thread. The component is: glibc. NOTE: the vendor's position is \"ASLR bypass itself is not a vulnerability.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-330"
          ],
          "VendorSeverity": {
            "debian": 1,
            "nvd": 2,
            "redhat": 1
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:P/I:N/A:N",
              "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
              "V2Score": 5,
              "V3Score": 5.3
            },
            "redhat": {
              "V3Vector": "CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
              "V3Score": 2.9
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2019-1010025",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-1010025",
            "https://security-tracker.debian.org/tracker/CVE-2019-1010025",
            "https://sourceware.org/bugzilla/show_bug.cgi?id=22853",
            "https://support.f5.com/csp/article/K06046097",
            "https://support.f5.com/csp/article/K06046097?utm_source=f5support\u0026amp%3Butm_medium=RSS",
            "https://ubuntu.com/security/CVE-2019-1010025",
            "https://www.cve.org/CVERecord?id=CVE-2019-1010025"
          ],
          "PublishedDate": "2019-07-15T04:15:13.537Z",
          "LastModifiedDate": "2024-08-05T03:15:25.333Z"
        },
        {
          "VulnerabilityID": "CVE-2019-9192",
          "PkgID": "libc6@2.28-10+deb10u2",
          "PkgName": "libc6",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libc6@2.28-10%2Bdeb10u2?arch=amd64\u0026distro=debian-10.13",
            "UID": "5a3be8cddcee1bcf"
          },
          "InstalledVersion": "2.28-10+deb10u2",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2019-9192",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "glibc: uncontrolled recursion in function check_dst_limits_calc_pos_1 in posix/regexec.c",
          "Description": "In the GNU C Library (aka glibc or libc6) through 2.29, check_dst_limits_calc_pos_1 in posix/regexec.c has Uncontrolled Recursion, as demonstrated by '(|)(\\\\1\\\\1)*' in grep, a different issue than CVE-2018-20796. NOTE: the software maintainer disputes that this is a vulnerability because the behavior occurs only with a crafted pattern",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-674"
          ],
          "VendorSeverity": {
            "cbl-mariner": 3,
            "debian": 1,
            "nvd": 3,
            "redhat": 1
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
              "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V2Score": 5,
              "V3Score": 7.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:N/I:N/A:L",
              "V3Score": 2.8
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2019-9192",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-9192",
            "https://sourceware.org/bugzilla/show_bug.cgi?id=24269",
            "https://support.f5.com/csp/article/K26346590?utm_source=f5support\u0026amp%3Butm_medium=RSS",
            "https://www.cve.org/CVERecord?id=CVE-2019-9192"
          ],
          "PublishedDate": "2019-02-26T18:29:00.34Z",
          "LastModifiedDate": "2024-08-04T22:15:34.74Z"
        },
        {
          "VulnerabilityID": "CVE-2022-1304",
          "PkgID": "libcom-err2@1.44.5-1+deb10u3",
          "PkgName": "libcom-err2",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libcom-err2@1.44.5-1%2Bdeb10u3?arch=amd64\u0026distro=debian-10.13",
            "UID": "4e290d2a0aa14919"
          },
          "InstalledVersion": "1.44.5-1+deb10u3",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2022-1304",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "e2fsprogs: out-of-bounds read/write via crafted filesystem",
          "Description": "An out-of-bounds read/write vulnerability was found in e2fsprogs 1.46.5. This issue leads to a segmentation fault and possibly arbitrary code execution via a specially crafted filesystem.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-125",
            "CWE-787"
          ],
          "VendorSeverity": {
            "alma": 2,
            "amazon": 2,
            "cbl-mariner": 3,
            "nvd": 3,
            "oracle-oval": 2,
            "photon": 3,
            "redhat": 2,
            "rocky": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
              "V2Score": 6.8,
              "V3Score": 7.8
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:H",
              "V3Score": 5.8
            }
          },
          "References": [
            "https://access.redhat.com/errata/RHSA-2022:8361",
            "https://access.redhat.com/security/cve/CVE-2022-1304",
            "https://bugzilla.redhat.com/2069726",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2069726",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-1304",
            "https://errata.almalinux.org/9/ALSA-2022-8361.html",
            "https://errata.rockylinux.org/RLSA-2022:8361",
            "https://linux.oracle.com/cve/CVE-2022-1304.html",
            "https://linux.oracle.com/errata/ELSA-2022-8361.html",
            "https://marc.info/?l=linux-ext4\u0026m=165056234501732\u0026w=2",
            "https://nvd.nist.gov/vuln/detail/CVE-2022-1304",
            "https://ubuntu.com/security/notices/USN-5464-1",
            "https://www.cve.org/CVERecord?id=CVE-2022-1304"
          ],
          "PublishedDate": "2022-04-14T21:15:08.49Z",
          "LastModifiedDate": "2023-11-07T03:41:53.02Z"
        },
        {
          "VulnerabilityID": "CVE-2019-8457",
          "PkgID": "libdb5.3@5.3.28+dfsg1-0.5",
          "PkgName": "libdb5.3",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libdb5.3@5.3.28%2Bdfsg1-0.5?arch=amd64\u0026distro=debian-10.13",
            "UID": "e3f919ad67723b46"
          },
          "InstalledVersion": "5.3.28+dfsg1-0.5",
          "Status": "will_not_fix",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2019-8457",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "sqlite: heap out-of-bound read in function rtreenode()",
          "Description": "SQLite3 from 3.6.0 to and including 3.27.2 is vulnerable to heap out-of-bound read in the rtreenode() function when handling invalid rtree tables.",
          "Severity": "CRITICAL",
          "CweIDs": [
            "CWE-125"
          ],
          "VendorSeverity": {
            "azure": 4,
            "nvd": 4,
            "oracle-oval": 2,
            "photon": 4,
            "redhat": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
              "V2Score": 7.5,
              "V3Score": 9.8
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 7.5
            }
          },
          "References": [
            "http://lists.opensuse.org/opensuse-security-announce/2019-06/msg00074.html",
            "https://access.redhat.com/security/cve/CVE-2019-8457",
            "https://kc.mcafee.com/corporate/index?page=content\u0026id=SB10365",
            "https://linux.oracle.com/cve/CVE-2019-8457.html",
            "https://linux.oracle.com/errata/ELSA-2020-1810.html",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/OPKYSWCOM3CL66RI76TYVIG6TJ263RXH/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/SJPFGA45DI4F5MCF2OAACGH3HQOF4G3M/",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-8457",
            "https://security.netapp.com/advisory/ntap-20190606-0002/",
            "https://ubuntu.com/security/notices/USN-4004-1",
            "https://ubuntu.com/security/notices/USN-4004-2",
            "https://ubuntu.com/security/notices/USN-4019-1",
            "https://ubuntu.com/security/notices/USN-4019-2",
            "https://usn.ubuntu.com/4004-1/",
            "https://usn.ubuntu.com/4004-2/",
            "https://usn.ubuntu.com/4019-1/",
            "https://usn.ubuntu.com/4019-2/",
            "https://www.cve.org/CVERecord?id=CVE-2019-8457",
            "https://www.oracle.com/security-alerts/cpuapr2020.html",
            "https://www.oracle.com/security-alerts/cpujan2020.html",
            "https://www.oracle.com/security-alerts/cpujul2020.html",
            "https://www.oracle.com/technetwork/security-advisory/cpuoct2019-5072832.html",
            "https://www.sqlite.org/releaselog/3_28_0.html",
            "https://www.sqlite.org/src/info/90acdbfce9c08858"
          ],
          "PublishedDate": "2019-05-30T16:29:01.84Z",
          "LastModifiedDate": "2023-11-07T03:13:30.25Z"
        },
        {
          "VulnerabilityID": "CVE-2024-45490",
          "PkgID": "libexpat1@2.2.6-2+deb10u6",
          "PkgName": "libexpat1",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libexpat1@2.2.6-2%2Bdeb10u6?arch=amd64\u0026distro=debian-10.13",
            "UID": "b5687b93fbdf5617"
          },
          "InstalledVersion": "2.2.6-2+deb10u6",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8f777578c172d018077d3dc22d6654911fff60066097943fe8c4697ecf8aac35",
            "DiffID": "sha256:3054512b6f71055cacea93ed12462e1ddc7f54988d9c7b51d10a5144d99ff501"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-45490",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
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
          "PkgID": "libexpat1@2.2.6-2+deb10u6",
          "PkgName": "libexpat1",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libexpat1@2.2.6-2%2Bdeb10u6?arch=amd64\u0026distro=debian-10.13",
            "UID": "b5687b93fbdf5617"
          },
          "InstalledVersion": "2.2.6-2+deb10u6",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8f777578c172d018077d3dc22d6654911fff60066097943fe8c4697ecf8aac35",
            "DiffID": "sha256:3054512b6f71055cacea93ed12462e1ddc7f54988d9c7b51d10a5144d99ff501"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-45491",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
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
          "PkgID": "libexpat1@2.2.6-2+deb10u6",
          "PkgName": "libexpat1",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libexpat1@2.2.6-2%2Bdeb10u6?arch=amd64\u0026distro=debian-10.13",
            "UID": "b5687b93fbdf5617"
          },
          "InstalledVersion": "2.2.6-2+deb10u6",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8f777578c172d018077d3dc22d6654911fff60066097943fe8c4697ecf8aac35",
            "DiffID": "sha256:3054512b6f71055cacea93ed12462e1ddc7f54988d9c7b51d10a5144d99ff501"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-45492",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
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
          "VulnerabilityID": "CVE-2023-52425",
          "VendorIDs": [
            "DLA-3783-1"
          ],
          "PkgID": "libexpat1@2.2.6-2+deb10u6",
          "PkgName": "libexpat1",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libexpat1@2.2.6-2%2Bdeb10u6?arch=amd64\u0026distro=debian-10.13",
            "UID": "b5687b93fbdf5617"
          },
          "InstalledVersion": "2.2.6-2+deb10u6",
          "FixedVersion": "2.2.6-2+deb10u7",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:8f777578c172d018077d3dc22d6654911fff60066097943fe8c4697ecf8aac35",
            "DiffID": "sha256:3054512b6f71055cacea93ed12462e1ddc7f54988d9c7b51d10a5144d99ff501"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-52425",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "expat: parsing large tokens can trigger a denial of service",
          "Description": "libexpat through 2.5.0 allows a denial of service (resource consumption) because many full reparsings are required in the case of a large token for which multiple buffer fills are needed.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-400"
          ],
          "VendorSeverity": {
            "alma": 2,
            "azure": 3,
            "cbl-mariner": 3,
            "nvd": 3,
            "oracle-oval": 2,
            "photon": 3,
            "redhat": 2,
            "rocky": 2,
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
            "http://www.openwall.com/lists/oss-security/2024/03/20/5",
            "https://access.redhat.com/errata/RHSA-2024:1530",
            "https://access.redhat.com/security/cve/CVE-2023-52425",
            "https://bugzilla.redhat.com/2262877",
            "https://bugzilla.redhat.com/2268766",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2262877",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-52425",
            "https://errata.almalinux.org/9/ALSA-2024-1530.html",
            "https://errata.rockylinux.org/RLSA-2024:1615",
            "https://github.com/libexpat/libexpat/pull/789",
            "https://linux.oracle.com/cve/CVE-2023-52425.html",
            "https://linux.oracle.com/errata/ELSA-2024-4259.html",
            "https://lists.debian.org/debian-lts-announce/2024/04/msg00006.html",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/PNRIHC7DVVRAIWFRGV23Y6UZXFBXSQDB/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/WNUBSGZFEZOBHJFTAD42SAN4ATW2VEMV/",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-52425",
            "https://security.netapp.com/advisory/ntap-20240614-0003/",
            "https://ubuntu.com/security/notices/USN-6694-1",
            "https://www.cve.org/CVERecord?id=CVE-2023-52425"
          ],
          "PublishedDate": "2024-02-04T20:15:46.063Z",
          "LastModifiedDate": "2024-08-26T20:35:10.427Z"
        },
        {
          "VulnerabilityID": "CVE-2013-0340",
          "PkgID": "libexpat1@2.2.6-2+deb10u6",
          "PkgName": "libexpat1",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libexpat1@2.2.6-2%2Bdeb10u6?arch=amd64\u0026distro=debian-10.13",
            "UID": "b5687b93fbdf5617"
          },
          "InstalledVersion": "2.2.6-2+deb10u6",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8f777578c172d018077d3dc22d6654911fff60066097943fe8c4697ecf8aac35",
            "DiffID": "sha256:3054512b6f71055cacea93ed12462e1ddc7f54988d9c7b51d10a5144d99ff501"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2013-0340",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "expat: internal entity expansion",
          "Description": "expat 2.1.0 and earlier does not properly handle entities expansion unless an application developer uses the XML_SetEntityDeclHandler function, which allows remote attackers to cause a denial of service (resource consumption), send HTTP requests to intranet servers, or read arbitrary files via a crafted XML document, aka an XML External Entity (XXE) issue.  NOTE: it could be argued that because expat already provides the ability to disable external entity expansion, the responsibility for resolving this issue lies with application developers; according to this argument, this entry should be REJECTed, and each affected application would need its own CVE.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-611"
          ],
          "VendorSeverity": {
            "cbl-mariner": 2,
            "debian": 1,
            "nvd": 2,
            "redhat": 2
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
              "V2Score": 6.8
            },
            "redhat": {
              "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:P",
              "V2Score": 4.3
            }
          },
          "References": [
            "http://openwall.com/lists/oss-security/2013/02/22/3",
            "http://seclists.org/fulldisclosure/2021/Oct/61",
            "http://seclists.org/fulldisclosure/2021/Oct/62",
            "http://seclists.org/fulldisclosure/2021/Oct/63",
            "http://seclists.org/fulldisclosure/2021/Sep/33",
            "http://seclists.org/fulldisclosure/2021/Sep/34",
            "http://seclists.org/fulldisclosure/2021/Sep/35",
            "http://seclists.org/fulldisclosure/2021/Sep/38",
            "http://seclists.org/fulldisclosure/2021/Sep/39",
            "http://seclists.org/fulldisclosure/2021/Sep/40",
            "http://securitytracker.com/id?1028213",
            "http://www.openwall.com/lists/oss-security/2013/04/12/6",
            "http://www.openwall.com/lists/oss-security/2021/10/07/4",
            "http://www.osvdb.org/90634",
            "http://www.securityfocus.com/bid/58233",
            "https://access.redhat.com/security/cve/CVE-2013-0340",
            "https://lists.apache.org/thread.html/r41eca5f4f09e74436cbb05dec450fc2bef37b5d3e966aa7cc5fada6d%40%3Cannounce.apache.org%3E",
            "https://lists.apache.org/thread.html/rfb2c193360436e230b85547e85a41bea0916916f96c501f5b6fc4702%40%3Cusers.openoffice.apache.org%3E",
            "https://nvd.nist.gov/vuln/detail/CVE-2013-0340",
            "https://security.gentoo.org/glsa/201701-21",
            "https://support.apple.com/kb/HT212804",
            "https://support.apple.com/kb/HT212805",
            "https://support.apple.com/kb/HT212807",
            "https://support.apple.com/kb/HT212814",
            "https://support.apple.com/kb/HT212815",
            "https://support.apple.com/kb/HT212819",
            "https://www.cve.org/CVERecord?id=CVE-2013-0340"
          ],
          "PublishedDate": "2014-01-21T18:55:09.117Z",
          "LastModifiedDate": "2023-11-07T02:13:49.033Z"
        },
        {
          "VulnerabilityID": "CVE-2023-52426",
          "PkgID": "libexpat1@2.2.6-2+deb10u6",
          "PkgName": "libexpat1",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libexpat1@2.2.6-2%2Bdeb10u6?arch=amd64\u0026distro=debian-10.13",
            "UID": "b5687b93fbdf5617"
          },
          "InstalledVersion": "2.2.6-2+deb10u6",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8f777578c172d018077d3dc22d6654911fff60066097943fe8c4697ecf8aac35",
            "DiffID": "sha256:3054512b6f71055cacea93ed12462e1ddc7f54988d9c7b51d10a5144d99ff501"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-52426",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "expat: recursive XML entity expansion vulnerability",
          "Description": "libexpat through 2.5.0 allows recursive XML Entity Expansion if XML_DTD is undefined at compile time.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-776"
          ],
          "VendorSeverity": {
            "amazon": 2,
            "azure": 2,
            "cbl-mariner": 2,
            "debian": 1,
            "nvd": 2,
            "photon": 2,
            "redhat": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 5.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 5.5
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2023-52426",
            "https://cwe.mitre.org/data/definitions/776.html",
            "https://github.com/libexpat/libexpat/commit/0f075ec8ecb5e43f8fdca5182f8cca4703da0404",
            "https://github.com/libexpat/libexpat/pull/777",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/PNRIHC7DVVRAIWFRGV23Y6UZXFBXSQDB/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/WNUBSGZFEZOBHJFTAD42SAN4ATW2VEMV/",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-52426",
            "https://security.netapp.com/advisory/ntap-20240307-0005/",
            "https://www.cve.org/CVERecord?id=CVE-2023-52426"
          ],
          "PublishedDate": "2024-02-04T20:15:46.12Z",
          "LastModifiedDate": "2024-03-07T17:15:11.893Z"
        },
        {
          "VulnerabilityID": "CVE-2024-28757",
          "PkgID": "libexpat1@2.2.6-2+deb10u6",
          "PkgName": "libexpat1",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libexpat1@2.2.6-2%2Bdeb10u6?arch=amd64\u0026distro=debian-10.13",
            "UID": "b5687b93fbdf5617"
          },
          "InstalledVersion": "2.2.6-2+deb10u6",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8f777578c172d018077d3dc22d6654911fff60066097943fe8c4697ecf8aac35",
            "DiffID": "sha256:3054512b6f71055cacea93ed12462e1ddc7f54988d9c7b51d10a5144d99ff501"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-28757",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "expat: XML Entity Expansion",
          "Description": "libexpat through 2.6.1 allows an XML Entity Expansion attack when there is isolated use of external parsers (created via XML_ExternalEntityParserCreate).",
          "Severity": "LOW",
          "VendorSeverity": {
            "alma": 2,
            "amazon": 3,
            "azure": 3,
            "cbl-mariner": 3,
            "debian": 1,
            "oracle-oval": 2,
            "photon": 3,
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
            "http://www.openwall.com/lists/oss-security/2024/03/15/1",
            "https://access.redhat.com/errata/RHSA-2024:1530",
            "https://access.redhat.com/security/cve/CVE-2024-28757",
            "https://bugzilla.redhat.com/2262877",
            "https://bugzilla.redhat.com/2268766",
            "https://errata.almalinux.org/9/ALSA-2024-1530.html",
            "https://github.com/libexpat/libexpat/issues/839",
            "https://github.com/libexpat/libexpat/pull/842",
            "https://linux.oracle.com/cve/CVE-2024-28757.html",
            "https://linux.oracle.com/errata/ELSA-2024-1530.html",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/FPLC6WDSRDUYS7F7JWAOVOHFNOUQ43DD/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/LKJ7V5F6LJCEQJXDBWGT27J7NAP3E3N7/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/VK2O34GH43NTHBZBN7G5Y6YKJKPUCTBE/",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-28757",
            "https://security.netapp.com/advisory/ntap-20240322-0001/",
            "https://ubuntu.com/security/notices/USN-6694-1",
            "https://www.cve.org/CVERecord?id=CVE-2024-28757"
          ],
          "PublishedDate": "2024-03-10T05:15:06.57Z",
          "LastModifiedDate": "2024-05-01T19:15:22.567Z"
        },
        {
          "VulnerabilityID": "CVE-2022-1304",
          "PkgID": "libext2fs2@1.44.5-1+deb10u3",
          "PkgName": "libext2fs2",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libext2fs2@1.44.5-1%2Bdeb10u3?arch=amd64\u0026distro=debian-10.13",
            "UID": "bc675dc2444ceeae"
          },
          "InstalledVersion": "1.44.5-1+deb10u3",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2022-1304",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "e2fsprogs: out-of-bounds read/write via crafted filesystem",
          "Description": "An out-of-bounds read/write vulnerability was found in e2fsprogs 1.46.5. This issue leads to a segmentation fault and possibly arbitrary code execution via a specially crafted filesystem.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-125",
            "CWE-787"
          ],
          "VendorSeverity": {
            "alma": 2,
            "amazon": 2,
            "cbl-mariner": 3,
            "nvd": 3,
            "oracle-oval": 2,
            "photon": 3,
            "redhat": 2,
            "rocky": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
              "V2Score": 6.8,
              "V3Score": 7.8
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:H",
              "V3Score": 5.8
            }
          },
          "References": [
            "https://access.redhat.com/errata/RHSA-2022:8361",
            "https://access.redhat.com/security/cve/CVE-2022-1304",
            "https://bugzilla.redhat.com/2069726",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2069726",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-1304",
            "https://errata.almalinux.org/9/ALSA-2022-8361.html",
            "https://errata.rockylinux.org/RLSA-2022:8361",
            "https://linux.oracle.com/cve/CVE-2022-1304.html",
            "https://linux.oracle.com/errata/ELSA-2022-8361.html",
            "https://marc.info/?l=linux-ext4\u0026m=165056234501732\u0026w=2",
            "https://nvd.nist.gov/vuln/detail/CVE-2022-1304",
            "https://ubuntu.com/security/notices/USN-5464-1",
            "https://www.cve.org/CVERecord?id=CVE-2022-1304"
          ],
          "PublishedDate": "2022-04-14T21:15:08.49Z",
          "LastModifiedDate": "2023-11-07T03:41:53.02Z"
        },
        {
          "VulnerabilityID": "CVE-2024-28085",
          "VendorIDs": [
            "DLA-3782-1"
          ],
          "PkgID": "libfdisk1@2.33.1-0.1",
          "PkgName": "libfdisk1",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libfdisk1@2.33.1-0.1?arch=amd64\u0026distro=debian-10.13",
            "UID": "f2a72fb16acbdc4d"
          },
          "InstalledVersion": "2.33.1-0.1",
          "FixedVersion": "2.33.1-0.1+deb10u1",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-28085",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "util-linux: CVE-2024-28085: wall: escape sequence injection",
          "Description": "wall in util-linux through 2.40, often installed with setgid tty permissions, allows escape sequences to be sent to other users' terminals through argv. (Specifically, escape sequences received from stdin are blocked, but escape sequences received from argv are not blocked.) There may be plausible scenarios where this leads to account takeover.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-150"
          ],
          "VendorSeverity": {
            "cbl-mariner": 4,
            "photon": 3,
            "redhat": 3,
            "ubuntu": 2
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N",
              "V3Score": 8.4
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2024/03/27/5",
            "http://www.openwall.com/lists/oss-security/2024/03/27/6",
            "http://www.openwall.com/lists/oss-security/2024/03/27/7",
            "http://www.openwall.com/lists/oss-security/2024/03/27/8",
            "http://www.openwall.com/lists/oss-security/2024/03/27/9",
            "http://www.openwall.com/lists/oss-security/2024/03/28/1",
            "http://www.openwall.com/lists/oss-security/2024/03/28/2",
            "http://www.openwall.com/lists/oss-security/2024/03/28/3",
            "https://access.redhat.com/security/cve/CVE-2024-28085",
            "https://github.com/skyler-ferrante/CVE-2024-28085",
            "https://github.com/util-linux/util-linux/security/advisories/GHSA-xv2h-c6ww-mrjq",
            "https://lists.debian.org/debian-lts-announce/2024/04/msg00005.html",
            "https://mirrors.edge.kernel.org/pub/linux/utils/util-linux/",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-28085",
            "https://people.rit.edu/sjf5462/6831711781/wall_2_27_2024.txt",
            "https://security.netapp.com/advisory/ntap-20240531-0003/",
            "https://ubuntu.com/security/notices/USN-6719-1",
            "https://ubuntu.com/security/notices/USN-6719-2",
            "https://www.cve.org/CVERecord?id=CVE-2024-28085",
            "https://www.openwall.com/lists/oss-security/2024/03/27/5"
          ],
          "PublishedDate": "2024-03-27T19:15:48.367Z",
          "LastModifiedDate": "2024-08-26T21:35:09.31Z"
        },
        {
          "VulnerabilityID": "CVE-2021-37600",
          "VendorIDs": [
            "DLA-3782-1"
          ],
          "PkgID": "libfdisk1@2.33.1-0.1",
          "PkgName": "libfdisk1",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libfdisk1@2.33.1-0.1?arch=amd64\u0026distro=debian-10.13",
            "UID": "f2a72fb16acbdc4d"
          },
          "InstalledVersion": "2.33.1-0.1",
          "FixedVersion": "2.33.1-0.1+deb10u1",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2021-37600",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "util-linux: integer overflow can lead to buffer overflow in get_sem_elements() in sys-utils/ipcutils.c",
          "Description": "An integer overflow in util-linux through 2.37.1 can potentially cause a buffer overflow if an attacker were able to use system resources in a way that leads to a large number in the /proc/sysvipc/sem file. NOTE: this is unexploitable in GNU C Library environments, and possibly in all realistic environments.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-190"
          ],
          "VendorSeverity": {
            "amazon": 1,
            "cbl-mariner": 2,
            "nvd": 2,
            "photon": 2,
            "redhat": 1,
            "ubuntu": 1
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:L/AC:H/Au:N/C:N/I:N/A:P",
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
              "V2Score": 1.2,
              "V3Score": 5.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:H",
              "V3Score": 4.7
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2021-37600",
            "https://github.com/karelzak/util-linux/commit/1c9143d0c1f979c3daf10e1c37b5b1e916c22a1c",
            "https://github.com/karelzak/util-linux/issues/1395",
            "https://lists.debian.org/debian-lts-announce/2024/04/msg00005.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-37600",
            "https://security.gentoo.org/glsa/202401-08",
            "https://security.netapp.com/advisory/ntap-20210902-0002/",
            "https://www.cve.org/CVERecord?id=CVE-2021-37600"
          ],
          "PublishedDate": "2021-07-30T14:15:18.737Z",
          "LastModifiedDate": "2024-08-04T02:15:24.44Z"
        },
        {
          "VulnerabilityID": "CVE-2022-0563",
          "PkgID": "libfdisk1@2.33.1-0.1",
          "PkgName": "libfdisk1",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libfdisk1@2.33.1-0.1?arch=amd64\u0026distro=debian-10.13",
            "UID": "f2a72fb16acbdc4d"
          },
          "InstalledVersion": "2.33.1-0.1",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2022-0563",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "util-linux: partial disclosure of arbitrary files in chfn and chsh when compiled with libreadline",
          "Description": "A flaw was found in the util-linux chfn and chsh utilities when compiled with Readline support. The Readline library uses an \"INPUTRC\" environment variable to get a path to the library config file. When the library cannot parse the specified file, it prints an error message containing data from the file. This flaw allows an unprivileged user to read root-owned files, potentially leading to privilege escalation. This flaw affects util-linux versions prior to 2.37.4.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-209"
          ],
          "VendorSeverity": {
            "amazon": 2,
            "cbl-mariner": 2,
            "debian": 1,
            "nvd": 2,
            "photon": 2,
            "redhat": 2
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:L/AC:M/Au:N/C:P/I:N/A:N",
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
              "V2Score": 1.9,
              "V3Score": 5.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
              "V3Score": 5.5
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2022-0563",
            "https://blog.trailofbits.com/2023/02/16/suid-logic-bug-linux-readline/",
            "https://lore.kernel.org/util-linux/20220214110609.msiwlm457ngoic6w%40ws.net.home/T/#u",
            "https://lore.kernel.org/util-linux/20220214110609.msiwlm457ngoic6w@ws.net.home/T/#u",
            "https://nvd.nist.gov/vuln/detail/CVE-2022-0563",
            "https://security.gentoo.org/glsa/202401-08",
            "https://security.netapp.com/advisory/ntap-20220331-0002/",
            "https://www.cve.org/CVERecord?id=CVE-2022-0563"
          ],
          "PublishedDate": "2022-02-21T19:15:08.393Z",
          "LastModifiedDate": "2024-01-07T09:15:08.713Z"
        },
        {
          "VulnerabilityID": "CVE-2018-12886",
          "PkgID": "libgcc1@1:8.3.0-6",
          "PkgName": "libgcc1",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libgcc1@8.3.0-6?arch=amd64\u0026distro=debian-10.13\u0026epoch=1",
            "UID": "f61ab691c2c81827"
          },
          "InstalledVersion": "1:8.3.0-6",
          "Status": "will_not_fix",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2018-12886",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "gcc: spilling of stack protection address in cfgexpand.c and function.c leads to stack-overflow protection bypass",
          "Description": "stack_protect_prologue in cfgexpand.c and stack_protect_epilogue in function.c in GNU Compiler Collection (GCC) 4.1 through 8 (under certain circumstances) generate instruction sequences when targeting ARM targets that spill the address of the stack protector guard, which allows an attacker to bypass the protection of -fstack-protector, -fstack-protector-all, -fstack-protector-strong, and -fstack-protector-explicit against stack overflow by controlling what the stack canary is compared against.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-209"
          ],
          "VendorSeverity": {
            "nvd": 3,
            "redhat": 2,
            "ubuntu": 1
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
              "V3Vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
              "V2Score": 6.8,
              "V3Score": 8.1
            },
            "redhat": {
              "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H",
              "V3Score": 6.8
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2018-12886",
            "https://gcc.gnu.org/git/?p=gcc.git;a=commit;h=89d7557202d25a393666ac4c0f7dbdab31e452a2",
            "https://gcc.gnu.org/viewcvs/gcc/trunk/gcc/config/arm/arm-protos.h?revision=266379\u0026view=markup",
            "https://nvd.nist.gov/vuln/detail/CVE-2018-12886",
            "https://www.cve.org/CVERecord?id=CVE-2018-12886",
            "https://www.gnu.org/software/gcc/gcc-8/changes.html"
          ],
          "PublishedDate": "2019-05-22T19:29:00.297Z",
          "LastModifiedDate": "2020-08-24T17:37:01.14Z"
        },
        {
          "VulnerabilityID": "CVE-2019-15847",
          "PkgID": "libgcc1@1:8.3.0-6",
          "PkgName": "libgcc1",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libgcc1@8.3.0-6?arch=amd64\u0026distro=debian-10.13\u0026epoch=1",
            "UID": "f61ab691c2c81827"
          },
          "InstalledVersion": "1:8.3.0-6",
          "Status": "will_not_fix",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2019-15847",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "gcc: POWER9 \"DARN\" RNG intrinsic produces repeated output",
          "Description": "The POWER9 backend in GNU Compiler Collection (GCC) before version 10 could optimize multiple calls of the __builtin_darn intrinsic into a single call, thus reducing the entropy of the random number generator. This occurred because a volatile operation was not specified. For example, within a single execution of a program, the output of every __builtin_darn() call may be the same.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-331"
          ],
          "VendorSeverity": {
            "cbl-mariner": 3,
            "nvd": 3,
            "oracle-oval": 2,
            "redhat": 2,
            "ubuntu": 1
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:P/I:N/A:N",
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
              "V2Score": 5,
              "V3Score": 7.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
              "V3Score": 7.5
            }
          },
          "References": [
            "http://lists.opensuse.org/opensuse-security-announce/2019-10/msg00056.html",
            "http://lists.opensuse.org/opensuse-security-announce/2019-10/msg00057.html",
            "http://lists.opensuse.org/opensuse-security-announce/2020-05/msg00058.html",
            "https://access.redhat.com/security/cve/CVE-2019-15847",
            "https://gcc.gnu.org/bugzilla/show_bug.cgi?id=91481",
            "https://gcc.gnu.org/git/?p=gcc.git;a=commit;h=457dac402027dd7e14543fbd59a75858422cf6c6",
            "https://gcc.gnu.org/git/?p=gcc.git;a=commit;h=e99bfdd2a8db732ea84cf0a6486707e5e821ad7e",
            "https://linux.oracle.com/cve/CVE-2019-15847.html",
            "https://linux.oracle.com/errata/ELSA-2020-1864.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-15847",
            "https://www.cve.org/CVERecord?id=CVE-2019-15847"
          ],
          "PublishedDate": "2019-09-02T23:15:10.837Z",
          "LastModifiedDate": "2020-09-17T13:38:06.51Z"
        },
        {
          "VulnerabilityID": "CVE-2023-4039",
          "PkgID": "libgcc1@1:8.3.0-6",
          "PkgName": "libgcc1",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libgcc1@8.3.0-6?arch=amd64\u0026distro=debian-10.13\u0026epoch=1",
            "UID": "f61ab691c2c81827"
          },
          "InstalledVersion": "1:8.3.0-6",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-4039",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "gcc: -fstack-protector fails to guard dynamic stack allocations on ARM64",
          "Description": "\n\n**DISPUTED**A failure in the -fstack-protector feature in GCC-based toolchains \nthat target AArch64 allows an attacker to exploit an existing buffer \noverflow in dynamically-sized local variables in your application \nwithout this being detected. This stack-protector failure only applies \nto C99-style dynamically-sized local variables or those created using \nalloca(). The stack-protector operates as intended for statically-sized \nlocal variables.\n\nThe default behavior when the stack-protector \ndetects an overflow is to terminate your application, resulting in \ncontrolled loss of availability. An attacker who can exploit a buffer \noverflow without triggering the stack-protector might be able to change \nprogram flow control to cause an uncontrolled loss of availability or to\n go further and affect confidentiality or integrity. NOTE: The GCC project argues that this is a missed hardening bug and not a vulnerability by itself.\n\n\n\n\n\n",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-693"
          ],
          "VendorSeverity": {
            "amazon": 2,
            "azure": 2,
            "cbl-mariner": 2,
            "nvd": 2,
            "oracle-oval": 1,
            "ubuntu": 2
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
              "V3Score": 4.8
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2023-4039",
            "https://developer.arm.com/Arm%20Security%20Center/GCC%20Stack%20Protector%20Vulnerability%20AArch64",
            "https://gcc.gnu.org/git/?p=gcc.git;a=blob_plain;f=SECURITY.txt",
            "https://gcc.gnu.org/pipermail/gcc-patches/2023-October/634066.html",
            "https://github.com/metaredteam/external-disclosures/security/advisories/GHSA-x7ch-h5rf-w2mf",
            "https://inbox.sourceware.org/gcc-patches/46cfa37b-56eb-344d-0745-e0d35393392d@gotplt.org",
            "https://linux.oracle.com/cve/CVE-2023-4039.html",
            "https://linux.oracle.com/errata/ELSA-2023-28766.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-4039",
            "https://rtx.meta.security/mitigation/2023/09/12/CVE-2023-4039.html",
            "https://www.cve.org/CVERecord?id=CVE-2023-4039"
          ],
          "PublishedDate": "2023-09-13T09:15:15.69Z",
          "LastModifiedDate": "2024-08-02T08:15:14.993Z"
        },
        {
          "VulnerabilityID": "CVE-2021-33560",
          "PkgID": "libgcrypt20@1.8.4-5+deb10u1",
          "PkgName": "libgcrypt20",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libgcrypt20@1.8.4-5%2Bdeb10u1?arch=amd64\u0026distro=debian-10.13",
            "UID": "a4770d149e7c7cec"
          },
          "InstalledVersion": "1.8.4-5+deb10u1",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2021-33560",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "libgcrypt: mishandles ElGamal encryption because it lacks exponent blinding to address a side-channel attack against mpi_powm",
          "Description": "Libgcrypt before 1.8.8 and 1.9.x before 1.9.3 mishandles ElGamal encryption because it lacks exponent blinding to address a side-channel attack against mpi_powm, and the window size is not chosen appropriately. This, for example, affects use of ElGamal in OpenPGP.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-203"
          ],
          "VendorSeverity": {
            "alma": 2,
            "amazon": 2,
            "cbl-mariner": 3,
            "nvd": 3,
            "oracle-oval": 2,
            "photon": 3,
            "redhat": 2,
            "ubuntu": 1
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:P/I:N/A:N",
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
              "V2Score": 5,
              "V3Score": 7.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
              "V3Score": 7.5
            }
          },
          "References": [
            "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-33560.json",
            "https://access.redhat.com/security/cve/CVE-2021-33560",
            "https://dev.gnupg.org/T5305",
            "https://dev.gnupg.org/T5328",
            "https://dev.gnupg.org/T5466",
            "https://dev.gnupg.org/rCe8b7f10be275bcedb5fc05ed4837a89bfd605c61",
            "https://eprint.iacr.org/2021/923",
            "https://errata.almalinux.org/8/ALSA-2021-4409.html",
            "https://linux.oracle.com/cve/CVE-2021-33560.html",
            "https://linux.oracle.com/errata/ELSA-2022-9263.html",
            "https://lists.debian.org/debian-lts-announce/2021/06/msg00021.html",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/BKKTOIGFW2SGN3DO2UHHVZ7MJSYN4AAB/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/R7OAPCUGPF3VLA7QAJUQSL255D4ITVTL/",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-33560",
            "https://security.gentoo.org/glsa/202210-13",
            "https://ubuntu.com/security/notices/USN-5080-1",
            "https://ubuntu.com/security/notices/USN-5080-2",
            "https://www.cve.org/CVERecord?id=CVE-2021-33560",
            "https://www.oracle.com/security-alerts/cpuapr2022.html",
            "https://www.oracle.com/security-alerts/cpujan2022.html",
            "https://www.oracle.com/security-alerts/cpujul2022.html",
            "https://www.oracle.com/security-alerts/cpuoct2021.html"
          ],
          "PublishedDate": "2021-06-08T11:15:07.767Z",
          "LastModifiedDate": "2023-11-07T03:35:52.62Z"
        },
        {
          "VulnerabilityID": "CVE-2019-13627",
          "PkgID": "libgcrypt20@1.8.4-5+deb10u1",
          "PkgName": "libgcrypt20",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libgcrypt20@1.8.4-5%2Bdeb10u1?arch=amd64\u0026distro=debian-10.13",
            "UID": "a4770d149e7c7cec"
          },
          "InstalledVersion": "1.8.4-5+deb10u1",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2019-13627",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "libgcrypt: ECDSA timing attack allowing private key leak",
          "Description": "It was discovered that there was a ECDSA timing attack in the libgcrypt20 cryptographic library. Version affected: 1.8.4-5, 1.7.6-2+deb9u3, and 1.6.3-2+deb8u4. Versions fixed: 1.8.5-2 and 1.6.3-2+deb8u7.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-203"
          ],
          "VendorSeverity": {
            "nvd": 2,
            "oracle-oval": 2,
            "redhat": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:L/AC:H/Au:N/C:P/I:P/A:N",
              "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N",
              "V2Score": 2.6,
              "V3Score": 6.3
            },
            "redhat": {
              "V3Vector": "CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N",
              "V3Score": 6.3
            }
          },
          "References": [
            "http://lists.opensuse.org/opensuse-security-announce/2019-09/msg00060.html",
            "http://lists.opensuse.org/opensuse-security-announce/2020-01/msg00018.html",
            "http://www.openwall.com/lists/oss-security/2019/10/02/2",
            "https://access.redhat.com/security/cve/CVE-2019-13627",
            "https://dev.gnupg.org/T4683",
            "https://github.com/gpg/libgcrypt/releases/tag/libgcrypt-1.8.5",
            "https://linux.oracle.com/cve/CVE-2019-13627.html",
            "https://linux.oracle.com/errata/ELSA-2020-4482.html",
            "https://lists.debian.org/debian-lts-announce/2019/09/msg00024.html",
            "https://lists.debian.org/debian-lts-announce/2020/01/msg00001.html",
            "https://minerva.crocs.fi.muni.cz/",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-13627",
            "https://security-tracker.debian.org/tracker/CVE-2019-13627",
            "https://security.gentoo.org/glsa/202003-32",
            "https://ubuntu.com/security/notices/USN-4236-1",
            "https://ubuntu.com/security/notices/USN-4236-2",
            "https://ubuntu.com/security/notices/USN-4236-3",
            "https://usn.ubuntu.com/4236-1/",
            "https://usn.ubuntu.com/4236-2/",
            "https://usn.ubuntu.com/4236-3/",
            "https://www.cve.org/CVERecord?id=CVE-2019-13627"
          ],
          "PublishedDate": "2019-09-25T15:15:11.877Z",
          "LastModifiedDate": "2021-07-21T11:39:23.747Z"
        },
        {
          "VulnerabilityID": "CVE-2024-2236",
          "PkgID": "libgcrypt20@1.8.4-5+deb10u1",
          "PkgName": "libgcrypt20",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libgcrypt20@1.8.4-5%2Bdeb10u1?arch=amd64\u0026distro=debian-10.13",
            "UID": "a4770d149e7c7cec"
          },
          "InstalledVersion": "1.8.4-5+deb10u1",
          "Status": "fix_deferred",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-2236",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "libgcrypt: vulnerable to Marvin Attack",
          "Description": "A timing-based side-channel flaw was found in libgcrypt's RSA implementation. This issue may allow a remote attacker to initiate a Bleichenbacher-style attack, which can lead to the decryption of RSA ciphertexts.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-208"
          ],
          "VendorSeverity": {
            "redhat": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
              "V3Score": 5.9
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2024-2236",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2245218",
            "https://dev.gnupg.org/T7136",
            "https://github.com/tomato42/marvin-toolkit/tree/master/example/libgcrypt",
            "https://gitlab.com/redhat-crypto/libgcrypt/libgcrypt-mirror/-/merge_requests/17",
            "https://lists.gnupg.org/pipermail/gcrypt-devel/2024-March/005607.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-2236",
            "https://www.cve.org/CVERecord?id=CVE-2024-2236"
          ],
          "PublishedDate": "2024-03-06T22:15:57.977Z",
          "LastModifiedDate": "2024-09-14T04:15:02.903Z"
        },
        {
          "VulnerabilityID": "CVE-2018-6829",
          "PkgID": "libgcrypt20@1.8.4-5+deb10u1",
          "PkgName": "libgcrypt20",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libgcrypt20@1.8.4-5%2Bdeb10u1?arch=amd64\u0026distro=debian-10.13",
            "UID": "a4770d149e7c7cec"
          },
          "InstalledVersion": "1.8.4-5+deb10u1",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2018-6829",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "libgcrypt: ElGamal implementation doesn't have semantic security due to incorrectly encoded plaintexts possibly allowing to obtain sensitive information",
          "Description": "cipher/elgamal.c in Libgcrypt through 1.8.2, when used to encrypt messages directly, improperly encodes plaintexts, which allows attackers to obtain sensitive information by reading ciphertext data (i.e., it does not have semantic security in face of a ciphertext-only attack). The Decisional Diffie-Hellman (DDH) assumption does not hold for Libgcrypt's ElGamal implementation.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-327"
          ],
          "VendorSeverity": {
            "debian": 1,
            "nvd": 3,
            "redhat": 2
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:P/I:N/A:N",
              "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
              "V2Score": 5,
              "V3Score": 7.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
              "V3Score": 5.3
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2018-6829",
            "https://github.com/weikengchen/attack-on-libgcrypt-elgamal",
            "https://github.com/weikengchen/attack-on-libgcrypt-elgamal/wiki",
            "https://lists.gnupg.org/pipermail/gcrypt-devel/2018-February/004394.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2018-6829",
            "https://www.cve.org/CVERecord?id=CVE-2018-6829",
            "https://www.oracle.com/security-alerts/cpujan2020.html"
          ],
          "PublishedDate": "2018-02-07T23:29:01.703Z",
          "LastModifiedDate": "2020-01-15T20:15:18.557Z"
        },
        {
          "VulnerabilityID": "CVE-2024-0553",
          "VendorIDs": [
            "DLA-3740-1"
          ],
          "PkgID": "libgnutls30@3.6.7-4+deb10u10",
          "PkgName": "libgnutls30",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libgnutls30@3.6.7-4%2Bdeb10u10?arch=amd64\u0026distro=debian-10.13",
            "UID": "60abc971b6a0792d"
          },
          "InstalledVersion": "3.6.7-4+deb10u10",
          "FixedVersion": "3.6.7-4+deb10u12",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-0553",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "gnutls: incomplete fix for CVE-2023-5981",
          "Description": "A vulnerability was found in GnuTLS. The response times to malformed ciphertexts in RSA-PSK ClientKeyExchange differ from the response times of ciphertexts with correct PKCS#1 v1.5 padding. This issue may allow a remote attacker to perform a timing side-channel attack in the RSA-PSK key exchange, potentially leading to the leakage of sensitive data. CVE-2024-0553 is designated as an incomplete resolution for CVE-2023-5981.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-203"
          ],
          "VendorSeverity": {
            "alma": 2,
            "amazon": 2,
            "azure": 3,
            "nvd": 3,
            "oracle-oval": 2,
            "photon": 2,
            "redhat": 2,
            "rocky": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
              "V3Score": 7.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
              "V3Score": 7.5
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2024/01/19/3",
            "https://access.redhat.com/errata/RHSA-2024:0533",
            "https://access.redhat.com/errata/RHSA-2024:0627",
            "https://access.redhat.com/errata/RHSA-2024:0796",
            "https://access.redhat.com/errata/RHSA-2024:1082",
            "https://access.redhat.com/errata/RHSA-2024:1108",
            "https://access.redhat.com/errata/RHSA-2024:1383",
            "https://access.redhat.com/errata/RHSA-2024:2094",
            "https://access.redhat.com/security/cve/CVE-2024-0553",
            "https://bugzilla.redhat.com/2248445",
            "https://bugzilla.redhat.com/2258412",
            "https://bugzilla.redhat.com/2258544",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2258412",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-0553",
            "https://errata.almalinux.org/9/ALSA-2024-0533.html",
            "https://errata.rockylinux.org/RLSA-2024:0627",
            "https://gitlab.com/gnutls/gnutls/-/issues/1522",
            "https://gnutls.org/security-new.html#GNUTLS-SA-2024-01-14",
            "https://linux.oracle.com/cve/CVE-2024-0553.html",
            "https://linux.oracle.com/errata/ELSA-2024-12336.html",
            "https://lists.debian.org/debian-lts-announce/2024/02/msg00010.html",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/7ZEIOLORQ7N6WRPFXZSYDL2MC4LP7VFV/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/GNXKVR5YNUEBNHAHM5GSYKBZX4W2HMN2/",
            "https://lists.gnupg.org/pipermail/gnutls-help/2024-January/004841.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-0553",
            "https://security.netapp.com/advisory/ntap-20240202-0011/",
            "https://ubuntu.com/security/notices/USN-6593-1",
            "https://www.cve.org/CVERecord?id=CVE-2024-0553"
          ],
          "PublishedDate": "2024-01-16T12:15:45.557Z",
          "LastModifiedDate": "2024-07-08T18:15:06.153Z"
        },
        {
          "VulnerabilityID": "CVE-2023-5981",
          "VendorIDs": [
            "DLA-3660-1"
          ],
          "PkgID": "libgnutls30@3.6.7-4+deb10u10",
          "PkgName": "libgnutls30",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libgnutls30@3.6.7-4%2Bdeb10u10?arch=amd64\u0026distro=debian-10.13",
            "UID": "60abc971b6a0792d"
          },
          "InstalledVersion": "3.6.7-4+deb10u10",
          "FixedVersion": "3.6.7-4+deb10u11",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-5981",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "gnutls: timing side-channel in the RSA-PSK authentication",
          "Description": "A vulnerability was found that the response times to malformed ciphertexts in RSA-PSK ClientKeyExchange differ from response times of ciphertexts with correct PKCS#1 v1.5 padding.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-203"
          ],
          "VendorSeverity": {
            "alma": 2,
            "amazon": 2,
            "nvd": 2,
            "oracle-oval": 2,
            "photon": 2,
            "redhat": 2,
            "rocky": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
              "V3Score": 5.9
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
              "V3Score": 5.9
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2024/01/19/3",
            "https://access.redhat.com/errata/RHSA-2024:0155",
            "https://access.redhat.com/errata/RHSA-2024:0319",
            "https://access.redhat.com/errata/RHSA-2024:0399",
            "https://access.redhat.com/errata/RHSA-2024:0451",
            "https://access.redhat.com/errata/RHSA-2024:0533",
            "https://access.redhat.com/errata/RHSA-2024:1383",
            "https://access.redhat.com/errata/RHSA-2024:2094",
            "https://access.redhat.com/security/cve/CVE-2023-5981",
            "https://bugzilla.redhat.com/2248445",
            "https://bugzilla.redhat.com/2258412",
            "https://bugzilla.redhat.com/2258544",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2248445",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-5981",
            "https://errata.almalinux.org/9/ALSA-2024-0533.html",
            "https://errata.rockylinux.org/RLSA-2024:0155",
            "https://gnutls.org/security-new.html#GNUTLS-SA-2023-10-23",
            "https://linux.oracle.com/cve/CVE-2023-5981.html",
            "https://linux.oracle.com/errata/ELSA-2024-12336.html",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/7ZEIOLORQ7N6WRPFXZSYDL2MC4LP7VFV/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/GNXKVR5YNUEBNHAHM5GSYKBZX4W2HMN2/",
            "https://lists.gnupg.org/pipermail/gnutls-help/2023-November/004837.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-5981",
            "https://ubuntu.com/security/notices/USN-6499-1",
            "https://ubuntu.com/security/notices/USN-6499-2",
            "https://www.cve.org/CVERecord?id=CVE-2023-5981"
          ],
          "PublishedDate": "2023-11-28T12:15:07.04Z",
          "LastModifiedDate": "2024-07-08T18:15:04.087Z"
        },
        {
          "VulnerabilityID": "CVE-2011-3389",
          "PkgID": "libgnutls30@3.6.7-4+deb10u10",
          "PkgName": "libgnutls30",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libgnutls30@3.6.7-4%2Bdeb10u10?arch=amd64\u0026distro=debian-10.13",
            "UID": "60abc971b6a0792d"
          },
          "InstalledVersion": "3.6.7-4+deb10u10",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2011-3389",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "HTTPS: block-wise chosen-plaintext attack against SSL/TLS (BEAST)",
          "Description": "The SSL protocol, as used in certain configurations in Microsoft Windows and Microsoft Internet Explorer, Mozilla Firefox, Google Chrome, Opera, and other products, encrypts data by using CBC mode with chained initialization vectors, which allows man-in-the-middle attackers to obtain plaintext HTTP headers via a blockwise chosen-boundary attack (BCBA) on an HTTPS session, in conjunction with JavaScript code that uses (1) the HTML5 WebSocket API, (2) the Java URLConnection API, or (3) the Silverlight WebClient API, aka a \"BEAST\" attack.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-326"
          ],
          "VendorSeverity": {
            "amazon": 4,
            "debian": 1,
            "nvd": 2,
            "oracle-oval": 4,
            "redhat": 2,
            "ubuntu": 1
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:M/Au:N/C:P/I:N/A:N",
              "V2Score": 4.3
            },
            "redhat": {
              "V2Vector": "AV:N/AC:M/Au:N/C:P/I:N/A:N",
              "V2Score": 4.3
            }
          },
          "References": [
            "http://arcticdog.wordpress.com/2012/08/29/beast-openssl-and-apache/",
            "http://blog.mozilla.com/security/2011/09/27/attack-against-tls-protected-communications/",
            "http://blogs.technet.com/b/msrc/archive/2011/09/26/microsoft-releases-security-advisory-2588513.aspx",
            "http://blogs.technet.com/b/srd/archive/2011/09/26/is-ssl-broken-more-about-security-advisory-2588513.aspx",
            "http://curl.haxx.se/docs/adv_20120124B.html",
            "http://downloads.asterisk.org/pub/security/AST-2016-001.html",
            "http://ekoparty.org/2011/juliano-rizzo.php",
            "http://eprint.iacr.org/2004/111",
            "http://eprint.iacr.org/2006/136",
            "http://googlechromereleases.blogspot.com/2011/10/chrome-stable-release.html",
            "http://isc.sans.edu/diary/SSL+TLS+part+3+/11635",
            "http://lists.apple.com/archives/Security-announce/2011//Oct/msg00001.html",
            "http://lists.apple.com/archives/Security-announce/2011//Oct/msg00002.html",
            "http://lists.apple.com/archives/security-announce/2012/Feb/msg00000.html",
            "http://lists.apple.com/archives/security-announce/2012/Jul/msg00001.html",
            "http://lists.apple.com/archives/security-announce/2012/May/msg00001.html",
            "http://lists.apple.com/archives/security-announce/2012/Sep/msg00004.html",
            "http://lists.apple.com/archives/security-announce/2013/Oct/msg00004.html",
            "http://lists.opensuse.org/opensuse-security-announce/2012-01/msg00049.html",
            "http://lists.opensuse.org/opensuse-security-announce/2012-01/msg00051.html",
            "http://lists.opensuse.org/opensuse-security-announce/2012-05/msg00009.html",
            "http://lists.opensuse.org/opensuse-security-announce/2020-01/msg00040.html",
            "http://marc.info/?l=bugtraq\u0026m=132750579901589\u0026w=2",
            "http://marc.info/?l=bugtraq\u0026m=132872385320240\u0026w=2",
            "http://marc.info/?l=bugtraq\u0026m=133365109612558\u0026w=2",
            "http://marc.info/?l=bugtraq\u0026m=133728004526190\u0026w=2",
            "http://marc.info/?l=bugtraq\u0026m=134254866602253\u0026w=2",
            "http://marc.info/?l=bugtraq\u0026m=134254957702612\u0026w=2",
            "http://my.opera.com/securitygroup/blog/2011/09/28/the-beast-ssl-tls-issue",
            "http://osvdb.org/74829",
            "http://rhn.redhat.com/errata/RHSA-2012-0508.html",
            "http://rhn.redhat.com/errata/RHSA-2013-1455.html",
            "http://secunia.com/advisories/45791",
            "http://secunia.com/advisories/47998",
            "http://secunia.com/advisories/48256",
            "http://secunia.com/advisories/48692",
            "http://secunia.com/advisories/48915",
            "http://secunia.com/advisories/48948",
            "http://secunia.com/advisories/49198",
            "http://secunia.com/advisories/55322",
            "http://secunia.com/advisories/55350",
            "http://secunia.com/advisories/55351",
            "http://security.gentoo.org/glsa/glsa-201203-02.xml",
            "http://security.gentoo.org/glsa/glsa-201406-32.xml",
            "http://support.apple.com/kb/HT4999",
            "http://support.apple.com/kb/HT5001",
            "http://support.apple.com/kb/HT5130",
            "http://support.apple.com/kb/HT5281",
            "http://support.apple.com/kb/HT5501",
            "http://support.apple.com/kb/HT6150",
            "http://technet.microsoft.com/security/advisory/2588513",
            "http://vnhacker.blogspot.com/2011/09/beast.html",
            "http://www.apcmedia.com/salestools/SJHN-7RKGNM/SJHN-7RKGNM_R4_EN.pdf",
            "http://www.debian.org/security/2012/dsa-2398",
            "http://www.educatedguesswork.org/2011/09/security_impact_of_the_rizzodu.html",
            "http://www.ibm.com/developerworks/java/jdk/alerts/",
            "http://www.imperialviolet.org/2011/09/23/chromeandbeast.html",
            "http://www.insecure.cl/Beast-SSL.rar",
            "http://www.kb.cert.org/vuls/id/864643",
            "http://www.mandriva.com/security/advisories?name=MDVSA-2012:058",
            "http://www.opera.com/docs/changelogs/mac/1151/",
            "http://www.opera.com/docs/changelogs/mac/1160/",
            "http://www.opera.com/docs/changelogs/unix/1151/",
            "http://www.opera.com/docs/changelogs/unix/1160/",
            "http://www.opera.com/docs/changelogs/windows/1151/",
            "http://www.opera.com/docs/changelogs/windows/1160/",
            "http://www.opera.com/support/kb/view/1004/",
            "http://www.oracle.com/technetwork/topics/security/cpujan2015-1972971.html",
            "http://www.oracle.com/technetwork/topics/security/cpujul2015-2367936.html",
            "http://www.oracle.com/technetwork/topics/security/javacpuoct2011-443431.html",
            "http://www.redhat.com/support/errata/RHSA-2011-1384.html",
            "http://www.redhat.com/support/errata/RHSA-2012-0006.html",
            "http://www.securityfocus.com/bid/49388",
            "http://www.securityfocus.com/bid/49778",
            "http://www.securitytracker.com/id/1029190",
            "http://www.securitytracker.com/id?1025997",
            "http://www.securitytracker.com/id?1026103",
            "http://www.securitytracker.com/id?1026704",
            "http://www.ubuntu.com/usn/USN-1263-1",
            "http://www.us-cert.gov/cas/techalerts/TA12-010A.html",
            "https://access.redhat.com/security/cve/CVE-2011-3389",
            "https://blogs.oracle.com/sunsecurity/entry/multiple_vulnerabilities_in_fetchmail",
            "https://bugzilla.novell.com/show_bug.cgi?id=719047",
            "https://bugzilla.redhat.com/show_bug.cgi?id=737506",
            "https://cert-portal.siemens.com/productcert/pdf/ssa-556833.pdf",
            "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2012/ms12-006",
            "https://h20564.www2.hp.com/portal/site/hpsc/public/kb/docDisplay?docId=emr_na-c03839862",
            "https://hermes.opensuse.org/messages/13154861",
            "https://hermes.opensuse.org/messages/13155432",
            "https://ics-cert.us-cert.gov/advisories/ICSMA-18-058-02",
            "https://linux.oracle.com/cve/CVE-2011-3389.html",
            "https://linux.oracle.com/errata/ELSA-2011-1380.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2011-3389",
            "https://oval.cisecurity.org/repository/search/definition/oval%3Aorg.mitre.oval%3Adef%3A14752",
            "https://ubuntu.com/security/notices/USN-1263-1",
            "https://www.cve.org/CVERecord?id=CVE-2011-3389"
          ],
          "PublishedDate": "2011-09-06T19:55:03.197Z",
          "LastModifiedDate": "2022-11-29T15:56:08.637Z"
        },
        {
          "VulnerabilityID": "CVE-2019-12290",
          "PkgID": "libidn2-0@2.0.5-1+deb10u1",
          "PkgName": "libidn2-0",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libidn2-0@2.0.5-1%2Bdeb10u1?arch=amd64\u0026distro=debian-10.13",
            "UID": "8bfa68a99373d90d"
          },
          "InstalledVersion": "2.0.5-1+deb10u1",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2019-12290",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "GNU libidn2 before 2.2.0 fails to perform the roundtrip checks specifi ...",
          "Description": "GNU libidn2 before 2.2.0 fails to perform the roundtrip checks specified in RFC3490 Section 4.2 when converting A-labels to U-labels. This makes it possible in some circumstances for one domain to impersonate another. By creating a malicious domain that matches a target domain except for the inclusion of certain punycoded Unicode characters (that would be discarded when converted first to a Unicode label and then back to an ASCII label), arbitrary domains can be impersonated.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-20"
          ],
          "VendorSeverity": {
            "amazon": 2,
            "nvd": 3,
            "ubuntu": 2
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:N/I:P/A:N",
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
              "V2Score": 5,
              "V3Score": 7.5
            }
          },
          "References": [
            "http://lists.opensuse.org/opensuse-security-announce/2019-12/msg00008.html",
            "http://lists.opensuse.org/opensuse-security-announce/2019-12/msg00009.html",
            "https://gitlab.com/libidn/libidn2/commit/241e8f486134793cb0f4a5b0e5817a97883401f5",
            "https://gitlab.com/libidn/libidn2/commit/614117ef6e4c60e1950d742e3edf0a0ef8d389de",
            "https://gitlab.com/libidn/libidn2/merge_requests/71",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/3UFT76Y7OSGPZV3EBEHD6ISVUM3DLARM/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/KXDKYWFV6N2HHVSE67FFDM7G3FEL2ZNE/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/ONG3GJRRJO35COPGVJXXSZLU4J5Y42AT/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/RSI4TI2JTQWQ3YEUX5X36GTVGKO4QKZ5/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/U6ZXL2RDNQRAHCMKWPOMJFKYJ344X4HL/",
            "https://security.gentoo.org/glsa/202003-63",
            "https://ubuntu.com/security/notices/USN-4168-1",
            "https://usn.ubuntu.com/4168-1/",
            "https://www.cve.org/CVERecord?id=CVE-2019-12290"
          ],
          "PublishedDate": "2019-10-22T16:15:10.877Z",
          "LastModifiedDate": "2023-11-07T03:03:30.877Z"
        },
        {
          "VulnerabilityID": "CVE-2019-17543",
          "PkgID": "liblz4-1@1.8.3-1+deb10u1",
          "PkgName": "liblz4-1",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/liblz4-1@1.8.3-1%2Bdeb10u1?arch=amd64\u0026distro=debian-10.13",
            "UID": "ea42054ce54c4d86"
          },
          "InstalledVersion": "1.8.3-1+deb10u1",
          "Status": "will_not_fix",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2019-17543",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "lz4: heap-based buffer overflow in LZ4_write32",
          "Description": "LZ4 before 1.9.2 has a heap-based buffer overflow in LZ4_write32 (related to LZ4_compress_destSize), affecting applications that call LZ4_compress_fast with a large input. (This issue can also lead to data corruption.) NOTE: the vendor states \"only a few specific / uncommon usages of the API are at risk.\"",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-787"
          ],
          "VendorSeverity": {
            "debian": 1,
            "nvd": 3,
            "photon": 3,
            "redhat": 2
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
              "V2Score": 6.8,
              "V3Score": 8.1
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
              "V3Score": 8.1
            }
          },
          "References": [
            "http://lists.opensuse.org/opensuse-security-announce/2019-10/msg00069.html",
            "http://lists.opensuse.org/opensuse-security-announce/2019-10/msg00070.html",
            "https://access.redhat.com/security/cve/CVE-2019-17543",
            "https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=15941",
            "https://github.com/lz4/lz4/compare/v1.9.1...v1.9.2",
            "https://github.com/lz4/lz4/issues/801",
            "https://github.com/lz4/lz4/pull/756",
            "https://github.com/lz4/lz4/pull/760",
            "https://lists.apache.org/thread.html/25015588b770d67470b7ba7ea49a305d6735dd7f00eabe7d50ec1e17%40%3Cissues.arrow.apache.org%3E",
            "https://lists.apache.org/thread.html/543302d55e2d2da4311994e9b0debdc676bf3fd05e1a2be3407aa2d6%40%3Cissues.arrow.apache.org%3E",
            "https://lists.apache.org/thread.html/793012683dc0fa6819b7c2560e6cf990811014c40c7d75412099c357%40%3Cissues.arrow.apache.org%3E",
            "https://lists.apache.org/thread.html/9ff0606d16be2ab6a81619e1c9e23c3e251756638e36272c8c8b7fa3%40%3Cissues.arrow.apache.org%3E",
            "https://lists.apache.org/thread.html/f0038c4fab2ee25aee849ebeff6b33b3aa89e07ccfb06b5c87b36316%40%3Cissues.arrow.apache.org%3E",
            "https://lists.apache.org/thread.html/f506bc371d4a068d5d84d7361293568f61167d3a1c3e91f0def2d7d3%40%3Cdev.arrow.apache.org%3E",
            "https://lists.apache.org/thread.html/r0fb226357e7988a241b06b93bab065bcea2eb38658b382e485960e26%40%3Cissues.kudu.apache.org%3E",
            "https://lists.apache.org/thread.html/r4068ba81066792f2b4d208b39c4c4713c5d4c79bd8cb6c1904af5720%40%3Cissues.kudu.apache.org%3E",
            "https://lists.apache.org/thread.html/r7bc72200f94298bc9a0e35637f388deb53467ca4b2e2ad1ff66d8960%40%3Cissues.kudu.apache.org%3E",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-17543",
            "https://security.netapp.com/advisory/ntap-20210723-0001/",
            "https://www.cve.org/CVERecord?id=CVE-2019-17543",
            "https://www.oracle.com//security-alerts/cpujul2021.html",
            "https://www.oracle.com/security-alerts/cpuoct2020.html"
          ],
          "PublishedDate": "2019-10-14T02:15:10.873Z",
          "LastModifiedDate": "2023-11-07T03:06:19.137Z"
        },
        {
          "VulnerabilityID": "CVE-2024-28085",
          "VendorIDs": [
            "DLA-3782-1"
          ],
          "PkgID": "libmount1@2.33.1-0.1",
          "PkgName": "libmount1",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libmount1@2.33.1-0.1?arch=amd64\u0026distro=debian-10.13",
            "UID": "7215f8b0787268da"
          },
          "InstalledVersion": "2.33.1-0.1",
          "FixedVersion": "2.33.1-0.1+deb10u1",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-28085",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "util-linux: CVE-2024-28085: wall: escape sequence injection",
          "Description": "wall in util-linux through 2.40, often installed with setgid tty permissions, allows escape sequences to be sent to other users' terminals through argv. (Specifically, escape sequences received from stdin are blocked, but escape sequences received from argv are not blocked.) There may be plausible scenarios where this leads to account takeover.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-150"
          ],
          "VendorSeverity": {
            "cbl-mariner": 4,
            "photon": 3,
            "redhat": 3,
            "ubuntu": 2
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N",
              "V3Score": 8.4
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2024/03/27/5",
            "http://www.openwall.com/lists/oss-security/2024/03/27/6",
            "http://www.openwall.com/lists/oss-security/2024/03/27/7",
            "http://www.openwall.com/lists/oss-security/2024/03/27/8",
            "http://www.openwall.com/lists/oss-security/2024/03/27/9",
            "http://www.openwall.com/lists/oss-security/2024/03/28/1",
            "http://www.openwall.com/lists/oss-security/2024/03/28/2",
            "http://www.openwall.com/lists/oss-security/2024/03/28/3",
            "https://access.redhat.com/security/cve/CVE-2024-28085",
            "https://github.com/skyler-ferrante/CVE-2024-28085",
            "https://github.com/util-linux/util-linux/security/advisories/GHSA-xv2h-c6ww-mrjq",
            "https://lists.debian.org/debian-lts-announce/2024/04/msg00005.html",
            "https://mirrors.edge.kernel.org/pub/linux/utils/util-linux/",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-28085",
            "https://people.rit.edu/sjf5462/6831711781/wall_2_27_2024.txt",
            "https://security.netapp.com/advisory/ntap-20240531-0003/",
            "https://ubuntu.com/security/notices/USN-6719-1",
            "https://ubuntu.com/security/notices/USN-6719-2",
            "https://www.cve.org/CVERecord?id=CVE-2024-28085",
            "https://www.openwall.com/lists/oss-security/2024/03/27/5"
          ],
          "PublishedDate": "2024-03-27T19:15:48.367Z",
          "LastModifiedDate": "2024-08-26T21:35:09.31Z"
        },
        {
          "VulnerabilityID": "CVE-2021-37600",
          "VendorIDs": [
            "DLA-3782-1"
          ],
          "PkgID": "libmount1@2.33.1-0.1",
          "PkgName": "libmount1",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libmount1@2.33.1-0.1?arch=amd64\u0026distro=debian-10.13",
            "UID": "7215f8b0787268da"
          },
          "InstalledVersion": "2.33.1-0.1",
          "FixedVersion": "2.33.1-0.1+deb10u1",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2021-37600",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "util-linux: integer overflow can lead to buffer overflow in get_sem_elements() in sys-utils/ipcutils.c",
          "Description": "An integer overflow in util-linux through 2.37.1 can potentially cause a buffer overflow if an attacker were able to use system resources in a way that leads to a large number in the /proc/sysvipc/sem file. NOTE: this is unexploitable in GNU C Library environments, and possibly in all realistic environments.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-190"
          ],
          "VendorSeverity": {
            "amazon": 1,
            "cbl-mariner": 2,
            "nvd": 2,
            "photon": 2,
            "redhat": 1,
            "ubuntu": 1
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:L/AC:H/Au:N/C:N/I:N/A:P",
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
              "V2Score": 1.2,
              "V3Score": 5.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:H",
              "V3Score": 4.7
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2021-37600",
            "https://github.com/karelzak/util-linux/commit/1c9143d0c1f979c3daf10e1c37b5b1e916c22a1c",
            "https://github.com/karelzak/util-linux/issues/1395",
            "https://lists.debian.org/debian-lts-announce/2024/04/msg00005.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-37600",
            "https://security.gentoo.org/glsa/202401-08",
            "https://security.netapp.com/advisory/ntap-20210902-0002/",
            "https://www.cve.org/CVERecord?id=CVE-2021-37600"
          ],
          "PublishedDate": "2021-07-30T14:15:18.737Z",
          "LastModifiedDate": "2024-08-04T02:15:24.44Z"
        },
        {
          "VulnerabilityID": "CVE-2022-0563",
          "PkgID": "libmount1@2.33.1-0.1",
          "PkgName": "libmount1",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libmount1@2.33.1-0.1?arch=amd64\u0026distro=debian-10.13",
            "UID": "7215f8b0787268da"
          },
          "InstalledVersion": "2.33.1-0.1",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2022-0563",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "util-linux: partial disclosure of arbitrary files in chfn and chsh when compiled with libreadline",
          "Description": "A flaw was found in the util-linux chfn and chsh utilities when compiled with Readline support. The Readline library uses an \"INPUTRC\" environment variable to get a path to the library config file. When the library cannot parse the specified file, it prints an error message containing data from the file. This flaw allows an unprivileged user to read root-owned files, potentially leading to privilege escalation. This flaw affects util-linux versions prior to 2.37.4.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-209"
          ],
          "VendorSeverity": {
            "amazon": 2,
            "cbl-mariner": 2,
            "debian": 1,
            "nvd": 2,
            "photon": 2,
            "redhat": 2
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:L/AC:M/Au:N/C:P/I:N/A:N",
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
              "V2Score": 1.9,
              "V3Score": 5.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
              "V3Score": 5.5
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2022-0563",
            "https://blog.trailofbits.com/2023/02/16/suid-logic-bug-linux-readline/",
            "https://lore.kernel.org/util-linux/20220214110609.msiwlm457ngoic6w%40ws.net.home/T/#u",
            "https://lore.kernel.org/util-linux/20220214110609.msiwlm457ngoic6w@ws.net.home/T/#u",
            "https://nvd.nist.gov/vuln/detail/CVE-2022-0563",
            "https://security.gentoo.org/glsa/202401-08",
            "https://security.netapp.com/advisory/ntap-20220331-0002/",
            "https://www.cve.org/CVERecord?id=CVE-2022-0563"
          ],
          "PublishedDate": "2022-02-21T19:15:08.393Z",
          "LastModifiedDate": "2024-01-07T09:15:08.713Z"
        },
        {
          "VulnerabilityID": "CVE-2021-39537",
          "VendorIDs": [
            "DLA-3682-1"
          ],
          "PkgID": "libncursesw6@6.1+20181013-2+deb10u3",
          "PkgName": "libncursesw6",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libncursesw6@6.1%2B20181013-2%2Bdeb10u3?arch=amd64\u0026distro=debian-10.13",
            "UID": "b938666b7e5bf7ca"
          },
          "InstalledVersion": "6.1+20181013-2+deb10u3",
          "FixedVersion": "6.1+20181013-2+deb10u5",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2021-39537",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "ncurses: heap-based buffer overflow in _nc_captoinfo() in captoinfo.c",
          "Description": "An issue was discovered in ncurses through v6.2-1. _nc_captoinfo in captoinfo.c has a heap-based buffer overflow.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-787"
          ],
          "VendorSeverity": {
            "amazon": 2,
            "cbl-mariner": 3,
            "nvd": 3,
            "photon": 3,
            "redhat": 1,
            "ubuntu": 1
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
              "V2Score": 6.8,
              "V3Score": 8.8
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
              "V3Score": 5.5
            }
          },
          "References": [
            "http://cvsweb.netbsd.org/bsdweb.cgi/pkgsrc/devel/ncurses/patches/patch-ncurses_tinfo_captoinfo.c?rev=1.1\u0026content-type=text/x-cvsweb-markup",
            "http://seclists.org/fulldisclosure/2022/Oct/28",
            "http://seclists.org/fulldisclosure/2022/Oct/41",
            "http://seclists.org/fulldisclosure/2022/Oct/43",
            "http://seclists.org/fulldisclosure/2022/Oct/45",
            "https://access.redhat.com/security/cve/CVE-2021-39537",
            "https://lists.debian.org/debian-lts-announce/2023/12/msg00004.html",
            "https://lists.gnu.org/archive/html/bug-ncurses/2020-08/msg00006.html",
            "https://lists.gnu.org/archive/html/bug-ncurses/2021-10/msg00023.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-39537",
            "https://security.netapp.com/advisory/ntap-20230427-0012/",
            "https://support.apple.com/kb/HT213443",
            "https://support.apple.com/kb/HT213444",
            "https://support.apple.com/kb/HT213488",
            "https://ubuntu.com/security/notices/USN-5477-1",
            "https://ubuntu.com/security/notices/USN-6099-1",
            "https://www.cve.org/CVERecord?id=CVE-2021-39537"
          ],
          "PublishedDate": "2021-09-20T16:15:12.477Z",
          "LastModifiedDate": "2023-12-03T20:15:06.86Z"
        },
        {
          "VulnerabilityID": "CVE-2023-29491",
          "VendorIDs": [
            "DLA-3682-1"
          ],
          "PkgID": "libncursesw6@6.1+20181013-2+deb10u3",
          "PkgName": "libncursesw6",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libncursesw6@6.1%2B20181013-2%2Bdeb10u3?arch=amd64\u0026distro=debian-10.13",
            "UID": "b938666b7e5bf7ca"
          },
          "InstalledVersion": "6.1+20181013-2+deb10u3",
          "FixedVersion": "6.1+20181013-2+deb10u5",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-29491",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "ncurses: Local users can trigger security-relevant memory corruption via malformed data",
          "Description": "ncurses before 6.4 20230408, when used by a setuid application, allows local users to trigger security-relevant memory corruption via malformed data in a terminfo database file that is found in $HOME/.terminfo or reached via the TERMINFO or TERM environment variable.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-787"
          ],
          "VendorSeverity": {
            "alma": 2,
            "amazon": 3,
            "cbl-mariner": 3,
            "nvd": 3,
            "oracle-oval": 2,
            "photon": 3,
            "redhat": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
              "V3Score": 7.8
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
              "V3Score": 7.8
            }
          },
          "References": [
            "http://ncurses.scripts.mit.edu/?p=ncurses.git%3Ba=commit%3Bh=eb51b1ea1f75a0ec17c9c5937cb28df1e8eeec56",
            "http://ncurses.scripts.mit.edu/?p=ncurses.git;a=commit;h=eb51b1ea1f75a0ec17c9c5937cb28df1e8eeec56",
            "http://www.openwall.com/lists/oss-security/2023/04/19/10",
            "http://www.openwall.com/lists/oss-security/2023/04/19/11",
            "https://access.redhat.com/errata/RHSA-2023:6698",
            "https://access.redhat.com/security/cve/CVE-2023-29491",
            "https://bugzilla.redhat.com/2191704",
            "https://errata.almalinux.org/9/ALSA-2023-6698.html",
            "https://invisible-island.net/ncurses/NEWS.html#index-t20230408",
            "https://linux.oracle.com/cve/CVE-2023-29491.html",
            "https://linux.oracle.com/errata/ELSA-2023-6698.html",
            "https://lists.debian.org/debian-lts-announce/2023/12/msg00004.html",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/LU4MYMKFEZQ5VSCVLRIZGDQOUW3T44GT/",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-29491",
            "https://security.netapp.com/advisory/ntap-20230517-0009/",
            "https://support.apple.com/kb/HT213843",
            "https://support.apple.com/kb/HT213844",
            "https://support.apple.com/kb/HT213845",
            "https://ubuntu.com/security/notices/USN-6099-1",
            "https://www.cve.org/CVERecord?id=CVE-2023-29491",
            "https://www.openwall.com/lists/oss-security/2023/04/12/5",
            "https://www.openwall.com/lists/oss-security/2023/04/13/4"
          ],
          "PublishedDate": "2023-04-14T01:15:08.57Z",
          "LastModifiedDate": "2024-01-31T03:15:07.86Z"
        },
        {
          "VulnerabilityID": "CVE-2020-19189",
          "VendorIDs": [
            "DLA-3586-1"
          ],
          "PkgID": "libncursesw6@6.1+20181013-2+deb10u3",
          "PkgName": "libncursesw6",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libncursesw6@6.1%2B20181013-2%2Bdeb10u3?arch=amd64\u0026distro=debian-10.13",
            "UID": "b938666b7e5bf7ca"
          },
          "InstalledVersion": "6.1+20181013-2+deb10u3",
          "FixedVersion": "6.1+20181013-2+deb10u4",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2020-19189",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "ncurses: Heap buffer overflow in postprocess_terminfo function in tinfo/parse_entry.c:997",
          "Description": "Buffer Overflow vulnerability in postprocess_terminfo function in tinfo/parse_entry.c:997 in ncurses 6.1 allows remote attackers to cause a denial of service via crafted command.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-787"
          ],
          "VendorSeverity": {
            "amazon": 2,
            "nvd": 2,
            "redhat": 1,
            "ubuntu": 2
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
              "V3Score": 6.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
              "V3Score": 6.5
            }
          },
          "References": [
            "http://seclists.org/fulldisclosure/2023/Dec/10",
            "http://seclists.org/fulldisclosure/2023/Dec/11",
            "http://seclists.org/fulldisclosure/2023/Dec/9",
            "https://access.redhat.com/security/cve/CVE-2020-19189",
            "https://github.com/zjuchenyuan/fuzzpoc/blob/master/infotocap_poc5.md",
            "https://lists.debian.org/debian-lts-announce/2023/09/msg00033.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2020-19189",
            "https://security.netapp.com/advisory/ntap-20231006-0005/",
            "https://support.apple.com/kb/HT214036",
            "https://support.apple.com/kb/HT214037",
            "https://support.apple.com/kb/HT214038",
            "https://ubuntu.com/security/notices/USN-6451-1",
            "https://www.cve.org/CVERecord?id=CVE-2020-19189"
          ],
          "PublishedDate": "2023-08-22T19:16:01.02Z",
          "LastModifiedDate": "2023-12-13T01:15:07.683Z"
        },
        {
          "VulnerabilityID": "CVE-2023-50495",
          "PkgID": "libncursesw6@6.1+20181013-2+deb10u3",
          "PkgName": "libncursesw6",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libncursesw6@6.1%2B20181013-2%2Bdeb10u3?arch=amd64\u0026distro=debian-10.13",
            "UID": "b938666b7e5bf7ca"
          },
          "InstalledVersion": "6.1+20181013-2+deb10u3",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-50495",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "ncurses: segmentation fault via _nc_wrap_entry()",
          "Description": "NCurse v6.4-20230418 was discovered to contain a segmentation fault via the component _nc_wrap_entry().",
          "Severity": "MEDIUM",
          "VendorSeverity": {
            "amazon": 2,
            "nvd": 2,
            "redhat": 1,
            "ubuntu": 1
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
              "V3Score": 6.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
              "V3Score": 6.5
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2023-50495",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/LU4MYMKFEZQ5VSCVLRIZGDQOUW3T44GT/",
            "https://lists.gnu.org/archive/html/bug-ncurses/2023-04/msg00020.html",
            "https://lists.gnu.org/archive/html/bug-ncurses/2023-04/msg00029.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-50495",
            "https://security.netapp.com/advisory/ntap-20240119-0008/",
            "https://ubuntu.com/security/notices/USN-6684-1",
            "https://www.cve.org/CVERecord?id=CVE-2023-50495"
          ],
          "PublishedDate": "2023-12-12T15:15:07.867Z",
          "LastModifiedDate": "2024-01-31T03:15:08.49Z"
        },
        {
          "VulnerabilityID": "CVE-2023-45918",
          "PkgID": "libncursesw6@6.1+20181013-2+deb10u3",
          "PkgName": "libncursesw6",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libncursesw6@6.1%2B20181013-2%2Bdeb10u3?arch=amd64\u0026distro=debian-10.13",
            "UID": "b938666b7e5bf7ca"
          },
          "InstalledVersion": "6.1+20181013-2+deb10u3",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-45918",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "ncurses: NULL pointer dereference in tgetstr in tinfo/lib_termcap.c",
          "Description": "ncurses 6.4-20230610 has a NULL pointer dereference in tgetstr in tinfo/lib_termcap.c.",
          "Severity": "LOW",
          "VendorSeverity": {
            "amazon": 2,
            "redhat": 1,
            "ubuntu": 1
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L",
              "V3Score": 3.3
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2023-45918",
            "https://lists.gnu.org/archive/html/bug-ncurses/2023-06/msg00005.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-45918",
            "https://security.netapp.com/advisory/ntap-20240315-0006/",
            "https://www.cve.org/CVERecord?id=CVE-2023-45918"
          ],
          "PublishedDate": "2024-02-16T22:15:07.88Z",
          "LastModifiedDate": "2024-03-15T11:15:08.51Z"
        },
        {
          "VulnerabilityID": "CVE-2024-22365",
          "PkgID": "libpam-modules@1.3.1-5",
          "PkgName": "libpam-modules",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libpam-modules@1.3.1-5?arch=amd64\u0026distro=debian-10.13",
            "UID": "e241da84c6f108ae"
          },
          "InstalledVersion": "1.3.1-5",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-22365",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "pam: allowing unprivileged user to block another user namespace",
          "Description": "linux-pam (aka Linux PAM) before 1.6.0 allows attackers to cause a denial of service (blocked login process) via mkfifo because the openat call (for protect_dir) lacks O_DIRECTORY.",
          "Severity": "MEDIUM",
          "VendorSeverity": {
            "alma": 2,
            "amazon": 1,
            "cbl-mariner": 2,
            "nvd": 2,
            "oracle-oval": 2,
            "photon": 2,
            "redhat": 2,
            "rocky": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 5.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 5.5
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2024/01/18/3",
            "https://access.redhat.com/errata/RHSA-2024:2438",
            "https://access.redhat.com/security/cve/CVE-2024-22365",
            "https://bugzilla.redhat.com/2257722",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2257722",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-22365",
            "https://errata.almalinux.org/9/ALSA-2024-2438.html",
            "https://errata.rockylinux.org/RLSA-2024:3163",
            "https://github.com/linux-pam/linux-pam",
            "https://github.com/linux-pam/linux-pam/commit/031bb5a5d0d950253b68138b498dc93be69a64cb",
            "https://github.com/linux-pam/linux-pam/releases/tag/v1.6.0",
            "https://linux.oracle.com/cve/CVE-2024-22365.html",
            "https://linux.oracle.com/errata/ELSA-2024-3163.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-22365",
            "https://ubuntu.com/security/notices/USN-6588-1",
            "https://ubuntu.com/security/notices/USN-6588-2",
            "https://www.cve.org/CVERecord?id=CVE-2024-22365",
            "https://www.openwall.com/lists/oss-security/2024/01/18/3"
          ],
          "PublishedDate": "2024-02-06T08:15:52.203Z",
          "LastModifiedDate": "2024-02-14T00:27:40.143Z"
        },
        {
          "VulnerabilityID": "CVE-2024-22365",
          "PkgID": "libpam-modules-bin@1.3.1-5",
          "PkgName": "libpam-modules-bin",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libpam-modules-bin@1.3.1-5?arch=amd64\u0026distro=debian-10.13",
            "UID": "3e9cd0832ab3f434"
          },
          "InstalledVersion": "1.3.1-5",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-22365",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "pam: allowing unprivileged user to block another user namespace",
          "Description": "linux-pam (aka Linux PAM) before 1.6.0 allows attackers to cause a denial of service (blocked login process) via mkfifo because the openat call (for protect_dir) lacks O_DIRECTORY.",
          "Severity": "MEDIUM",
          "VendorSeverity": {
            "alma": 2,
            "amazon": 1,
            "cbl-mariner": 2,
            "nvd": 2,
            "oracle-oval": 2,
            "photon": 2,
            "redhat": 2,
            "rocky": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 5.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 5.5
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2024/01/18/3",
            "https://access.redhat.com/errata/RHSA-2024:2438",
            "https://access.redhat.com/security/cve/CVE-2024-22365",
            "https://bugzilla.redhat.com/2257722",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2257722",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-22365",
            "https://errata.almalinux.org/9/ALSA-2024-2438.html",
            "https://errata.rockylinux.org/RLSA-2024:3163",
            "https://github.com/linux-pam/linux-pam",
            "https://github.com/linux-pam/linux-pam/commit/031bb5a5d0d950253b68138b498dc93be69a64cb",
            "https://github.com/linux-pam/linux-pam/releases/tag/v1.6.0",
            "https://linux.oracle.com/cve/CVE-2024-22365.html",
            "https://linux.oracle.com/errata/ELSA-2024-3163.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-22365",
            "https://ubuntu.com/security/notices/USN-6588-1",
            "https://ubuntu.com/security/notices/USN-6588-2",
            "https://www.cve.org/CVERecord?id=CVE-2024-22365",
            "https://www.openwall.com/lists/oss-security/2024/01/18/3"
          ],
          "PublishedDate": "2024-02-06T08:15:52.203Z",
          "LastModifiedDate": "2024-02-14T00:27:40.143Z"
        },
        {
          "VulnerabilityID": "CVE-2024-22365",
          "PkgID": "libpam-runtime@1.3.1-5",
          "PkgName": "libpam-runtime",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libpam-runtime@1.3.1-5?arch=all\u0026distro=debian-10.13",
            "UID": "975acdc185e53c5"
          },
          "InstalledVersion": "1.3.1-5",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-22365",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "pam: allowing unprivileged user to block another user namespace",
          "Description": "linux-pam (aka Linux PAM) before 1.6.0 allows attackers to cause a denial of service (blocked login process) via mkfifo because the openat call (for protect_dir) lacks O_DIRECTORY.",
          "Severity": "MEDIUM",
          "VendorSeverity": {
            "alma": 2,
            "amazon": 1,
            "cbl-mariner": 2,
            "nvd": 2,
            "oracle-oval": 2,
            "photon": 2,
            "redhat": 2,
            "rocky": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 5.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 5.5
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2024/01/18/3",
            "https://access.redhat.com/errata/RHSA-2024:2438",
            "https://access.redhat.com/security/cve/CVE-2024-22365",
            "https://bugzilla.redhat.com/2257722",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2257722",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-22365",
            "https://errata.almalinux.org/9/ALSA-2024-2438.html",
            "https://errata.rockylinux.org/RLSA-2024:3163",
            "https://github.com/linux-pam/linux-pam",
            "https://github.com/linux-pam/linux-pam/commit/031bb5a5d0d950253b68138b498dc93be69a64cb",
            "https://github.com/linux-pam/linux-pam/releases/tag/v1.6.0",
            "https://linux.oracle.com/cve/CVE-2024-22365.html",
            "https://linux.oracle.com/errata/ELSA-2024-3163.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-22365",
            "https://ubuntu.com/security/notices/USN-6588-1",
            "https://ubuntu.com/security/notices/USN-6588-2",
            "https://www.cve.org/CVERecord?id=CVE-2024-22365",
            "https://www.openwall.com/lists/oss-security/2024/01/18/3"
          ],
          "PublishedDate": "2024-02-06T08:15:52.203Z",
          "LastModifiedDate": "2024-02-14T00:27:40.143Z"
        },
        {
          "VulnerabilityID": "CVE-2024-22365",
          "PkgID": "libpam0g@1.3.1-5",
          "PkgName": "libpam0g",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libpam0g@1.3.1-5?arch=amd64\u0026distro=debian-10.13",
            "UID": "81139c873c8bff71"
          },
          "InstalledVersion": "1.3.1-5",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-22365",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "pam: allowing unprivileged user to block another user namespace",
          "Description": "linux-pam (aka Linux PAM) before 1.6.0 allows attackers to cause a denial of service (blocked login process) via mkfifo because the openat call (for protect_dir) lacks O_DIRECTORY.",
          "Severity": "MEDIUM",
          "VendorSeverity": {
            "alma": 2,
            "amazon": 1,
            "cbl-mariner": 2,
            "nvd": 2,
            "oracle-oval": 2,
            "photon": 2,
            "redhat": 2,
            "rocky": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 5.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 5.5
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2024/01/18/3",
            "https://access.redhat.com/errata/RHSA-2024:2438",
            "https://access.redhat.com/security/cve/CVE-2024-22365",
            "https://bugzilla.redhat.com/2257722",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2257722",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-22365",
            "https://errata.almalinux.org/9/ALSA-2024-2438.html",
            "https://errata.rockylinux.org/RLSA-2024:3163",
            "https://github.com/linux-pam/linux-pam",
            "https://github.com/linux-pam/linux-pam/commit/031bb5a5d0d950253b68138b498dc93be69a64cb",
            "https://github.com/linux-pam/linux-pam/releases/tag/v1.6.0",
            "https://linux.oracle.com/cve/CVE-2024-22365.html",
            "https://linux.oracle.com/errata/ELSA-2024-3163.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-22365",
            "https://ubuntu.com/security/notices/USN-6588-1",
            "https://ubuntu.com/security/notices/USN-6588-2",
            "https://www.cve.org/CVERecord?id=CVE-2024-22365",
            "https://www.openwall.com/lists/oss-security/2024/01/18/3"
          ],
          "PublishedDate": "2024-02-06T08:15:52.203Z",
          "LastModifiedDate": "2024-02-14T00:27:40.143Z"
        },
        {
          "VulnerabilityID": "CVE-2020-14155",
          "PkgID": "libpcre3@2:8.39-12",
          "PkgName": "libpcre3",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libpcre3@8.39-12?arch=amd64\u0026distro=debian-10.13\u0026epoch=2",
            "UID": "73049a5390897d29"
          },
          "InstalledVersion": "2:8.39-12",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2020-14155",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "pcre: Integer overflow when parsing callout numeric arguments",
          "Description": "libpcre in PCRE before 8.44 allows an integer overflow via a large number after a (?C substring.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-190"
          ],
          "VendorSeverity": {
            "alma": 1,
            "bitnami": 2,
            "cbl-mariner": 2,
            "nvd": 2,
            "oracle-oval": 1,
            "photon": 2,
            "redhat": 1,
            "rocky": 1,
            "ubuntu": 1
          },
          "CVSS": {
            "bitnami": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
              "V3Score": 5.3
            },
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
              "V2Score": 5,
              "V3Score": 5.3
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
              "V3Score": 5.3
            }
          },
          "References": [
            "http://seclists.org/fulldisclosure/2020/Dec/32",
            "http://seclists.org/fulldisclosure/2021/Feb/14",
            "https://about.gitlab.com/releases/2020/07/01/security-release-13-1-2-release/",
            "https://access.redhat.com/security/cve/CVE-2020-14155",
            "https://bugs.gentoo.org/717920",
            "https://bugzilla.redhat.com/show_bug.cgi?id=1848436",
            "https://bugzilla.redhat.com/show_bug.cgi?id=1848444",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-20838",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-14155",
            "https://errata.almalinux.org/8/ALSA-2021-4373.html",
            "https://errata.rockylinux.org/RLSA-2021:4373",
            "https://linux.oracle.com/cve/CVE-2020-14155.html",
            "https://linux.oracle.com/errata/ELSA-2021-4373.html",
            "https://lists.apache.org/thread.html/rf9fa47ab66495c78bb4120b0754dd9531ca2ff0430f6685ac9b07772%40%3Cdev.mina.apache.org%3E",
            "https://nvd.nist.gov/vuln/detail/CVE-2020-14155",
            "https://security.netapp.com/advisory/ntap-20221028-0010/",
            "https://support.apple.com/kb/HT211931",
            "https://support.apple.com/kb/HT212147",
            "https://ubuntu.com/security/notices/USN-5425-1",
            "https://www.cve.org/CVERecord?id=CVE-2020-14155",
            "https://www.oracle.com/security-alerts/cpuapr2022.html",
            "https://www.pcre.org/original/changelog.txt"
          ],
          "PublishedDate": "2020-06-15T17:15:10.777Z",
          "LastModifiedDate": "2024-03-27T16:04:48.863Z"
        },
        {
          "VulnerabilityID": "CVE-2017-11164",
          "PkgID": "libpcre3@2:8.39-12",
          "PkgName": "libpcre3",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libpcre3@8.39-12?arch=amd64\u0026distro=debian-10.13\u0026epoch=2",
            "UID": "73049a5390897d29"
          },
          "InstalledVersion": "2:8.39-12",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2017-11164",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "pcre: OP_KETRMAX feature in the match function in pcre_exec.c",
          "Description": "In PCRE 8.41, the OP_KETRMAX feature in the match function in pcre_exec.c allows stack exhaustion (uncontrolled recursion) when processing a crafted regular expression.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-674"
          ],
          "VendorSeverity": {
            "debian": 1,
            "nvd": 3,
            "photon": 3,
            "redhat": 1,
            "ubuntu": 1
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:C",
              "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V2Score": 7.8,
              "V3Score": 7.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L",
              "V3Score": 3.3
            }
          },
          "References": [
            "http://openwall.com/lists/oss-security/2017/07/11/3",
            "http://www.openwall.com/lists/oss-security/2023/04/11/1",
            "http://www.openwall.com/lists/oss-security/2023/04/12/1",
            "http://www.securityfocus.com/bid/99575",
            "https://access.redhat.com/security/cve/CVE-2017-11164",
            "https://lists.apache.org/thread.html/rf9fa47ab66495c78bb4120b0754dd9531ca2ff0430f6685ac9b07772%40%3Cdev.mina.apache.org%3E",
            "https://nvd.nist.gov/vuln/detail/CVE-2017-11164",
            "https://www.cve.org/CVERecord?id=CVE-2017-11164"
          ],
          "PublishedDate": "2017-07-11T03:29:00.277Z",
          "LastModifiedDate": "2023-11-07T02:38:10.98Z"
        },
        {
          "VulnerabilityID": "CVE-2017-16231",
          "PkgID": "libpcre3@2:8.39-12",
          "PkgName": "libpcre3",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libpcre3@8.39-12?arch=amd64\u0026distro=debian-10.13\u0026epoch=2",
            "UID": "73049a5390897d29"
          },
          "InstalledVersion": "2:8.39-12",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2017-16231",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "pcre: self-recursive call in match() in pcre_exec.c leads to denial of service",
          "Description": "In PCRE 8.41, after compiling, a pcretest load test PoC produces a crash overflow in the function match() in pcre_exec.c because of a self-recursive call. NOTE: third parties dispute the relevance of this report, noting that there are options that can be used to limit the amount of stack that is used",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-119"
          ],
          "VendorSeverity": {
            "debian": 1,
            "nvd": 2,
            "photon": 2,
            "redhat": 2
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:L/AC:L/Au:N/C:N/I:N/A:P",
              "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
              "V2Score": 2.1,
              "V3Score": 5.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
              "V3Score": 5.5
            }
          },
          "References": [
            "http://packetstormsecurity.com/files/150897/PCRE-8.41-Buffer-Overflow.html",
            "http://seclists.org/fulldisclosure/2018/Dec/33",
            "http://www.openwall.com/lists/oss-security/2017/11/01/11",
            "http://www.openwall.com/lists/oss-security/2017/11/01/3",
            "http://www.openwall.com/lists/oss-security/2017/11/01/7",
            "http://www.openwall.com/lists/oss-security/2017/11/01/8",
            "http://www.securityfocus.com/bid/101688",
            "https://access.redhat.com/security/cve/CVE-2017-16231",
            "https://bugs.exim.org/show_bug.cgi?id=2047",
            "https://nvd.nist.gov/vuln/detail/CVE-2017-16231",
            "https://www.cve.org/CVERecord?id=CVE-2017-16231"
          ],
          "PublishedDate": "2019-03-21T15:59:56.217Z",
          "LastModifiedDate": "2024-08-05T21:15:24.307Z"
        },
        {
          "VulnerabilityID": "CVE-2017-7245",
          "PkgID": "libpcre3@2:8.39-12",
          "PkgName": "libpcre3",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libpcre3@8.39-12?arch=amd64\u0026distro=debian-10.13\u0026epoch=2",
            "UID": "73049a5390897d29"
          },
          "InstalledVersion": "2:8.39-12",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2017-7245",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "pcre: stack-based buffer overflow write in pcre32_copy_substring",
          "Description": "Stack-based buffer overflow in the pcre32_copy_substring function in pcre_get.c in libpcre1 in PCRE 8.40 allows remote attackers to cause a denial of service (WRITE of size 4) or possibly have unspecified other impact via a crafted file.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-119"
          ],
          "VendorSeverity": {
            "debian": 1,
            "nvd": 3,
            "redhat": 1
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
              "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
              "V2Score": 6.8,
              "V3Score": 7.8
            },
            "redhat": {
              "V3Vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L",
              "V3Score": 3.7
            }
          },
          "References": [
            "http://www.securityfocus.com/bid/97067",
            "https://access.redhat.com/errata/RHSA-2018:2486",
            "https://access.redhat.com/security/cve/CVE-2017-7245",
            "https://blogs.gentoo.org/ago/2017/03/20/libpcre-two-stack-based-buffer-overflow-write-in-pcre32_copy_substring-pcre_get-c/",
            "https://nvd.nist.gov/vuln/detail/CVE-2017-7245",
            "https://security.gentoo.org/glsa/201710-25",
            "https://www.cve.org/CVERecord?id=CVE-2017-7245"
          ],
          "PublishedDate": "2017-03-23T21:59:00.193Z",
          "LastModifiedDate": "2018-08-17T10:29:03.003Z"
        },
        {
          "VulnerabilityID": "CVE-2017-7246",
          "PkgID": "libpcre3@2:8.39-12",
          "PkgName": "libpcre3",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libpcre3@8.39-12?arch=amd64\u0026distro=debian-10.13\u0026epoch=2",
            "UID": "73049a5390897d29"
          },
          "InstalledVersion": "2:8.39-12",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2017-7246",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "pcre: stack-based buffer overflow write in pcre32_copy_substring",
          "Description": "Stack-based buffer overflow in the pcre32_copy_substring function in pcre_get.c in libpcre1 in PCRE 8.40 allows remote attackers to cause a denial of service (WRITE of size 268) or possibly have unspecified other impact via a crafted file.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-119"
          ],
          "VendorSeverity": {
            "debian": 1,
            "nvd": 3,
            "redhat": 1
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
              "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
              "V2Score": 6.8,
              "V3Score": 7.8
            },
            "redhat": {
              "V3Vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L",
              "V3Score": 3.7
            }
          },
          "References": [
            "http://www.securityfocus.com/bid/97067",
            "https://access.redhat.com/errata/RHSA-2018:2486",
            "https://access.redhat.com/security/cve/CVE-2017-7246",
            "https://blogs.gentoo.org/ago/2017/03/20/libpcre-two-stack-based-buffer-overflow-write-in-pcre32_copy_substring-pcre_get-c/",
            "https://nvd.nist.gov/vuln/detail/CVE-2017-7246",
            "https://security.gentoo.org/glsa/201710-25",
            "https://www.cve.org/CVERecord?id=CVE-2017-7246"
          ],
          "PublishedDate": "2017-03-23T21:59:00.223Z",
          "LastModifiedDate": "2018-08-17T10:29:03.08Z"
        },
        {
          "VulnerabilityID": "CVE-2019-20838",
          "PkgID": "libpcre3@2:8.39-12",
          "PkgName": "libpcre3",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libpcre3@8.39-12?arch=amd64\u0026distro=debian-10.13\u0026epoch=2",
            "UID": "73049a5390897d29"
          },
          "InstalledVersion": "2:8.39-12",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2019-20838",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "pcre: Buffer over-read in JIT when UTF is disabled and \\X or \\R has fixed quantifier greater than 1",
          "Description": "libpcre in PCRE before 8.43 allows a subject buffer over-read in JIT when UTF is disabled, and \\X or \\R has more than one fixed quantifier, a related issue to CVE-2019-20454.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-125"
          ],
          "VendorSeverity": {
            "alma": 1,
            "cbl-mariner": 3,
            "debian": 1,
            "nvd": 3,
            "oracle-oval": 1,
            "photon": 3,
            "redhat": 1,
            "rocky": 1,
            "ubuntu": 1
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:P",
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V2Score": 4.3,
              "V3Score": 7.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 7.5
            }
          },
          "References": [
            "http://seclists.org/fulldisclosure/2020/Dec/32",
            "http://seclists.org/fulldisclosure/2021/Feb/14",
            "https://access.redhat.com/security/cve/CVE-2019-20838",
            "https://bugs.gentoo.org/717920",
            "https://bugzilla.redhat.com/show_bug.cgi?id=1848436",
            "https://bugzilla.redhat.com/show_bug.cgi?id=1848444",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-20838",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-14155",
            "https://errata.almalinux.org/8/ALSA-2021-4373.html",
            "https://errata.rockylinux.org/RLSA-2021:4373",
            "https://linux.oracle.com/cve/CVE-2019-20838.html",
            "https://linux.oracle.com/errata/ELSA-2021-4373.html",
            "https://lists.apache.org/thread.html/rf9fa47ab66495c78bb4120b0754dd9531ca2ff0430f6685ac9b07772%40%3Cdev.mina.apache.org%3E",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-20838",
            "https://support.apple.com/kb/HT211931",
            "https://support.apple.com/kb/HT212147",
            "https://ubuntu.com/security/notices/USN-5425-1",
            "https://www.cve.org/CVERecord?id=CVE-2019-20838",
            "https://www.pcre.org/original/changelog.txt"
          ],
          "PublishedDate": "2020-06-15T17:15:09.683Z",
          "LastModifiedDate": "2024-03-27T16:05:46.553Z"
        },
        {
          "VulnerabilityID": "CVE-2019-9893",
          "PkgID": "libseccomp2@2.3.3-4",
          "PkgName": "libseccomp2",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libseccomp2@2.3.3-4?arch=amd64\u0026distro=debian-10.13",
            "UID": "f6cd646b0e361f39"
          },
          "InstalledVersion": "2.3.3-4",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2019-9893",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "libseccomp: incorrect generation of syscall filters in libseccomp",
          "Description": "libseccomp before 2.4.0 did not correctly generate 64-bit syscall argument comparisons using the arithmetic operators (LT, GT, LE, GE), which might able to lead to bypassing seccomp filters and potential privilege escalations.",
          "Severity": "LOW",
          "VendorSeverity": {
            "amazon": 2,
            "debian": 1,
            "nvd": 4,
            "oracle-oval": 2,
            "photon": 4,
            "redhat": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
              "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
              "V2Score": 7.5,
              "V3Score": 9.8
            },
            "redhat": {
              "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
              "V3Score": 7.3
            }
          },
          "References": [
            "http://lists.opensuse.org/opensuse-security-announce/2019-10/msg00022.html",
            "http://lists.opensuse.org/opensuse-security-announce/2019-10/msg00027.html",
            "http://www.paul-moore.com/blog/d/2019/03/libseccomp_v240.html",
            "https://access.redhat.com/errata/RHSA-2019:3624",
            "https://access.redhat.com/security/cve/CVE-2019-9893",
            "https://github.com/seccomp/libseccomp/issues/139",
            "https://linux.oracle.com/cve/CVE-2019-9893.html",
            "https://linux.oracle.com/errata/ELSA-2019-3624.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-9893",
            "https://seclists.org/oss-sec/2019/q1/179",
            "https://security.gentoo.org/glsa/201904-18",
            "https://ubuntu.com/security/notices/USN-4001-1",
            "https://ubuntu.com/security/notices/USN-4001-2",
            "https://usn.ubuntu.com/4001-1/",
            "https://usn.ubuntu.com/4001-2/",
            "https://www.cve.org/CVERecord?id=CVE-2019-9893",
            "https://www.openwall.com/lists/oss-security/2019/03/15/1"
          ],
          "PublishedDate": "2019-03-21T16:01:17.687Z",
          "LastModifiedDate": "2020-08-24T17:37:01.14Z"
        },
        {
          "VulnerabilityID": "CVE-2021-36084",
          "PkgID": "libsepol1@2.8-1",
          "PkgName": "libsepol1",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libsepol1@2.8-1?arch=amd64\u0026distro=debian-10.13",
            "UID": "7185c54f2ff8ff1"
          },
          "InstalledVersion": "2.8-1",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2021-36084",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "libsepol: use-after-free in __cil_verify_classperms()",
          "Description": "The CIL compiler in SELinux 3.2 has a use-after-free in __cil_verify_classperms (called from __cil_verify_classpermission and __cil_pre_verify_helper).",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-416"
          ],
          "VendorSeverity": {
            "alma": 2,
            "amazon": 2,
            "nvd": 1,
            "oracle-oval": 2,
            "photon": 1,
            "redhat": 2,
            "rocky": 2,
            "ubuntu": 1
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:L/AC:L/Au:N/C:N/I:N/A:P",
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L",
              "V2Score": 2.1,
              "V3Score": 3.3
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L",
              "V3Score": 3.3
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2021-36084",
            "https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=31065",
            "https://bugzilla.redhat.com/show_bug.cgi?id=1979662",
            "https://bugzilla.redhat.com/show_bug.cgi?id=1979664",
            "https://bugzilla.redhat.com/show_bug.cgi?id=1979666",
            "https://bugzilla.redhat.com/show_bug.cgi?id=1979668",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-36084",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-36085",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-36086",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-36087",
            "https://errata.almalinux.org/8/ALSA-2021-4513.html",
            "https://errata.rockylinux.org/RLSA-2021:4513",
            "https://github.com/SELinuxProject/selinux/commit/f34d3d30c8325e4847a6b696fe7a3936a8a361f3",
            "https://github.com/google/oss-fuzz-vulns/blob/main/vulns/selinux/OSV-2021-417.yaml",
            "https://linux.oracle.com/cve/CVE-2021-36084.html",
            "https://linux.oracle.com/errata/ELSA-2021-4513.html",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/U7ZYR3PIJ75N6U2IONJWCKZ5L2NKJTGR/",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-36084",
            "https://ubuntu.com/security/notices/USN-5391-1",
            "https://www.cve.org/CVERecord?id=CVE-2021-36084"
          ],
          "PublishedDate": "2021-07-01T03:15:08.717Z",
          "LastModifiedDate": "2023-11-07T03:36:42.51Z"
        },
        {
          "VulnerabilityID": "CVE-2021-36085",
          "PkgID": "libsepol1@2.8-1",
          "PkgName": "libsepol1",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libsepol1@2.8-1?arch=amd64\u0026distro=debian-10.13",
            "UID": "7185c54f2ff8ff1"
          },
          "InstalledVersion": "2.8-1",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2021-36085",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "libsepol: use-after-free in __cil_verify_classperms()",
          "Description": "The CIL compiler in SELinux 3.2 has a use-after-free in __cil_verify_classperms (called from __verify_map_perm_classperms and hashtab_map).",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-416"
          ],
          "VendorSeverity": {
            "alma": 2,
            "amazon": 2,
            "nvd": 1,
            "oracle-oval": 2,
            "photon": 1,
            "redhat": 2,
            "rocky": 2,
            "ubuntu": 1
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:L/AC:L/Au:N/C:N/I:N/A:P",
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L",
              "V2Score": 2.1,
              "V3Score": 3.3
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L",
              "V3Score": 3.3
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2021-36085",
            "https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=31124",
            "https://bugzilla.redhat.com/show_bug.cgi?id=1979662",
            "https://bugzilla.redhat.com/show_bug.cgi?id=1979664",
            "https://bugzilla.redhat.com/show_bug.cgi?id=1979666",
            "https://bugzilla.redhat.com/show_bug.cgi?id=1979668",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-36084",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-36085",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-36086",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-36087",
            "https://errata.almalinux.org/8/ALSA-2021-4513.html",
            "https://errata.rockylinux.org/RLSA-2021:4513",
            "https://github.com/SELinuxProject/selinux/commit/2d35fcc7e9e976a2346b1de20e54f8663e8a6cba",
            "https://github.com/google/oss-fuzz-vulns/blob/main/vulns/selinux/OSV-2021-421.yaml",
            "https://linux.oracle.com/cve/CVE-2021-36085.html",
            "https://linux.oracle.com/errata/ELSA-2021-4513.html",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/U7ZYR3PIJ75N6U2IONJWCKZ5L2NKJTGR/",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-36085",
            "https://ubuntu.com/security/notices/USN-5391-1",
            "https://www.cve.org/CVERecord?id=CVE-2021-36085"
          ],
          "PublishedDate": "2021-07-01T03:15:08.75Z",
          "LastModifiedDate": "2023-11-07T03:36:42.577Z"
        },
        {
          "VulnerabilityID": "CVE-2021-36086",
          "PkgID": "libsepol1@2.8-1",
          "PkgName": "libsepol1",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libsepol1@2.8-1?arch=amd64\u0026distro=debian-10.13",
            "UID": "7185c54f2ff8ff1"
          },
          "InstalledVersion": "2.8-1",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2021-36086",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "libsepol: use-after-free in cil_reset_classpermission()",
          "Description": "The CIL compiler in SELinux 3.2 has a use-after-free in cil_reset_classpermission (called from cil_reset_classperms_set and cil_reset_classperms_list).",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-416"
          ],
          "VendorSeverity": {
            "alma": 2,
            "amazon": 2,
            "nvd": 1,
            "oracle-oval": 2,
            "photon": 1,
            "redhat": 2,
            "rocky": 2,
            "ubuntu": 1
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:L/AC:L/Au:N/C:N/I:N/A:P",
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L",
              "V2Score": 2.1,
              "V3Score": 3.3
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L",
              "V3Score": 3.3
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2021-36086",
            "https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=32177",
            "https://bugzilla.redhat.com/show_bug.cgi?id=1979662",
            "https://bugzilla.redhat.com/show_bug.cgi?id=1979664",
            "https://bugzilla.redhat.com/show_bug.cgi?id=1979666",
            "https://bugzilla.redhat.com/show_bug.cgi?id=1979668",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-36084",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-36085",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-36086",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-36087",
            "https://errata.almalinux.org/8/ALSA-2021-4513.html",
            "https://errata.rockylinux.org/RLSA-2021:4513",
            "https://github.com/SELinuxProject/selinux/commit/c49a8ea09501ad66e799ea41b8154b6770fec2c8",
            "https://github.com/google/oss-fuzz-vulns/blob/main/vulns/selinux/OSV-2021-536.yaml",
            "https://linux.oracle.com/cve/CVE-2021-36086.html",
            "https://linux.oracle.com/errata/ELSA-2021-4513.html",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/U7ZYR3PIJ75N6U2IONJWCKZ5L2NKJTGR/",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-36086",
            "https://ubuntu.com/security/notices/USN-5391-1",
            "https://www.cve.org/CVERecord?id=CVE-2021-36086"
          ],
          "PublishedDate": "2021-07-01T03:15:08.783Z",
          "LastModifiedDate": "2023-11-07T03:36:42.637Z"
        },
        {
          "VulnerabilityID": "CVE-2021-36087",
          "PkgID": "libsepol1@2.8-1",
          "PkgName": "libsepol1",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libsepol1@2.8-1?arch=amd64\u0026distro=debian-10.13",
            "UID": "7185c54f2ff8ff1"
          },
          "InstalledVersion": "2.8-1",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2021-36087",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "libsepol: heap-based buffer overflow in ebitmap_match_any()",
          "Description": "The CIL compiler in SELinux 3.2 has a heap-based buffer over-read in ebitmap_match_any (called indirectly from cil_check_neverallow). This occurs because there is sometimes a lack of checks for invalid statements in an optional block.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-125"
          ],
          "VendorSeverity": {
            "alma": 2,
            "amazon": 2,
            "nvd": 1,
            "oracle-oval": 2,
            "redhat": 2,
            "rocky": 2,
            "ubuntu": 1
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:L/AC:L/Au:N/C:N/I:N/A:P",
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L",
              "V2Score": 2.1,
              "V3Score": 3.3
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L",
              "V3Score": 3.3
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2021-36087",
            "https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=32675",
            "https://bugzilla.redhat.com/show_bug.cgi?id=1979662",
            "https://bugzilla.redhat.com/show_bug.cgi?id=1979664",
            "https://bugzilla.redhat.com/show_bug.cgi?id=1979666",
            "https://bugzilla.redhat.com/show_bug.cgi?id=1979668",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-36084",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-36085",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-36086",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-36087",
            "https://errata.almalinux.org/8/ALSA-2021-4513.html",
            "https://errata.rockylinux.org/RLSA-2021:4513",
            "https://github.com/SELinuxProject/selinux/commit/340f0eb7f3673e8aacaf0a96cbfcd4d12a405521",
            "https://github.com/google/oss-fuzz-vulns/blob/main/vulns/selinux/OSV-2021-585.yaml",
            "https://linux.oracle.com/cve/CVE-2021-36087.html",
            "https://linux.oracle.com/errata/ELSA-2021-4513.html",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/U7ZYR3PIJ75N6U2IONJWCKZ5L2NKJTGR/",
            "https://lore.kernel.org/selinux/CAEN2sdqJKHvDzPnxS-J8grU8fSf32DDtx=kyh84OsCq_Vm+yaQ%40mail.gmail.com/T/",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-36087",
            "https://ubuntu.com/security/notices/USN-5391-1",
            "https://www.cve.org/CVERecord?id=CVE-2021-36087"
          ],
          "PublishedDate": "2021-07-01T03:15:08.817Z",
          "LastModifiedDate": "2023-11-07T03:36:42.693Z"
        },
        {
          "VulnerabilityID": "CVE-2024-28085",
          "VendorIDs": [
            "DLA-3782-1"
          ],
          "PkgID": "libsmartcols1@2.33.1-0.1",
          "PkgName": "libsmartcols1",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libsmartcols1@2.33.1-0.1?arch=amd64\u0026distro=debian-10.13",
            "UID": "40e82eee26aec690"
          },
          "InstalledVersion": "2.33.1-0.1",
          "FixedVersion": "2.33.1-0.1+deb10u1",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-28085",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "util-linux: CVE-2024-28085: wall: escape sequence injection",
          "Description": "wall in util-linux through 2.40, often installed with setgid tty permissions, allows escape sequences to be sent to other users' terminals through argv. (Specifically, escape sequences received from stdin are blocked, but escape sequences received from argv are not blocked.) There may be plausible scenarios where this leads to account takeover.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-150"
          ],
          "VendorSeverity": {
            "cbl-mariner": 4,
            "photon": 3,
            "redhat": 3,
            "ubuntu": 2
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N",
              "V3Score": 8.4
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2024/03/27/5",
            "http://www.openwall.com/lists/oss-security/2024/03/27/6",
            "http://www.openwall.com/lists/oss-security/2024/03/27/7",
            "http://www.openwall.com/lists/oss-security/2024/03/27/8",
            "http://www.openwall.com/lists/oss-security/2024/03/27/9",
            "http://www.openwall.com/lists/oss-security/2024/03/28/1",
            "http://www.openwall.com/lists/oss-security/2024/03/28/2",
            "http://www.openwall.com/lists/oss-security/2024/03/28/3",
            "https://access.redhat.com/security/cve/CVE-2024-28085",
            "https://github.com/skyler-ferrante/CVE-2024-28085",
            "https://github.com/util-linux/util-linux/security/advisories/GHSA-xv2h-c6ww-mrjq",
            "https://lists.debian.org/debian-lts-announce/2024/04/msg00005.html",
            "https://mirrors.edge.kernel.org/pub/linux/utils/util-linux/",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-28085",
            "https://people.rit.edu/sjf5462/6831711781/wall_2_27_2024.txt",
            "https://security.netapp.com/advisory/ntap-20240531-0003/",
            "https://ubuntu.com/security/notices/USN-6719-1",
            "https://ubuntu.com/security/notices/USN-6719-2",
            "https://www.cve.org/CVERecord?id=CVE-2024-28085",
            "https://www.openwall.com/lists/oss-security/2024/03/27/5"
          ],
          "PublishedDate": "2024-03-27T19:15:48.367Z",
          "LastModifiedDate": "2024-08-26T21:35:09.31Z"
        },
        {
          "VulnerabilityID": "CVE-2021-37600",
          "VendorIDs": [
            "DLA-3782-1"
          ],
          "PkgID": "libsmartcols1@2.33.1-0.1",
          "PkgName": "libsmartcols1",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libsmartcols1@2.33.1-0.1?arch=amd64\u0026distro=debian-10.13",
            "UID": "40e82eee26aec690"
          },
          "InstalledVersion": "2.33.1-0.1",
          "FixedVersion": "2.33.1-0.1+deb10u1",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2021-37600",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "util-linux: integer overflow can lead to buffer overflow in get_sem_elements() in sys-utils/ipcutils.c",
          "Description": "An integer overflow in util-linux through 2.37.1 can potentially cause a buffer overflow if an attacker were able to use system resources in a way that leads to a large number in the /proc/sysvipc/sem file. NOTE: this is unexploitable in GNU C Library environments, and possibly in all realistic environments.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-190"
          ],
          "VendorSeverity": {
            "amazon": 1,
            "cbl-mariner": 2,
            "nvd": 2,
            "photon": 2,
            "redhat": 1,
            "ubuntu": 1
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:L/AC:H/Au:N/C:N/I:N/A:P",
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
              "V2Score": 1.2,
              "V3Score": 5.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:H",
              "V3Score": 4.7
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2021-37600",
            "https://github.com/karelzak/util-linux/commit/1c9143d0c1f979c3daf10e1c37b5b1e916c22a1c",
            "https://github.com/karelzak/util-linux/issues/1395",
            "https://lists.debian.org/debian-lts-announce/2024/04/msg00005.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-37600",
            "https://security.gentoo.org/glsa/202401-08",
            "https://security.netapp.com/advisory/ntap-20210902-0002/",
            "https://www.cve.org/CVERecord?id=CVE-2021-37600"
          ],
          "PublishedDate": "2021-07-30T14:15:18.737Z",
          "LastModifiedDate": "2024-08-04T02:15:24.44Z"
        },
        {
          "VulnerabilityID": "CVE-2022-0563",
          "PkgID": "libsmartcols1@2.33.1-0.1",
          "PkgName": "libsmartcols1",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libsmartcols1@2.33.1-0.1?arch=amd64\u0026distro=debian-10.13",
            "UID": "40e82eee26aec690"
          },
          "InstalledVersion": "2.33.1-0.1",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2022-0563",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "util-linux: partial disclosure of arbitrary files in chfn and chsh when compiled with libreadline",
          "Description": "A flaw was found in the util-linux chfn and chsh utilities when compiled with Readline support. The Readline library uses an \"INPUTRC\" environment variable to get a path to the library config file. When the library cannot parse the specified file, it prints an error message containing data from the file. This flaw allows an unprivileged user to read root-owned files, potentially leading to privilege escalation. This flaw affects util-linux versions prior to 2.37.4.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-209"
          ],
          "VendorSeverity": {
            "amazon": 2,
            "cbl-mariner": 2,
            "debian": 1,
            "nvd": 2,
            "photon": 2,
            "redhat": 2
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:L/AC:M/Au:N/C:P/I:N/A:N",
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
              "V2Score": 1.9,
              "V3Score": 5.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
              "V3Score": 5.5
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2022-0563",
            "https://blog.trailofbits.com/2023/02/16/suid-logic-bug-linux-readline/",
            "https://lore.kernel.org/util-linux/20220214110609.msiwlm457ngoic6w%40ws.net.home/T/#u",
            "https://lore.kernel.org/util-linux/20220214110609.msiwlm457ngoic6w@ws.net.home/T/#u",
            "https://nvd.nist.gov/vuln/detail/CVE-2022-0563",
            "https://security.gentoo.org/glsa/202401-08",
            "https://security.netapp.com/advisory/ntap-20220331-0002/",
            "https://www.cve.org/CVERecord?id=CVE-2022-0563"
          ],
          "PublishedDate": "2022-02-21T19:15:08.393Z",
          "LastModifiedDate": "2024-01-07T09:15:08.713Z"
        },
        {
          "VulnerabilityID": "CVE-2019-19603",
          "PkgID": "libsqlite3-0@3.27.2-3+deb10u2",
          "PkgName": "libsqlite3-0",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libsqlite3-0@3.27.2-3%2Bdeb10u2?arch=amd64\u0026distro=debian-10.13",
            "UID": "7d9a841f9a1833b3"
          },
          "InstalledVersion": "3.27.2-3+deb10u2",
          "Status": "will_not_fix",
          "Layer": {
            "Digest": "sha256:8f777578c172d018077d3dc22d6654911fff60066097943fe8c4697ecf8aac35",
            "DiffID": "sha256:3054512b6f71055cacea93ed12462e1ddc7f54988d9c7b51d10a5144d99ff501"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2019-19603",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "sqlite: mishandling of certain SELECT statements with non-existent VIEW can lead to DoS",
          "Description": "SQLite 3.30.1 mishandles certain SELECT statements with a nonexistent VIEW, leading to an application crash.",
          "Severity": "HIGH",
          "VendorSeverity": {
            "alma": 2,
            "nvd": 3,
            "oracle-oval": 2,
            "photon": 3,
            "redhat": 2,
            "ubuntu": 1
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V2Score": 5,
              "V3Score": 7.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 7.5
            }
          },
          "References": [
            "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2019-13750.json",
            "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2019-13751.json",
            "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2019-19603.json",
            "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2019-5827.json",
            "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2020-13435.json",
            "https://access.redhat.com/security/cve/CVE-2019-19603",
            "https://cert-portal.siemens.com/productcert/pdf/ssa-389290.pdf",
            "https://errata.almalinux.org/8/ALSA-2021-4396.html",
            "https://github.com/sqlite/sqlite/commit/527cbd4a104cb93bf3994b3dd3619a6299a78b13",
            "https://linux.oracle.com/cve/CVE-2019-19603.html",
            "https://linux.oracle.com/errata/ELSA-2021-4396.html",
            "https://lists.apache.org/thread.html/rc713534b10f9daeee2e0990239fa407e2118e4aa9e88a7041177497c%40%3Cissues.guacamole.apache.org%3E",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-19603",
            "https://security.netapp.com/advisory/ntap-20191223-0001/",
            "https://ubuntu.com/security/notices/USN-4394-1",
            "https://usn.ubuntu.com/4394-1/",
            "https://www.cve.org/CVERecord?id=CVE-2019-19603",
            "https://www.oracle.com/security-alerts/cpuapr2020.html",
            "https://www.sqlite.org/"
          ],
          "PublishedDate": "2019-12-09T19:15:14.71Z",
          "LastModifiedDate": "2023-11-07T03:07:43.34Z"
        },
        {
          "VulnerabilityID": "CVE-2021-31239",
          "PkgID": "libsqlite3-0@3.27.2-3+deb10u2",
          "PkgName": "libsqlite3-0",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libsqlite3-0@3.27.2-3%2Bdeb10u2?arch=amd64\u0026distro=debian-10.13",
            "UID": "7d9a841f9a1833b3"
          },
          "InstalledVersion": "3.27.2-3+deb10u2",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8f777578c172d018077d3dc22d6654911fff60066097943fe8c4697ecf8aac35",
            "DiffID": "sha256:3054512b6f71055cacea93ed12462e1ddc7f54988d9c7b51d10a5144d99ff501"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2021-31239",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "sqlite: denial of service via the appendvfs.c function",
          "Description": "An issue found in SQLite SQLite3 v.3.35.4 that allows a remote attacker to cause a denial of service via the appendvfs.c function.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-125"
          ],
          "VendorSeverity": {
            "bitnami": 3,
            "nvd": 3,
            "photon": 3,
            "redhat": 2
          },
          "CVSS": {
            "bitnami": {
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
            "https://access.redhat.com/security/cve/CVE-2021-31239",
            "https://github.com/Tsiming/Vulnerabilities/blob/main/SQLite/CVE-2021-31239",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/73XUIHJ6UT75VFPDPLJOXJON7MVIKVZI/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/FXFL4TDAH72PRCPD5UPZMJMKIMVOPLTI/",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-31239",
            "https://security.gentoo.org/glsa/202311-03",
            "https://security.netapp.com/advisory/ntap-20230609-0010/",
            "https://www.cve.org/CVERecord?id=CVE-2021-31239",
            "https://www.sqlite.org/cves.html",
            "https://www.sqlite.org/forum/forumpost/d9fce1a89b"
          ],
          "PublishedDate": "2023-05-09T02:15:08.907Z",
          "LastModifiedDate": "2023-11-24T14:15:08.023Z"
        },
        {
          "VulnerabilityID": "CVE-2023-7104",
          "PkgID": "libsqlite3-0@3.27.2-3+deb10u2",
          "PkgName": "libsqlite3-0",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libsqlite3-0@3.27.2-3%2Bdeb10u2?arch=amd64\u0026distro=debian-10.13",
            "UID": "7d9a841f9a1833b3"
          },
          "InstalledVersion": "3.27.2-3+deb10u2",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8f777578c172d018077d3dc22d6654911fff60066097943fe8c4697ecf8aac35",
            "DiffID": "sha256:3054512b6f71055cacea93ed12462e1ddc7f54988d9c7b51d10a5144d99ff501"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-7104",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "sqlite: heap-buffer-overflow at sessionfuzz",
          "Description": "A vulnerability was found in SQLite SQLite3 up to 3.43.0 and classified as critical. This issue affects the function sessionReadRecord of the file ext/session/sqlite3session.c of the component make alltest Handler. The manipulation leads to heap-based buffer overflow. It is recommended to apply a patch to fix this issue. The associated identifier of this vulnerability is VDB-248999.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-119",
            "CWE-122"
          ],
          "VendorSeverity": {
            "alma": 2,
            "amazon": 3,
            "bitnami": 3,
            "cbl-mariner": 2,
            "nvd": 3,
            "oracle-oval": 2,
            "photon": 3,
            "redhat": 2,
            "rocky": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "bitnami": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
              "V3Score": 7.3
            },
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
              "V3Score": 7.3
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
              "V3Score": 7.3
            }
          },
          "References": [
            "https://access.redhat.com/errata/RHSA-2024:0465",
            "https://access.redhat.com/security/cve/CVE-2023-7104",
            "https://bugzilla.redhat.com/2256194",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2256194",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-7104",
            "https://errata.almalinux.org/9/ALSA-2024-0465.html",
            "https://errata.rockylinux.org/RLSA-2024:0253",
            "https://linux.oracle.com/cve/CVE-2023-7104.html",
            "https://linux.oracle.com/errata/ELSA-2024-0465.html",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/AYONA2XSNFMXLAW4IHLFI5UVV3QRNG5K/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/D6C2HN4T2S6GYNTAUXLH45LQZHK7QPHP/",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-7104",
            "https://security.netapp.com/advisory/ntap-20240112-0008/",
            "https://sqlite.org/forum/forumpost/5bcbf4571c",
            "https://sqlite.org/src/info/0e4e7a05c4204b47",
            "https://ubuntu.com/security/notices/USN-6566-1",
            "https://ubuntu.com/security/notices/USN-6566-2",
            "https://vuldb.com/?ctiid.248999",
            "https://vuldb.com/?id.248999",
            "https://www.cve.org/CVERecord?id=CVE-2023-7104"
          ],
          "PublishedDate": "2023-12-29T10:15:13.89Z",
          "LastModifiedDate": "2024-05-17T02:34:09.853Z"
        },
        {
          "VulnerabilityID": "CVE-2019-19645",
          "PkgID": "libsqlite3-0@3.27.2-3+deb10u2",
          "PkgName": "libsqlite3-0",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libsqlite3-0@3.27.2-3%2Bdeb10u2?arch=amd64\u0026distro=debian-10.13",
            "UID": "7d9a841f9a1833b3"
          },
          "InstalledVersion": "3.27.2-3+deb10u2",
          "Status": "will_not_fix",
          "Layer": {
            "Digest": "sha256:8f777578c172d018077d3dc22d6654911fff60066097943fe8c4697ecf8aac35",
            "DiffID": "sha256:3054512b6f71055cacea93ed12462e1ddc7f54988d9c7b51d10a5144d99ff501"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2019-19645",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "sqlite: infinite recursion via certain types of self-referential views in conjunction with ALTER TABLE statements",
          "Description": "alter.c in SQLite through 3.30.1 allows attackers to trigger infinite recursion via certain types of self-referential views in conjunction with ALTER TABLE statements.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-674"
          ],
          "VendorSeverity": {
            "azure": 2,
            "nvd": 2,
            "photon": 2,
            "redhat": 2,
            "ubuntu": 1
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:L/AC:L/Au:N/C:N/I:N/A:P",
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
              "V2Score": 2.1,
              "V3Score": 5.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 5.5
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2019-19645",
            "https://cert-portal.siemens.com/productcert/pdf/ssa-389290.pdf",
            "https://github.com/sqlite/sqlite/commit/38096961c7cd109110ac21d3ed7dad7e0cb0ae06",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-19645",
            "https://security.netapp.com/advisory/ntap-20191223-0001/",
            "https://ubuntu.com/security/notices/USN-4394-1",
            "https://usn.ubuntu.com/4394-1/",
            "https://www.cve.org/CVERecord?id=CVE-2019-19645",
            "https://www.oracle.com/security-alerts/cpuapr2020.html",
            "https://www.tenable.com/security/tns-2021-14"
          ],
          "PublishedDate": "2019-12-09T16:15:10.407Z",
          "LastModifiedDate": "2022-04-15T16:14:43.823Z"
        },
        {
          "VulnerabilityID": "CVE-2019-19924",
          "PkgID": "libsqlite3-0@3.27.2-3+deb10u2",
          "PkgName": "libsqlite3-0",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libsqlite3-0@3.27.2-3%2Bdeb10u2?arch=amd64\u0026distro=debian-10.13",
            "UID": "7d9a841f9a1833b3"
          },
          "InstalledVersion": "3.27.2-3+deb10u2",
          "Status": "will_not_fix",
          "Layer": {
            "Digest": "sha256:8f777578c172d018077d3dc22d6654911fff60066097943fe8c4697ecf8aac35",
            "DiffID": "sha256:3054512b6f71055cacea93ed12462e1ddc7f54988d9c7b51d10a5144d99ff501"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2019-19924",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "sqlite: incorrect sqlite3WindowRewrite() error handling leads to mishandling certain parser-tree rewriting",
          "Description": "SQLite 3.30.1 mishandles certain parser-tree rewriting, related to expr.c, vdbeaux.c, and window.c. This is caused by incorrect sqlite3WindowRewrite() error handling.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-755"
          ],
          "VendorSeverity": {
            "nvd": 2,
            "oracle-oval": 2,
            "photon": 2,
            "redhat": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:N/I:P/A:N",
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
              "V2Score": 5,
              "V3Score": 5.3
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
              "V3Score": 5.3
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2019-19924",
            "https://cert-portal.siemens.com/productcert/pdf/ssa-389290.pdf",
            "https://github.com/sqlite/sqlite/commit/8654186b0236d556aa85528c2573ee0b6ab71be3",
            "https://linux.oracle.com/cve/CVE-2019-19924.html",
            "https://linux.oracle.com/errata/ELSA-2020-1810.html",
            "https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b%40%3Cissues.bookkeeper.apache.org%3E",
            "https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4%40%3Cissues.bookkeeper.apache.org%3E",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-19924",
            "https://security.netapp.com/advisory/ntap-20200114-0003/",
            "https://ubuntu.com/security/notices/USN-4298-1",
            "https://usn.ubuntu.com/4298-1/",
            "https://www.cve.org/CVERecord?id=CVE-2019-19924",
            "https://www.oracle.com/security-alerts/cpuapr2020.html"
          ],
          "PublishedDate": "2019-12-24T16:15:11.37Z",
          "LastModifiedDate": "2023-11-07T03:07:52.213Z"
        },
        {
          "VulnerabilityID": "CVE-2020-13631",
          "PkgID": "libsqlite3-0@3.27.2-3+deb10u2",
          "PkgName": "libsqlite3-0",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libsqlite3-0@3.27.2-3%2Bdeb10u2?arch=amd64\u0026distro=debian-10.13",
            "UID": "7d9a841f9a1833b3"
          },
          "InstalledVersion": "3.27.2-3+deb10u2",
          "Status": "will_not_fix",
          "Layer": {
            "Digest": "sha256:8f777578c172d018077d3dc22d6654911fff60066097943fe8c4697ecf8aac35",
            "DiffID": "sha256:3054512b6f71055cacea93ed12462e1ddc7f54988d9c7b51d10a5144d99ff501"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2020-13631",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "sqlite: Virtual table can be renamed into the name of one of its shadow tables",
          "Description": "SQLite before 3.32.0 allows a virtual table to be renamed to the name of one of its shadow tables, related to alter.c and build.c.",
          "Severity": "MEDIUM",
          "VendorSeverity": {
            "alma": 2,
            "azure": 2,
            "bitnami": 2,
            "nvd": 2,
            "oracle-oval": 2,
            "photon": 2,
            "redhat": 2,
            "ubuntu": 1
          },
          "CVSS": {
            "bitnami": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",
              "V3Score": 5.5
            },
            "nvd": {
              "V2Vector": "AV:L/AC:L/Au:N/C:N/I:P/A:N",
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",
              "V2Score": 2.1,
              "V3Score": 5.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",
              "V3Score": 5.5
            }
          },
          "References": [
            "http://seclists.org/fulldisclosure/2020/Dec/32",
            "http://seclists.org/fulldisclosure/2020/Nov/19",
            "http://seclists.org/fulldisclosure/2020/Nov/20",
            "http://seclists.org/fulldisclosure/2020/Nov/22",
            "https://access.redhat.com/security/cve/CVE-2020-13631",
            "https://bugs.chromium.org/p/chromium/issues/detail?id=1080459",
            "https://cert-portal.siemens.com/productcert/pdf/ssa-389290.pdf",
            "https://errata.almalinux.org/8/ALSA-2021-1968.html",
            "https://linux.oracle.com/cve/CVE-2020-13631.html",
            "https://linux.oracle.com/errata/ELSA-2020-4442.html",
            "https://lists.apache.org/thread.html/rc713534b10f9daeee2e0990239fa407e2118e4aa9e88a7041177497c%40%3Cissues.guacamole.apache.org%3E",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/L7KXQWHIY2MQP4LNM6ODWJENMXYYQYBN/",
            "https://nvd.nist.gov/vuln/detail/CVE-2020-13631",
            "https://security.FreeBSD.org/advisories/FreeBSD-SA-20:22.sqlite.asc",
            "https://security.gentoo.org/glsa/202007-26",
            "https://security.netapp.com/advisory/ntap-20200608-0002/",
            "https://sqlite.org/src/info/eca0ba2cf4c0fdf7",
            "https://support.apple.com/kb/HT211843",
            "https://support.apple.com/kb/HT211844",
            "https://support.apple.com/kb/HT211850",
            "https://support.apple.com/kb/HT211931",
            "https://support.apple.com/kb/HT211935",
            "https://support.apple.com/kb/HT211952",
            "https://ubuntu.com/security/notices/USN-4394-1",
            "https://usn.ubuntu.com/4394-1/",
            "https://www.cve.org/CVERecord?id=CVE-2020-13631",
            "https://www.oracle.com/security-alerts/cpujul2020.html",
            "https://www.oracle.com/security-alerts/cpuoct2020.html"
          ],
          "PublishedDate": "2020-05-27T15:15:12.947Z",
          "LastModifiedDate": "2023-11-07T03:16:46.88Z"
        },
        {
          "VulnerabilityID": "CVE-2019-19244",
          "PkgID": "libsqlite3-0@3.27.2-3+deb10u2",
          "PkgName": "libsqlite3-0",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libsqlite3-0@3.27.2-3%2Bdeb10u2?arch=amd64\u0026distro=debian-10.13",
            "UID": "7d9a841f9a1833b3"
          },
          "InstalledVersion": "3.27.2-3+deb10u2",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8f777578c172d018077d3dc22d6654911fff60066097943fe8c4697ecf8aac35",
            "DiffID": "sha256:3054512b6f71055cacea93ed12462e1ddc7f54988d9c7b51d10a5144d99ff501"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2019-19244",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "sqlite: allows a crash if a sub-select uses both DISTINCT and window functions and also has certain ORDER BY usage",
          "Description": "sqlite3Select in select.c in SQLite 3.30.1 allows a crash if a sub-select uses both DISTINCT and window functions, and also has certain ORDER BY usage.",
          "Severity": "LOW",
          "VendorSeverity": {
            "debian": 1,
            "nvd": 3,
            "photon": 3,
            "redhat": 1,
            "ubuntu": 2
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V2Score": 5,
              "V3Score": 7.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 7.5
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2019-19244",
            "https://cert-portal.siemens.com/productcert/pdf/ssa-389290.pdf",
            "https://github.com/sqlite/sqlite/commit/e59c562b3f6894f84c715772c4b116d7b5c01348",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-19244",
            "https://ubuntu.com/security/notices/USN-4205-1",
            "https://usn.ubuntu.com/4205-1/",
            "https://www.cve.org/CVERecord?id=CVE-2019-19244",
            "https://www.oracle.com/security-alerts/cpuapr2020.html"
          ],
          "PublishedDate": "2019-11-25T20:15:11.407Z",
          "LastModifiedDate": "2022-04-15T16:12:54.09Z"
        },
        {
          "VulnerabilityID": "CVE-2020-11656",
          "PkgID": "libsqlite3-0@3.27.2-3+deb10u2",
          "PkgName": "libsqlite3-0",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libsqlite3-0@3.27.2-3%2Bdeb10u2?arch=amd64\u0026distro=debian-10.13",
            "UID": "7d9a841f9a1833b3"
          },
          "InstalledVersion": "3.27.2-3+deb10u2",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8f777578c172d018077d3dc22d6654911fff60066097943fe8c4697ecf8aac35",
            "DiffID": "sha256:3054512b6f71055cacea93ed12462e1ddc7f54988d9c7b51d10a5144d99ff501"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2020-11656",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "sqlite: use-after-free in the ALTER TABLE implementation",
          "Description": "In SQLite through 3.31.1, the ALTER TABLE implementation has a use-after-free, as demonstrated by an ORDER BY clause that belongs to a compound SELECT statement.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-416"
          ],
          "VendorSeverity": {
            "azure": 4,
            "bitnami": 4,
            "debian": 1,
            "nvd": 4,
            "photon": 4,
            "redhat": 2
          },
          "CVSS": {
            "bitnami": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
              "V3Score": 9.8
            },
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
              "V2Score": 7.5,
              "V3Score": 9.8
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
              "V3Score": 8.8
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2020-11656",
            "https://cert-portal.siemens.com/productcert/pdf/ssa-389290.pdf",
            "https://nvd.nist.gov/vuln/detail/CVE-2020-11656",
            "https://security.FreeBSD.org/advisories/FreeBSD-SA-20:22.sqlite.asc",
            "https://security.gentoo.org/glsa/202007-26",
            "https://security.netapp.com/advisory/ntap-20200416-0001/",
            "https://www.cve.org/CVERecord?id=CVE-2020-11656",
            "https://www.oracle.com/security-alerts/cpuApr2021.html",
            "https://www.oracle.com/security-alerts/cpujan2021.html",
            "https://www.oracle.com/security-alerts/cpujul2020.html",
            "https://www.oracle.com/security-alerts/cpuoct2020.html",
            "https://www.sqlite.org/src/info/d09f8c3621d5f7f8",
            "https://www.tenable.com/security/tns-2021-14",
            "https://www3.sqlite.org/cgi/src/info/b64674919f673602"
          ],
          "PublishedDate": "2020-04-09T03:15:11.41Z",
          "LastModifiedDate": "2022-04-08T10:34:53.773Z"
        },
        {
          "VulnerabilityID": "CVE-2021-36690",
          "PkgID": "libsqlite3-0@3.27.2-3+deb10u2",
          "PkgName": "libsqlite3-0",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libsqlite3-0@3.27.2-3%2Bdeb10u2?arch=amd64\u0026distro=debian-10.13",
            "UID": "7d9a841f9a1833b3"
          },
          "InstalledVersion": "3.27.2-3+deb10u2",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8f777578c172d018077d3dc22d6654911fff60066097943fe8c4697ecf8aac35",
            "DiffID": "sha256:3054512b6f71055cacea93ed12462e1ddc7f54988d9c7b51d10a5144d99ff501"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2021-36690",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "A segmentation fault can occur in the sqlite3.exe command-line compone ...",
          "Description": "A segmentation fault can occur in the sqlite3.exe command-line component of SQLite 3.36.0 via the idxGetTableInfo function when there is a crafted SQL query. NOTE: the vendor disputes the relevance of this report because a sqlite3.exe user already has full privileges (e.g., is intentionally allowed to execute commands). This report does NOT imply any problem in the SQLite library.",
          "Severity": "LOW",
          "VendorSeverity": {
            "bitnami": 3,
            "cbl-mariner": 3,
            "debian": 1,
            "nvd": 3,
            "ubuntu": 1
          },
          "CVSS": {
            "bitnami": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 7.5
            },
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V2Score": 5,
              "V3Score": 7.5
            }
          },
          "References": [
            "http://seclists.org/fulldisclosure/2022/Oct/28",
            "http://seclists.org/fulldisclosure/2022/Oct/39",
            "http://seclists.org/fulldisclosure/2022/Oct/41",
            "http://seclists.org/fulldisclosure/2022/Oct/47",
            "http://seclists.org/fulldisclosure/2022/Oct/49",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-36690",
            "https://support.apple.com/kb/HT213446",
            "https://support.apple.com/kb/HT213486",
            "https://support.apple.com/kb/HT213487",
            "https://support.apple.com/kb/HT213488",
            "https://ubuntu.com/security/notices/USN-5403-1",
            "https://www.cve.org/CVERecord?id=CVE-2021-36690",
            "https://www.sqlite.org/forum/forumpost/718c0a8d17"
          ],
          "PublishedDate": "2021-08-24T14:15:09.797Z",
          "LastModifiedDate": "2024-08-04T01:15:46.013Z"
        },
        {
          "VulnerabilityID": "CVE-2021-45346",
          "PkgID": "libsqlite3-0@3.27.2-3+deb10u2",
          "PkgName": "libsqlite3-0",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libsqlite3-0@3.27.2-3%2Bdeb10u2?arch=amd64\u0026distro=debian-10.13",
            "UID": "7d9a841f9a1833b3"
          },
          "InstalledVersion": "3.27.2-3+deb10u2",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8f777578c172d018077d3dc22d6654911fff60066097943fe8c4697ecf8aac35",
            "DiffID": "sha256:3054512b6f71055cacea93ed12462e1ddc7f54988d9c7b51d10a5144d99ff501"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2021-45346",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "sqlite: crafted SQL query allows a malicious user to obtain sensitive information",
          "Description": "A Memory Leak vulnerability exists in SQLite Project SQLite3 3.35.1 and 3.37.0 via maliciously crafted SQL Queries (made via editing the Database File), it is possible to query a record, and leak subsequent bytes of memory that extend beyond the record, which could let a malicious user obtain sensitive information. NOTE: The developer disputes this as a vulnerability stating that If you give SQLite a corrupted database file and submit a query against the database, it might read parts of the database that you did not intend or expect.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-401"
          ],
          "VendorSeverity": {
            "bitnami": 2,
            "debian": 1,
            "nvd": 2,
            "redhat": 1
          },
          "CVSS": {
            "bitnami": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
              "V3Score": 4.3
            },
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:S/C:P/I:N/A:N",
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
              "V2Score": 4,
              "V3Score": 4.3
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
              "V3Score": 4.3
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2021-45346",
            "https://github.com/guyinatuxedo/sqlite3_record_leaking",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-45346",
            "https://security.netapp.com/advisory/ntap-20220303-0001/",
            "https://sqlite.org/forum/forumpost/056d557c2f8c452ed5",
            "https://sqlite.org/forum/forumpost/53de8864ba114bf6",
            "https://www.cve.org/CVERecord?id=CVE-2021-45346",
            "https://www.sqlite.org/cves.html#status_of_recent_sqlite_cves"
          ],
          "PublishedDate": "2022-02-14T19:15:07.793Z",
          "LastModifiedDate": "2024-08-04T05:15:42.307Z"
        },
        {
          "VulnerabilityID": "CVE-2022-35737",
          "PkgID": "libsqlite3-0@3.27.2-3+deb10u2",
          "PkgName": "libsqlite3-0",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libsqlite3-0@3.27.2-3%2Bdeb10u2?arch=amd64\u0026distro=debian-10.13",
            "UID": "7d9a841f9a1833b3"
          },
          "InstalledVersion": "3.27.2-3+deb10u2",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8f777578c172d018077d3dc22d6654911fff60066097943fe8c4697ecf8aac35",
            "DiffID": "sha256:3054512b6f71055cacea93ed12462e1ddc7f54988d9c7b51d10a5144d99ff501"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2022-35737",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "sqlite: an array-bounds overflow if billions of bytes are used in a string argument to a C API",
          "Description": "SQLite 1.0.12 through 3.39.x before 3.39.2 sometimes allows an array-bounds overflow if billions of bytes are used in a string argument to a C API.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-129"
          ],
          "VendorSeverity": {
            "alma": 2,
            "amazon": 3,
            "bitnami": 3,
            "cbl-mariner": 3,
            "debian": 1,
            "ghsa": 3,
            "nvd": 3,
            "oracle-oval": 2,
            "photon": 3,
            "redhat": 2,
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
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 5.9
            }
          },
          "References": [
            "https://access.redhat.com/errata/RHSA-2023:0339",
            "https://access.redhat.com/security/cve/CVE-2022-35737",
            "https://blog.trailofbits.com/2022/10/25/sqlite-vulnerability-july-2022-library-api",
            "https://blog.trailofbits.com/2022/10/25/sqlite-vulnerability-july-2022-library-api/",
            "https://bugzilla.redhat.com/2110291",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2110291",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-35737",
            "https://errata.almalinux.org/9/ALSA-2023-0339.html",
            "https://errata.rockylinux.org/RLSA-2023:0339",
            "https://github.com/rusqlite/rusqlite",
            "https://kb.cert.org/vuls/id/720344",
            "https://linux.oracle.com/cve/CVE-2022-35737.html",
            "https://linux.oracle.com/errata/ELSA-2023-0339.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2022-35737",
            "https://rustsec.org/advisories/RUSTSEC-2022-0090.html",
            "https://security.gentoo.org/glsa/202210-40",
            "https://security.netapp.com/advisory/ntap-20220915-0009",
            "https://security.netapp.com/advisory/ntap-20220915-0009/",
            "https://sqlite.org/releaselog/3_39_2.html",
            "https://ubuntu.com/security/notices/USN-5712-1",
            "https://ubuntu.com/security/notices/USN-5716-1",
            "https://ubuntu.com/security/notices/USN-5716-2",
            "https://www.cve.org/CVERecord?id=CVE-2022-35737",
            "https://www.sqlite.org/cves.html",
            "https://www.sqlite.org/releaselog/3_39_2.html"
          ],
          "PublishedDate": "2022-08-03T06:15:07.69Z",
          "LastModifiedDate": "2024-03-27T16:05:26.36Z"
        },
        {
          "VulnerabilityID": "CVE-2022-1304",
          "PkgID": "libss2@1.44.5-1+deb10u3",
          "PkgName": "libss2",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libss2@1.44.5-1%2Bdeb10u3?arch=amd64\u0026distro=debian-10.13",
            "UID": "ef2aceb6e1da5dd4"
          },
          "InstalledVersion": "1.44.5-1+deb10u3",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2022-1304",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "e2fsprogs: out-of-bounds read/write via crafted filesystem",
          "Description": "An out-of-bounds read/write vulnerability was found in e2fsprogs 1.46.5. This issue leads to a segmentation fault and possibly arbitrary code execution via a specially crafted filesystem.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-125",
            "CWE-787"
          ],
          "VendorSeverity": {
            "alma": 2,
            "amazon": 2,
            "cbl-mariner": 3,
            "nvd": 3,
            "oracle-oval": 2,
            "photon": 3,
            "redhat": 2,
            "rocky": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
              "V2Score": 6.8,
              "V3Score": 7.8
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:H",
              "V3Score": 5.8
            }
          },
          "References": [
            "https://access.redhat.com/errata/RHSA-2022:8361",
            "https://access.redhat.com/security/cve/CVE-2022-1304",
            "https://bugzilla.redhat.com/2069726",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2069726",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-1304",
            "https://errata.almalinux.org/9/ALSA-2022-8361.html",
            "https://errata.rockylinux.org/RLSA-2022:8361",
            "https://linux.oracle.com/cve/CVE-2022-1304.html",
            "https://linux.oracle.com/errata/ELSA-2022-8361.html",
            "https://marc.info/?l=linux-ext4\u0026m=165056234501732\u0026w=2",
            "https://nvd.nist.gov/vuln/detail/CVE-2022-1304",
            "https://ubuntu.com/security/notices/USN-5464-1",
            "https://www.cve.org/CVERecord?id=CVE-2022-1304"
          ],
          "PublishedDate": "2022-04-14T21:15:08.49Z",
          "LastModifiedDate": "2023-11-07T03:41:53.02Z"
        },
        {
          "VulnerabilityID": "CVE-2023-3446",
          "VendorIDs": [
            "DLA-3530-1"
          ],
          "PkgID": "libssl1.1@1.1.1n-0+deb10u5",
          "PkgName": "libssl1.1",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libssl1.1@1.1.1n-0%2Bdeb10u5?arch=amd64\u0026distro=debian-10.13",
            "UID": "a38d42590ed16a34"
          },
          "InstalledVersion": "1.1.1n-0+deb10u5",
          "FixedVersion": "1.1.1n-0+deb10u6",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:824416e234237961c9c5d4f41dfe5b295a3c35a671ee52889bfb08d8e257ec4c",
            "DiffID": "sha256:ae2d55769c5efcb6230d27c88eef033128fa1d238bdafe50812402f471152bb7"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-3446",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "openssl: Excessive time spent checking DH keys and parameters",
          "Description": "Issue summary: Checking excessively long DH keys or parameters may be very slow.\n\nImpact summary: Applications that use the functions DH_check(), DH_check_ex()\nor EVP_PKEY_param_check() to check a DH key or DH parameters may experience long\ndelays. Where the key or parameters that are being checked have been obtained\nfrom an untrusted source this may lead to a Denial of Service.\n\nThe function DH_check() performs various checks on DH parameters. One of those\nchecks confirms that the modulus ('p' parameter) is not too large. Trying to use\na very large modulus is slow and OpenSSL will not normally use a modulus which\nis over 10,000 bits in length.\n\nHowever the DH_check() function checks numerous aspects of the key or parameters\nthat have been supplied. Some of those checks use the supplied modulus value\neven if it has already been found to be too large.\n\nAn application that calls DH_check() and supplies a key or parameters obtained\nfrom an untrusted source could be vulernable to a Denial of Service attack.\n\nThe function DH_check() is itself called by a number of other OpenSSL functions.\nAn application calling any of those other functions may similarly be affected.\nThe other functions affected by this are DH_check_ex() and\nEVP_PKEY_param_check().\n\nAlso vulnerable are the OpenSSL dhparam and pkeyparam command line applications\nwhen using the '-check' option.\n\nThe OpenSSL SSL/TLS implementation is not affected by this issue.\nThe OpenSSL 3.0 and 3.1 FIPS providers are not affected by this issue.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-1333"
          ],
          "VendorSeverity": {
            "alma": 1,
            "amazon": 2,
            "cbl-mariner": 2,
            "nvd": 2,
            "oracle-oval": 1,
            "photon": 2,
            "redhat": 1,
            "rocky": 3,
            "ubuntu": 1
          },
          "CVSS": {
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
            "http://www.openwall.com/lists/oss-security/2023/07/19/4",
            "http://www.openwall.com/lists/oss-security/2023/07/19/5",
            "http://www.openwall.com/lists/oss-security/2023/07/19/6",
            "http://www.openwall.com/lists/oss-security/2023/07/31/1",
            "http://www.openwall.com/lists/oss-security/2024/05/16/1",
            "https://access.redhat.com/errata/RHSA-2024:2447",
            "https://access.redhat.com/security/cve/CVE-2023-3446",
            "https://bugzilla.redhat.com/2223016",
            "https://bugzilla.redhat.com/2224962",
            "https://bugzilla.redhat.com/2227852",
            "https://bugzilla.redhat.com/2248616",
            "https://bugzilla.redhat.com/2257571",
            "https://bugzilla.redhat.com/2258502",
            "https://bugzilla.redhat.com/2259944",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2224962",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2257582",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2257583",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2258677",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2258688",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2258691",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2258694",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2258700",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-36763",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-36764",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-3446",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-45229",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-45231",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-45232",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-45233",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-45235",
            "https://errata.almalinux.org/9/ALSA-2024-2447.html",
            "https://errata.rockylinux.org/RLSA-2024:2264",
            "https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=1fa20cf2f506113c761777127a38bce5068740eb",
            "https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=8780a896543a654e757db1b9396383f9d8095528",
            "https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=9a0a4d3c1e7138915563c0df4fe6a3f9377b839c",
            "https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=fc9867c1e03c22ebf56943be205202e576aabf23",
            "https://linux.oracle.com/cve/CVE-2023-3446.html",
            "https://linux.oracle.com/errata/ELSA-2024-2447.html",
            "https://lists.debian.org/debian-lts-announce/2023/08/msg00019.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-3446",
            "https://security.gentoo.org/glsa/202402-08",
            "https://security.netapp.com/advisory/ntap-20230803-0011/",
            "https://ubuntu.com/security/notices/USN-6435-1",
            "https://ubuntu.com/security/notices/USN-6435-2",
            "https://ubuntu.com/security/notices/USN-6450-1",
            "https://ubuntu.com/security/notices/USN-6709-1",
            "https://www.cve.org/CVERecord?id=CVE-2023-3446",
            "https://www.openssl.org/news/secadv/20230719.txt"
          ],
          "PublishedDate": "2023-07-19T12:15:10.003Z",
          "LastModifiedDate": "2024-06-10T17:16:12.867Z"
        },
        {
          "VulnerabilityID": "CVE-2023-3817",
          "VendorIDs": [
            "DLA-3530-1"
          ],
          "PkgID": "libssl1.1@1.1.1n-0+deb10u5",
          "PkgName": "libssl1.1",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libssl1.1@1.1.1n-0%2Bdeb10u5?arch=amd64\u0026distro=debian-10.13",
            "UID": "a38d42590ed16a34"
          },
          "InstalledVersion": "1.1.1n-0+deb10u5",
          "FixedVersion": "1.1.1n-0+deb10u6",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:824416e234237961c9c5d4f41dfe5b295a3c35a671ee52889bfb08d8e257ec4c",
            "DiffID": "sha256:ae2d55769c5efcb6230d27c88eef033128fa1d238bdafe50812402f471152bb7"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-3817",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "OpenSSL: Excessive time spent checking DH q parameter value",
          "Description": "Issue summary: Checking excessively long DH keys or parameters may be very slow.\n\nImpact summary: Applications that use the functions DH_check(), DH_check_ex()\nor EVP_PKEY_param_check() to check a DH key or DH parameters may experience long\ndelays. Where the key or parameters that are being checked have been obtained\nfrom an untrusted source this may lead to a Denial of Service.\n\nThe function DH_check() performs various checks on DH parameters. After fixing\nCVE-2023-3446 it was discovered that a large q parameter value can also trigger\nan overly long computation during some of these checks. A correct q value,\nif present, cannot be larger than the modulus p parameter, thus it is\nunnecessary to perform these checks if q is larger than p.\n\nAn application that calls DH_check() and supplies a key or parameters obtained\nfrom an untrusted source could be vulnerable to a Denial of Service attack.\n\nThe function DH_check() is itself called by a number of other OpenSSL functions.\nAn application calling any of those other functions may similarly be affected.\nThe other functions affected by this are DH_check_ex() and\nEVP_PKEY_param_check().\n\nAlso vulnerable are the OpenSSL dhparam and pkeyparam command line applications\nwhen using the \"-check\" option.\n\nThe OpenSSL SSL/TLS implementation is not affected by this issue.\n\nThe OpenSSL 3.0 and 3.1 FIPS providers are not affected by this issue.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-834"
          ],
          "VendorSeverity": {
            "alma": 1,
            "amazon": 2,
            "azure": 2,
            "cbl-mariner": 2,
            "nvd": 2,
            "oracle-oval": 1,
            "photon": 2,
            "redhat": 1,
            "ubuntu": 1
          },
          "CVSS": {
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
            "http://seclists.org/fulldisclosure/2023/Jul/43",
            "http://www.openwall.com/lists/oss-security/2023/07/31/1",
            "http://www.openwall.com/lists/oss-security/2023/09/22/11",
            "http://www.openwall.com/lists/oss-security/2023/09/22/9",
            "http://www.openwall.com/lists/oss-security/2023/11/06/2",
            "https://access.redhat.com/errata/RHSA-2024:2447",
            "https://access.redhat.com/security/cve/CVE-2023-3817",
            "https://bugzilla.redhat.com/2223016",
            "https://bugzilla.redhat.com/2224962",
            "https://bugzilla.redhat.com/2227852",
            "https://bugzilla.redhat.com/2248616",
            "https://bugzilla.redhat.com/2257571",
            "https://bugzilla.redhat.com/2258502",
            "https://bugzilla.redhat.com/2259944",
            "https://errata.almalinux.org/9/ALSA-2024-2447.html",
            "https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=6a1eb62c29db6cb5eec707f9338aee00f44e26f5",
            "https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=869ad69aadd985c7b8ca6f4e5dd0eb274c9f3644",
            "https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=9002fd07327a91f35ba6c1307e71fa6fd4409b7f",
            "https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=91ddeba0f2269b017dc06c46c993a788974b1aa5",
            "https://linux.oracle.com/cve/CVE-2023-3817.html",
            "https://linux.oracle.com/errata/ELSA-2024-2447.html",
            "https://lists.debian.org/debian-lts-announce/2023/08/msg00019.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-3817",
            "https://security.gentoo.org/glsa/202402-08",
            "https://security.netapp.com/advisory/ntap-20230818-0014/",
            "https://security.netapp.com/advisory/ntap-20231027-0008/",
            "https://security.netapp.com/advisory/ntap-20240621-0006/",
            "https://ubuntu.com/security/notices/USN-6435-1",
            "https://ubuntu.com/security/notices/USN-6435-2",
            "https://ubuntu.com/security/notices/USN-6450-1",
            "https://ubuntu.com/security/notices/USN-6709-1",
            "https://www.cve.org/CVERecord?id=CVE-2023-3817",
            "https://www.openssl.org/news/secadv/20230731.txt"
          ],
          "PublishedDate": "2023-07-31T16:15:10.497Z",
          "LastModifiedDate": "2024-06-21T19:15:28.01Z"
        },
        {
          "VulnerabilityID": "CVE-2023-5678",
          "PkgID": "libssl1.1@1.1.1n-0+deb10u5",
          "PkgName": "libssl1.1",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libssl1.1@1.1.1n-0%2Bdeb10u5?arch=amd64\u0026distro=debian-10.13",
            "UID": "a38d42590ed16a34"
          },
          "InstalledVersion": "1.1.1n-0+deb10u5",
          "Status": "fix_deferred",
          "Layer": {
            "Digest": "sha256:824416e234237961c9c5d4f41dfe5b295a3c35a671ee52889bfb08d8e257ec4c",
            "DiffID": "sha256:ae2d55769c5efcb6230d27c88eef033128fa1d238bdafe50812402f471152bb7"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-5678",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "openssl: Generating excessively long X9.42 DH keys or checking excessively long X9.42 DH keys or parameters may be very slow",
          "Description": "Issue summary: Generating excessively long X9.42 DH keys or checking\nexcessively long X9.42 DH keys or parameters may be very slow.\n\nImpact summary: Applications that use the functions DH_generate_key() to\ngenerate an X9.42 DH key may experience long delays.  Likewise, applications\nthat use DH_check_pub_key(), DH_check_pub_key_ex() or EVP_PKEY_public_check()\nto check an X9.42 DH key or X9.42 DH parameters may experience long delays.\nWhere the key or parameters that are being checked have been obtained from\nan untrusted source this may lead to a Denial of Service.\n\nWhile DH_check() performs all the necessary checks (as of CVE-2023-3817),\nDH_check_pub_key() doesn't make any of these checks, and is therefore\nvulnerable for excessively large P and Q parameters.\n\nLikewise, while DH_generate_key() performs a check for an excessively large\nP, it doesn't check for an excessively large Q.\n\nAn application that calls DH_generate_key() or DH_check_pub_key() and\nsupplies a key or parameters obtained from an untrusted source could be\nvulnerable to a Denial of Service attack.\n\nDH_generate_key() and DH_check_pub_key() are also called by a number of\nother OpenSSL functions.  An application calling any of those other\nfunctions may similarly be affected.  The other functions affected by this\nare DH_check_pub_key_ex(), EVP_PKEY_public_check(), and EVP_PKEY_generate().\n\nAlso vulnerable are the OpenSSL pkey command line application when using the\n\"-pubcheck\" option, as well as the OpenSSL genpkey command line application.\n\nThe OpenSSL SSL/TLS implementation is not affected by this issue.\n\nThe OpenSSL 3.0 and 3.1 FIPS providers are not affected by this issue.\n\n",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-754"
          ],
          "VendorSeverity": {
            "alma": 1,
            "amazon": 2,
            "azure": 2,
            "cbl-mariner": 2,
            "nvd": 2,
            "oracle-oval": 1,
            "photon": 2,
            "redhat": 1,
            "ubuntu": 1
          },
          "CVSS": {
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
            "http://www.openwall.com/lists/oss-security/2024/03/11/1",
            "https://access.redhat.com/errata/RHSA-2024:2447",
            "https://access.redhat.com/security/cve/CVE-2023-5678",
            "https://bugzilla.redhat.com/2223016",
            "https://bugzilla.redhat.com/2224962",
            "https://bugzilla.redhat.com/2227852",
            "https://bugzilla.redhat.com/2248616",
            "https://bugzilla.redhat.com/2257571",
            "https://bugzilla.redhat.com/2258502",
            "https://bugzilla.redhat.com/2259944",
            "https://errata.almalinux.org/9/ALSA-2024-2447.html",
            "https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=34efaef6c103d636ab507a0cc34dca4d3aecc055",
            "https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=710fee740904b6290fef0dd5536fbcedbc38ff0c",
            "https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=db925ae2e65d0d925adef429afc37f75bd1c2017",
            "https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=ddeb4b6c6d527e54ce9a99cba785c0f7776e54b6",
            "https://linux.oracle.com/cve/CVE-2023-5678.html",
            "https://linux.oracle.com/errata/ELSA-2024-2447.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-5678",
            "https://security.netapp.com/advisory/ntap-20231130-0010/",
            "https://ubuntu.com/security/notices/USN-6622-1",
            "https://ubuntu.com/security/notices/USN-6632-1",
            "https://ubuntu.com/security/notices/USN-6709-1",
            "https://www.cve.org/CVERecord?id=CVE-2023-5678",
            "https://www.openssl.org/news/secadv/20231106.txt"
          ],
          "PublishedDate": "2023-11-06T16:15:42.67Z",
          "LastModifiedDate": "2024-05-01T18:15:12.393Z"
        },
        {
          "VulnerabilityID": "CVE-2024-0727",
          "PkgID": "libssl1.1@1.1.1n-0+deb10u5",
          "PkgName": "libssl1.1",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libssl1.1@1.1.1n-0%2Bdeb10u5?arch=amd64\u0026distro=debian-10.13",
            "UID": "a38d42590ed16a34"
          },
          "InstalledVersion": "1.1.1n-0+deb10u5",
          "Status": "fix_deferred",
          "Layer": {
            "Digest": "sha256:824416e234237961c9c5d4f41dfe5b295a3c35a671ee52889bfb08d8e257ec4c",
            "DiffID": "sha256:ae2d55769c5efcb6230d27c88eef033128fa1d238bdafe50812402f471152bb7"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-0727",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "openssl: denial of service via null dereference",
          "Description": "Issue summary: Processing a maliciously formatted PKCS12 file may lead OpenSSL\nto crash leading to a potential Denial of Service attack\n\nImpact summary: Applications loading files in the PKCS12 format from untrusted\nsources might terminate abruptly.\n\nA file in PKCS12 format can contain certificates and keys and may come from an\nuntrusted source. The PKCS12 specification allows certain fields to be NULL, but\nOpenSSL does not correctly check for this case. This can lead to a NULL pointer\ndereference that results in OpenSSL crashing. If an application processes PKCS12\nfiles from an untrusted source using the OpenSSL APIs then that application will\nbe vulnerable to this issue.\n\nOpenSSL APIs that are vulnerable to this are: PKCS12_parse(),\nPKCS12_unpack_p7data(), PKCS12_unpack_p7encdata(), PKCS12_unpack_authsafes()\nand PKCS12_newpass().\n\nWe have also fixed a similar issue in SMIME_write_PKCS7(). However since this\nfunction is related to writing data we do not consider it security significant.\n\nThe FIPS modules in 3.2, 3.1 and 3.0 are not affected by this issue.",
          "Severity": "MEDIUM",
          "VendorSeverity": {
            "alma": 1,
            "amazon": 2,
            "azure": 2,
            "cbl-mariner": 2,
            "ghsa": 2,
            "nvd": 2,
            "oracle-oval": 1,
            "photon": 2,
            "redhat": 1,
            "ubuntu": 1
          },
          "CVSS": {
            "ghsa": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
              "V3Score": 5.5
            },
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
              "V3Score": 5.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
              "V3Score": 5.5
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2024/03/11/1",
            "https://access.redhat.com/errata/RHSA-2024:2447",
            "https://access.redhat.com/security/cve/CVE-2024-0727",
            "https://bugzilla.redhat.com/2223016",
            "https://bugzilla.redhat.com/2224962",
            "https://bugzilla.redhat.com/2227852",
            "https://bugzilla.redhat.com/2248616",
            "https://bugzilla.redhat.com/2257571",
            "https://bugzilla.redhat.com/2258502",
            "https://bugzilla.redhat.com/2259944",
            "https://errata.almalinux.org/9/ALSA-2024-2447.html",
            "https://github.com/alexcrichton/openssl-src-rs/commit/add20f73b6b42be7451af2e1044d4e0e778992b2",
            "https://github.com/github/advisory-database/pull/3472",
            "https://github.com/openssl/openssl/commit/09df4395b5071217b76dc7d3d2e630eb8c5a79c2",
            "https://github.com/openssl/openssl/commit/775acfdbd0c6af9ac855f34969cdab0c0c90844a",
            "https://github.com/openssl/openssl/commit/d135eeab8a5dbf72b3da5240bab9ddb7678dbd2c",
            "https://github.com/openssl/openssl/pull/23362",
            "https://github.com/pyca/cryptography/commit/3519591d255d4506fbcd0d04037d45271903c64d",
            "https://github.openssl.org/openssl/extended-releases/commit/03b3941d60c4bce58fab69a0c22377ab439bc0e8",
            "https://github.openssl.org/openssl/extended-releases/commit/aebaa5883e31122b404e450732dc833dc9dee539",
            "https://linux.oracle.com/cve/CVE-2024-0727.html",
            "https://linux.oracle.com/errata/ELSA-2024-2447.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-0727",
            "https://security.netapp.com/advisory/ntap-20240208-0006",
            "https://security.netapp.com/advisory/ntap-20240208-0006/",
            "https://ubuntu.com/security/notices/USN-6622-1",
            "https://ubuntu.com/security/notices/USN-6632-1",
            "https://ubuntu.com/security/notices/USN-6709-1",
            "https://www.cve.org/CVERecord?id=CVE-2024-0727",
            "https://www.openssl.org/news/secadv/20240125.txt"
          ],
          "PublishedDate": "2024-01-26T09:15:07.637Z",
          "LastModifiedDate": "2024-05-01T18:15:13.057Z"
        },
        {
          "VulnerabilityID": "CVE-2024-4741",
          "PkgID": "libssl1.1@1.1.1n-0+deb10u5",
          "PkgName": "libssl1.1",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libssl1.1@1.1.1n-0%2Bdeb10u5?arch=amd64\u0026distro=debian-10.13",
            "UID": "a38d42590ed16a34"
          },
          "InstalledVersion": "1.1.1n-0+deb10u5",
          "Status": "fix_deferred",
          "Layer": {
            "Digest": "sha256:824416e234237961c9c5d4f41dfe5b295a3c35a671ee52889bfb08d8e257ec4c",
            "DiffID": "sha256:ae2d55769c5efcb6230d27c88eef033128fa1d238bdafe50812402f471152bb7"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-4741",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
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
          "PkgID": "libssl1.1@1.1.1n-0+deb10u5",
          "PkgName": "libssl1.1",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libssl1.1@1.1.1n-0%2Bdeb10u5?arch=amd64\u0026distro=debian-10.13",
            "UID": "a38d42590ed16a34"
          },
          "InstalledVersion": "1.1.1n-0+deb10u5",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:824416e234237961c9c5d4f41dfe5b295a3c35a671ee52889bfb08d8e257ec4c",
            "DiffID": "sha256:ae2d55769c5efcb6230d27c88eef033128fa1d238bdafe50812402f471152bb7"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-5535",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
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
          "PkgID": "libssl1.1@1.1.1n-0+deb10u5",
          "PkgName": "libssl1.1",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libssl1.1@1.1.1n-0%2Bdeb10u5?arch=amd64\u0026distro=debian-10.13",
            "UID": "a38d42590ed16a34"
          },
          "InstalledVersion": "1.1.1n-0+deb10u5",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:824416e234237961c9c5d4f41dfe5b295a3c35a671ee52889bfb08d8e257ec4c",
            "DiffID": "sha256:ae2d55769c5efcb6230d27c88eef033128fa1d238bdafe50812402f471152bb7"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-6119",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
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
          "VulnerabilityID": "CVE-2024-2511",
          "PkgID": "libssl1.1@1.1.1n-0+deb10u5",
          "PkgName": "libssl1.1",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libssl1.1@1.1.1n-0%2Bdeb10u5?arch=amd64\u0026distro=debian-10.13",
            "UID": "a38d42590ed16a34"
          },
          "InstalledVersion": "1.1.1n-0+deb10u5",
          "Status": "fix_deferred",
          "Layer": {
            "Digest": "sha256:824416e234237961c9c5d4f41dfe5b295a3c35a671ee52889bfb08d8e257ec4c",
            "DiffID": "sha256:ae2d55769c5efcb6230d27c88eef033128fa1d238bdafe50812402f471152bb7"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-2511",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "openssl: Unbounded memory growth with session handling in TLSv1.3",
          "Description": "Issue summary: Some non-default TLS server configurations can cause unbounded\nmemory growth when processing TLSv1.3 sessions\n\nImpact summary: An attacker may exploit certain server configurations to trigger\nunbounded memory growth that would lead to a Denial of Service\n\nThis problem can occur in TLSv1.3 if the non-default SSL_OP_NO_TICKET option is\nbeing used (but not if early_data support is also configured and the default\nanti-replay protection is in use). In this case, under certain conditions, the\nsession cache can get into an incorrect state and it will fail to flush properly\nas it fills. The session cache will continue to grow in an unbounded manner. A\nmalicious client could deliberately create the scenario for this failure to\nforce a Denial of Service. It may also happen by accident in normal operation.\n\nThis issue only affects TLS servers supporting TLSv1.3. It does not affect TLS\nclients.\n\nThe FIPS modules in 3.2, 3.1 and 3.0 are not affected by this issue. OpenSSL\n1.0.2 is also not affected by this issue.",
          "Severity": "LOW",
          "VendorSeverity": {
            "amazon": 2,
            "azure": 1,
            "cbl-mariner": 3,
            "photon": 3,
            "redhat": 1,
            "ubuntu": 1
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L",
              "V3Score": 3.7
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2024/04/08/5",
            "https://access.redhat.com/security/cve/CVE-2024-2511",
            "https://github.com/openssl/openssl/commit/7e4d731b1c07201ad9374c1cd9ac5263bdf35bce",
            "https://github.com/openssl/openssl/commit/b52867a9f618bb955bed2a3ce3db4d4f97ed8e5d",
            "https://github.com/openssl/openssl/commit/e9d7083e241670332e0443da0f0d4ffb52829f08",
            "https://github.openssl.org/openssl/extended-releases/commit/5f8d25770ae6437db119dfc951e207271a326640",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-2511",
            "https://security.netapp.com/advisory/ntap-20240503-0013/",
            "https://ubuntu.com/security/notices/USN-6937-1",
            "https://www.cve.org/CVERecord?id=CVE-2024-2511",
            "https://www.openssl.org/news/secadv/20240408.txt",
            "https://www.openssl.org/news/vulnerabilities.html"
          ],
          "PublishedDate": "2024-04-08T14:15:07.66Z",
          "LastModifiedDate": "2024-05-03T13:15:21.93Z"
        },
        {
          "VulnerabilityID": "CVE-2018-12886",
          "PkgID": "libstdc++6@8.3.0-6",
          "PkgName": "libstdc++6",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libstdc%2B%2B6@8.3.0-6?arch=amd64\u0026distro=debian-10.13",
            "UID": "42f772ca1cbb5878"
          },
          "InstalledVersion": "8.3.0-6",
          "Status": "will_not_fix",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2018-12886",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "gcc: spilling of stack protection address in cfgexpand.c and function.c leads to stack-overflow protection bypass",
          "Description": "stack_protect_prologue in cfgexpand.c and stack_protect_epilogue in function.c in GNU Compiler Collection (GCC) 4.1 through 8 (under certain circumstances) generate instruction sequences when targeting ARM targets that spill the address of the stack protector guard, which allows an attacker to bypass the protection of -fstack-protector, -fstack-protector-all, -fstack-protector-strong, and -fstack-protector-explicit against stack overflow by controlling what the stack canary is compared against.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-209"
          ],
          "VendorSeverity": {
            "nvd": 3,
            "redhat": 2,
            "ubuntu": 1
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
              "V3Vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
              "V2Score": 6.8,
              "V3Score": 8.1
            },
            "redhat": {
              "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H",
              "V3Score": 6.8
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2018-12886",
            "https://gcc.gnu.org/git/?p=gcc.git;a=commit;h=89d7557202d25a393666ac4c0f7dbdab31e452a2",
            "https://gcc.gnu.org/viewcvs/gcc/trunk/gcc/config/arm/arm-protos.h?revision=266379\u0026view=markup",
            "https://nvd.nist.gov/vuln/detail/CVE-2018-12886",
            "https://www.cve.org/CVERecord?id=CVE-2018-12886",
            "https://www.gnu.org/software/gcc/gcc-8/changes.html"
          ],
          "PublishedDate": "2019-05-22T19:29:00.297Z",
          "LastModifiedDate": "2020-08-24T17:37:01.14Z"
        },
        {
          "VulnerabilityID": "CVE-2019-15847",
          "PkgID": "libstdc++6@8.3.0-6",
          "PkgName": "libstdc++6",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libstdc%2B%2B6@8.3.0-6?arch=amd64\u0026distro=debian-10.13",
            "UID": "42f772ca1cbb5878"
          },
          "InstalledVersion": "8.3.0-6",
          "Status": "will_not_fix",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2019-15847",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "gcc: POWER9 \"DARN\" RNG intrinsic produces repeated output",
          "Description": "The POWER9 backend in GNU Compiler Collection (GCC) before version 10 could optimize multiple calls of the __builtin_darn intrinsic into a single call, thus reducing the entropy of the random number generator. This occurred because a volatile operation was not specified. For example, within a single execution of a program, the output of every __builtin_darn() call may be the same.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-331"
          ],
          "VendorSeverity": {
            "cbl-mariner": 3,
            "nvd": 3,
            "oracle-oval": 2,
            "redhat": 2,
            "ubuntu": 1
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:P/I:N/A:N",
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
              "V2Score": 5,
              "V3Score": 7.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
              "V3Score": 7.5
            }
          },
          "References": [
            "http://lists.opensuse.org/opensuse-security-announce/2019-10/msg00056.html",
            "http://lists.opensuse.org/opensuse-security-announce/2019-10/msg00057.html",
            "http://lists.opensuse.org/opensuse-security-announce/2020-05/msg00058.html",
            "https://access.redhat.com/security/cve/CVE-2019-15847",
            "https://gcc.gnu.org/bugzilla/show_bug.cgi?id=91481",
            "https://gcc.gnu.org/git/?p=gcc.git;a=commit;h=457dac402027dd7e14543fbd59a75858422cf6c6",
            "https://gcc.gnu.org/git/?p=gcc.git;a=commit;h=e99bfdd2a8db732ea84cf0a6486707e5e821ad7e",
            "https://linux.oracle.com/cve/CVE-2019-15847.html",
            "https://linux.oracle.com/errata/ELSA-2020-1864.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-15847",
            "https://www.cve.org/CVERecord?id=CVE-2019-15847"
          ],
          "PublishedDate": "2019-09-02T23:15:10.837Z",
          "LastModifiedDate": "2020-09-17T13:38:06.51Z"
        },
        {
          "VulnerabilityID": "CVE-2023-4039",
          "PkgID": "libstdc++6@8.3.0-6",
          "PkgName": "libstdc++6",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libstdc%2B%2B6@8.3.0-6?arch=amd64\u0026distro=debian-10.13",
            "UID": "42f772ca1cbb5878"
          },
          "InstalledVersion": "8.3.0-6",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-4039",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "gcc: -fstack-protector fails to guard dynamic stack allocations on ARM64",
          "Description": "\n\n**DISPUTED**A failure in the -fstack-protector feature in GCC-based toolchains \nthat target AArch64 allows an attacker to exploit an existing buffer \noverflow in dynamically-sized local variables in your application \nwithout this being detected. This stack-protector failure only applies \nto C99-style dynamically-sized local variables or those created using \nalloca(). The stack-protector operates as intended for statically-sized \nlocal variables.\n\nThe default behavior when the stack-protector \ndetects an overflow is to terminate your application, resulting in \ncontrolled loss of availability. An attacker who can exploit a buffer \noverflow without triggering the stack-protector might be able to change \nprogram flow control to cause an uncontrolled loss of availability or to\n go further and affect confidentiality or integrity. NOTE: The GCC project argues that this is a missed hardening bug and not a vulnerability by itself.\n\n\n\n\n\n",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-693"
          ],
          "VendorSeverity": {
            "amazon": 2,
            "azure": 2,
            "cbl-mariner": 2,
            "nvd": 2,
            "oracle-oval": 1,
            "ubuntu": 2
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
              "V3Score": 4.8
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2023-4039",
            "https://developer.arm.com/Arm%20Security%20Center/GCC%20Stack%20Protector%20Vulnerability%20AArch64",
            "https://gcc.gnu.org/git/?p=gcc.git;a=blob_plain;f=SECURITY.txt",
            "https://gcc.gnu.org/pipermail/gcc-patches/2023-October/634066.html",
            "https://github.com/metaredteam/external-disclosures/security/advisories/GHSA-x7ch-h5rf-w2mf",
            "https://inbox.sourceware.org/gcc-patches/46cfa37b-56eb-344d-0745-e0d35393392d@gotplt.org",
            "https://linux.oracle.com/cve/CVE-2023-4039.html",
            "https://linux.oracle.com/errata/ELSA-2023-28766.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-4039",
            "https://rtx.meta.security/mitigation/2023/09/12/CVE-2023-4039.html",
            "https://www.cve.org/CVERecord?id=CVE-2023-4039"
          ],
          "PublishedDate": "2023-09-13T09:15:15.69Z",
          "LastModifiedDate": "2024-08-02T08:15:14.993Z"
        },
        {
          "VulnerabilityID": "CVE-2019-3843",
          "PkgID": "libsystemd0@241-7~deb10u9",
          "PkgName": "libsystemd0",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libsystemd0@241-7~deb10u9?arch=amd64\u0026distro=debian-10.13",
            "UID": "aa67c4ff0e17a1d0"
          },
          "InstalledVersion": "241-7~deb10u9",
          "Status": "will_not_fix",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2019-3843",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "systemd: services with DynamicUser can create SUID/SGID binaries",
          "Description": "It was discovered that a systemd service that uses DynamicUser property can create a SUID/SGID binary that would be allowed to run as the transient service UID/GID even after the service is terminated. A local attacker may use this flaw to access resources that will be owned by a potentially different service in the future, when the UID/GID will be recycled.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-269",
            "CWE-266"
          ],
          "VendorSeverity": {
            "cbl-mariner": 3,
            "nvd": 3,
            "oracle-oval": 2,
            "photon": 3,
            "redhat": 2,
            "ubuntu": 1
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:L/AC:L/Au:N/C:P/I:P/A:P",
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
              "V2Score": 4.6,
              "V3Score": 7.8
            },
            "redhat": {
              "V3Vector": "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:L",
              "V3Score": 4.5
            }
          },
          "References": [
            "http://www.securityfocus.com/bid/108116",
            "https://access.redhat.com/security/cve/CVE-2019-3843",
            "https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2019-3843",
            "https://github.com/systemd/systemd-stable/pull/54 (backport for v241-stable)",
            "https://linux.oracle.com/cve/CVE-2019-3843.html",
            "https://linux.oracle.com/errata/ELSA-2020-1794.html",
            "https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b%40%3Cissues.bookkeeper.apache.org%3E",
            "https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4%40%3Cissues.bookkeeper.apache.org%3E",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/5JXQAKSTMABZ46EVCRMW62DHWYHTTFES/",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-3843",
            "https://security.netapp.com/advisory/ntap-20190619-0002/",
            "https://ubuntu.com/security/notices/USN-4269-1",
            "https://usn.ubuntu.com/4269-1/",
            "https://www.cve.org/CVERecord?id=CVE-2019-3843"
          ],
          "PublishedDate": "2019-04-26T21:29:00.36Z",
          "LastModifiedDate": "2023-11-07T03:10:14.033Z"
        },
        {
          "VulnerabilityID": "CVE-2019-3844",
          "PkgID": "libsystemd0@241-7~deb10u9",
          "PkgName": "libsystemd0",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libsystemd0@241-7~deb10u9?arch=amd64\u0026distro=debian-10.13",
            "UID": "aa67c4ff0e17a1d0"
          },
          "InstalledVersion": "241-7~deb10u9",
          "Status": "will_not_fix",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2019-3844",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "systemd: services with DynamicUser can get new privileges and create SGID binaries",
          "Description": "It was discovered that a systemd service that uses DynamicUser property can get new privileges through the execution of SUID binaries, which would allow to create binaries owned by the service transient group with the setgid bit set. A local attacker may use this flaw to access resources that will be owned by a potentially different service in the future, when the GID will be recycled.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-268"
          ],
          "VendorSeverity": {
            "cbl-mariner": 3,
            "nvd": 3,
            "oracle-oval": 2,
            "photon": 3,
            "redhat": 2,
            "ubuntu": 1
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:L/AC:L/Au:N/C:P/I:P/A:P",
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
              "V2Score": 4.6,
              "V3Score": 7.8
            },
            "redhat": {
              "V3Vector": "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:L",
              "V3Score": 4.5
            }
          },
          "References": [
            "http://www.securityfocus.com/bid/108096",
            "https://access.redhat.com/security/cve/CVE-2019-3844",
            "https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2019-3844",
            "https://linux.oracle.com/cve/CVE-2019-3844.html",
            "https://linux.oracle.com/errata/ELSA-2020-1794.html",
            "https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b%40%3Cissues.bookkeeper.apache.org%3E",
            "https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4%40%3Cissues.bookkeeper.apache.org%3E",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-3844",
            "https://security.netapp.com/advisory/ntap-20190619-0002/",
            "https://ubuntu.com/security/notices/USN-4269-1",
            "https://usn.ubuntu.com/4269-1/",
            "https://www.cve.org/CVERecord?id=CVE-2019-3844"
          ],
          "PublishedDate": "2019-04-26T21:29:00.423Z",
          "LastModifiedDate": "2023-11-07T03:10:14.13Z"
        },
        {
          "VulnerabilityID": "CVE-2023-50387",
          "PkgID": "libsystemd0@241-7~deb10u9",
          "PkgName": "libsystemd0",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libsystemd0@241-7~deb10u9?arch=amd64\u0026distro=debian-10.13",
            "UID": "aa67c4ff0e17a1d0"
          },
          "InstalledVersion": "241-7~deb10u9",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-50387",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "bind9: KeyTrap - Extreme CPU consumption in DNSSEC validator",
          "Description": "Certain DNSSEC aspects of the DNS protocol (in RFC 4033, 4034, 4035, 6840, and related RFCs) allow remote attackers to cause a denial of service (CPU consumption) via one or more DNSSEC responses, aka the \"KeyTrap\" issue. One of the concerns is that, when there is a zone with many DNSKEY and RRSIG records, the protocol specification implies that an algorithm must evaluate all combinations of DNSKEY and RRSIG records.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-770"
          ],
          "VendorSeverity": {
            "alma": 3,
            "amazon": 3,
            "azure": 3,
            "cbl-mariner": 3,
            "nvd": 3,
            "oracle-oval": 3,
            "photon": 3,
            "redhat": 3,
            "rocky": 3,
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
            "http://www.openwall.com/lists/oss-security/2024/02/16/2",
            "http://www.openwall.com/lists/oss-security/2024/02/16/3",
            "https://access.redhat.com/errata/RHSA-2024:2551",
            "https://access.redhat.com/security/cve/CVE-2023-50387",
            "https://blog.powerdns.com/2024/02/13/powerdns-recursor-4-8-6-4-9-3-5-0-2-released",
            "https://bugzilla.redhat.com/2263896",
            "https://bugzilla.redhat.com/2263897",
            "https://bugzilla.redhat.com/2263909",
            "https://bugzilla.redhat.com/2263911",
            "https://bugzilla.redhat.com/2263914",
            "https://bugzilla.redhat.com/2263917",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2263896",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2263897",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2263909",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2263911",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2263914",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2263917",
            "https://bugzilla.suse.com/show_bug.cgi?id=1219823",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4408",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-50387",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-50868",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-5517",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-5679",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-6516",
            "https://docs.powerdns.com/recursor/security-advisories/powerdns-advisory-2024-01.html",
            "https://errata.almalinux.org/9/ALSA-2024-2551.html",
            "https://errata.rockylinux.org/RLSA-2024:2551",
            "https://gitlab.nic.cz/knot/knot-resolver/-/releases/v5.7.1",
            "https://kb.isc.org/docs/cve-2023-50387",
            "https://linux.oracle.com/cve/CVE-2023-50387.html",
            "https://linux.oracle.com/errata/ELSA-2024-3741.html",
            "https://lists.debian.org/debian-lts-announce/2024/02/msg00006.html",
            "https://lists.debian.org/debian-lts-announce/2024/05/msg00011.html",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/6FV5O347JTX7P5OZA6NGO4MKTXRXMKOZ/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/BUIP7T7Z4T3UHLXFWG6XIVDP4GYPD3AI/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/HVRDSJVZKMCXKKPP6PNR62T7RWZ3YSDZ/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/IGSLGKUAQTW5JPPZCMF5YPEYALLRUZZ6/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/PNNHZSZPG2E7NBMBNYPGHCFI4V4XRWNQ/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/RGS7JN6FZXUSTC2XKQHH27574XOULYYJ/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/SVYA42BLXUCIDLD35YIJPJSHDIADNYMP/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/TEXGOYGW7DBS3N2QSSQONZ4ENIRQEAPG/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/UQESRWMJCF4JEYJEAKLRM6CT55GLJAB7/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/ZDZFMEKQTZ4L7RY46FCENWFB5MDT263R/",
            "https://lists.thekelleys.org.uk/pipermail/dnsmasq-discuss/2024q1/017430.html",
            "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-50387",
            "https://news.ycombinator.com/item?id=39367411",
            "https://news.ycombinator.com/item?id=39372384",
            "https://nlnetlabs.nl/downloads/unbound/CVE-2023-50387_CVE-2023-50868.txt",
            "https://nlnetlabs.nl/news/2024/Feb/13/unbound-1.19.1-released/",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-50387",
            "https://security.netapp.com/advisory/ntap-20240307-0007/",
            "https://ubuntu.com/security/notices/USN-6633-1",
            "https://ubuntu.com/security/notices/USN-6642-1",
            "https://ubuntu.com/security/notices/USN-6657-1",
            "https://ubuntu.com/security/notices/USN-6657-2",
            "https://ubuntu.com/security/notices/USN-6665-1",
            "https://ubuntu.com/security/notices/USN-6723-1",
            "https://www.athene-center.de/aktuelles/key-trap",
            "https://www.athene-center.de/fileadmin/content/PDF/Technical_Report_KeyTrap.pdf",
            "https://www.cve.org/CVERecord?id=CVE-2023-50387",
            "https://www.isc.org/blogs/2024-bind-security-release/",
            "https://www.knot-resolver.cz/2024-02-13-knot-resolver-5.7.1.html",
            "https://www.securityweek.com/keytrap-dns-attack-could-disable-large-parts-of-internet-researchers/",
            "https://www.theregister.com/2024/02/13/dnssec_vulnerability_internet/"
          ],
          "PublishedDate": "2024-02-14T16:15:45.3Z",
          "LastModifiedDate": "2024-06-10T17:16:15.963Z"
        },
        {
          "VulnerabilityID": "CVE-2023-50868",
          "PkgID": "libsystemd0@241-7~deb10u9",
          "PkgName": "libsystemd0",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libsystemd0@241-7~deb10u9?arch=amd64\u0026distro=debian-10.13",
            "UID": "aa67c4ff0e17a1d0"
          },
          "InstalledVersion": "241-7~deb10u9",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-50868",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "bind9: Preparing an NSEC3 closest encloser proof can exhaust CPU resources",
          "Description": "The Closest Encloser Proof aspect of the DNS protocol (in RFC 5155 when RFC 9276 guidance is skipped) allows remote attackers to cause a denial of service (CPU consumption for SHA-1 computations) via DNSSEC responses in a random subdomain attack, aka the \"NSEC3\" issue. The RFC 5155 specification implies that an algorithm must perform thousands of iterations of a hash function in certain situations.",
          "Severity": "HIGH",
          "VendorSeverity": {
            "alma": 3,
            "amazon": 3,
            "azure": 3,
            "cbl-mariner": 3,
            "oracle-oval": 3,
            "photon": 3,
            "redhat": 3,
            "rocky": 3,
            "ubuntu": 2
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 7.5
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2024/02/16/2",
            "http://www.openwall.com/lists/oss-security/2024/02/16/3",
            "https://access.redhat.com/errata/RHSA-2024:2551",
            "https://access.redhat.com/security/cve/CVE-2023-50868",
            "https://blog.powerdns.com/2024/02/13/powerdns-recursor-4-8-6-4-9-3-5-0-2-released",
            "https://bugzilla.redhat.com/2263896",
            "https://bugzilla.redhat.com/2263897",
            "https://bugzilla.redhat.com/2263909",
            "https://bugzilla.redhat.com/2263911",
            "https://bugzilla.redhat.com/2263914",
            "https://bugzilla.redhat.com/2263917",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2263896",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2263897",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2263909",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2263911",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2263914",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2263917",
            "https://bugzilla.suse.com/show_bug.cgi?id=1219826",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4408",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-50387",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-50868",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-5517",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-5679",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-6516",
            "https://datatracker.ietf.org/doc/html/rfc5155",
            "https://docs.powerdns.com/recursor/security-advisories/powerdns-advisory-2024-01.html",
            "https://errata.almalinux.org/9/ALSA-2024-2551.html",
            "https://errata.rockylinux.org/RLSA-2024:2551",
            "https://gitlab.nic.cz/knot/knot-resolver/-/releases/v5.7.1",
            "https://kb.isc.org/docs/cve-2023-50868",
            "https://linux.oracle.com/cve/CVE-2023-50868.html",
            "https://linux.oracle.com/errata/ELSA-2024-3741.html",
            "https://lists.debian.org/debian-lts-announce/2024/02/msg00006.html",
            "https://lists.debian.org/debian-lts-announce/2024/05/msg00011.html",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/6FV5O347JTX7P5OZA6NGO4MKTXRXMKOZ/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/BUIP7T7Z4T3UHLXFWG6XIVDP4GYPD3AI/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/HVRDSJVZKMCXKKPP6PNR62T7RWZ3YSDZ/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/IGSLGKUAQTW5JPPZCMF5YPEYALLRUZZ6/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/PNNHZSZPG2E7NBMBNYPGHCFI4V4XRWNQ/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/RGS7JN6FZXUSTC2XKQHH27574XOULYYJ/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/SVYA42BLXUCIDLD35YIJPJSHDIADNYMP/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/TEXGOYGW7DBS3N2QSSQONZ4ENIRQEAPG/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/UQESRWMJCF4JEYJEAKLRM6CT55GLJAB7/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/ZDZFMEKQTZ4L7RY46FCENWFB5MDT263R/",
            "https://lists.thekelleys.org.uk/pipermail/dnsmasq-discuss/2024q1/017430.html",
            "https://nlnetlabs.nl/downloads/unbound/CVE-2023-50387_CVE-2023-50868.txt",
            "https://nlnetlabs.nl/news/2024/Feb/13/unbound-1.19.1-released/",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-50868",
            "https://security.netapp.com/advisory/ntap-20240307-0008/",
            "https://ubuntu.com/security/notices/USN-6633-1",
            "https://ubuntu.com/security/notices/USN-6642-1",
            "https://ubuntu.com/security/notices/USN-6657-1",
            "https://ubuntu.com/security/notices/USN-6657-2",
            "https://ubuntu.com/security/notices/USN-6665-1",
            "https://ubuntu.com/security/notices/USN-6723-1",
            "https://www.cve.org/CVERecord?id=CVE-2023-50868",
            "https://www.isc.org/blogs/2024-bind-security-release/",
            "https://www.knot-resolver.cz/2024-02-13-knot-resolver-5.7.1.html"
          ],
          "PublishedDate": "2024-02-14T16:15:45.377Z",
          "LastModifiedDate": "2024-06-10T17:16:16.2Z"
        },
        {
          "VulnerabilityID": "CVE-2021-3997",
          "PkgID": "libsystemd0@241-7~deb10u9",
          "PkgName": "libsystemd0",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libsystemd0@241-7~deb10u9?arch=amd64\u0026distro=debian-10.13",
            "UID": "aa67c4ff0e17a1d0"
          },
          "InstalledVersion": "241-7~deb10u9",
          "Status": "will_not_fix",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2021-3997",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "systemd: Uncontrolled recursion in systemd-tmpfiles when removing files",
          "Description": "A flaw was found in systemd. An uncontrolled recursion in systemd-tmpfiles may lead to a denial of service at boot time when too many nested directories are created in /tmp.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-674"
          ],
          "VendorSeverity": {
            "amazon": 2,
            "cbl-mariner": 2,
            "nvd": 2,
            "photon": 2,
            "redhat": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 5.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 5.5
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2021-3997",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2024639",
            "https://github.com/systemd/systemd/commit/5b1cf7a9be37e20133c0208005274ce4a5b5c6a1",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-3997",
            "https://security.gentoo.org/glsa/202305-15",
            "https://ubuntu.com/security/notices/USN-5226-1",
            "https://www.cve.org/CVERecord?id=CVE-2021-3997",
            "https://www.openwall.com/lists/oss-security/2022/01/10/2"
          ],
          "PublishedDate": "2022-08-23T20:15:08.67Z",
          "LastModifiedDate": "2023-05-03T12:15:15.95Z"
        },
        {
          "VulnerabilityID": "CVE-2022-3821",
          "VendorIDs": [
            "DLA-3474-1"
          ],
          "PkgID": "libsystemd0@241-7~deb10u9",
          "PkgName": "libsystemd0",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libsystemd0@241-7~deb10u9?arch=amd64\u0026distro=debian-10.13",
            "UID": "aa67c4ff0e17a1d0"
          },
          "InstalledVersion": "241-7~deb10u9",
          "FixedVersion": "241-7~deb10u10",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2022-3821",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "systemd: buffer overrun in format_timespan() function",
          "Description": "An off-by-one Error issue was discovered in Systemd in format_timespan() function of time-util.c. An attacker could supply specific values for time and accuracy that leads to buffer overrun in format_timespan(), leading to a Denial of Service.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-193"
          ],
          "VendorSeverity": {
            "alma": 2,
            "amazon": 2,
            "azure": 2,
            "cbl-mariner": 2,
            "nvd": 2,
            "oracle-oval": 2,
            "photon": 2,
            "redhat": 2,
            "rocky": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 5.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 5.5
            }
          },
          "References": [
            "https://access.redhat.com/errata/RHSA-2023:0336",
            "https://access.redhat.com/security/cve/CVE-2022-3821",
            "https://bugzilla.redhat.com/2139327",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2139327",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-3821",
            "https://errata.almalinux.org/9/ALSA-2023-0336.html",
            "https://errata.rockylinux.org/RLSA-2023:0336",
            "https://github.com/systemd/systemd/commit/9102c625a673a3246d7e73d8737f3494446bad4e",
            "https://github.com/systemd/systemd/issues/23928",
            "https://github.com/systemd/systemd/pull/23933",
            "https://linux.oracle.com/cve/CVE-2022-3821.html",
            "https://linux.oracle.com/errata/ELSA-2023-0336.html",
            "https://lists.debian.org/debian-lts-announce/2023/06/msg00036.html",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/RVBQC2VLSDVQAPJTEMTREXDL4HYLXG2P/",
            "https://nvd.nist.gov/vuln/detail/CVE-2022-3821",
            "https://security.gentoo.org/glsa/202305-15",
            "https://ubuntu.com/security/notices/USN-5928-1",
            "https://www.cve.org/CVERecord?id=CVE-2022-3821"
          ],
          "PublishedDate": "2022-11-08T22:15:16.7Z",
          "LastModifiedDate": "2023-11-07T03:51:50.43Z"
        },
        {
          "VulnerabilityID": "CVE-2022-4415",
          "PkgID": "libsystemd0@241-7~deb10u9",
          "PkgName": "libsystemd0",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libsystemd0@241-7~deb10u9?arch=amd64\u0026distro=debian-10.13",
            "UID": "aa67c4ff0e17a1d0"
          },
          "InstalledVersion": "241-7~deb10u9",
          "Status": "will_not_fix",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2022-4415",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "systemd: local information leak due to systemd-coredump not respecting fs.suid_dumpable kernel setting",
          "Description": "A vulnerability was found in systemd. This security flaw can cause a local information leak due to systemd-coredump not respecting the fs.suid_dumpable kernel setting.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-200"
          ],
          "VendorSeverity": {
            "alma": 2,
            "amazon": 2,
            "azure": 2,
            "cbl-mariner": 2,
            "nvd": 2,
            "oracle-oval": 2,
            "photon": 2,
            "redhat": 2,
            "rocky": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
              "V3Score": 5.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
              "V3Score": 5.5
            }
          },
          "References": [
            "https://access.redhat.com/errata/RHSA-2023:0954",
            "https://access.redhat.com/security/cve/CVE-2022-4415",
            "https://bugzilla.redhat.com/2149063",
            "https://bugzilla.redhat.com/2155515",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2149063",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2155515",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-4415",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-45873",
            "https://errata.almalinux.org/9/ALSA-2023-0954.html",
            "https://errata.rockylinux.org/RLSA-2023:0954",
            "https://github.com/systemd/systemd/commit/b7641425659243c09473cd8fb3aef2c0d4a3eb9c",
            "https://linux.oracle.com/cve/CVE-2022-4415.html",
            "https://linux.oracle.com/errata/ELSA-2023-0954.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2022-4415",
            "https://ubuntu.com/security/notices/USN-5928-1",
            "https://www.cve.org/CVERecord?id=CVE-2022-4415",
            "https://www.openwall.com/lists/oss-security/2022/12/21/3"
          ],
          "PublishedDate": "2023-01-11T15:15:09.59Z",
          "LastModifiedDate": "2023-02-02T16:19:28.633Z"
        },
        {
          "VulnerabilityID": "CVE-2023-7008",
          "PkgID": "libsystemd0@241-7~deb10u9",
          "PkgName": "libsystemd0",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libsystemd0@241-7~deb10u9?arch=amd64\u0026distro=debian-10.13",
            "UID": "aa67c4ff0e17a1d0"
          },
          "InstalledVersion": "241-7~deb10u9",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-7008",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "systemd-resolved: Unsigned name response in signed zone is not refused when DNSSEC=yes",
          "Description": "A vulnerability was found in systemd-resolved. This issue may allow systemd-resolved to accept records of DNSSEC-signed domains even when they have no signature, allowing man-in-the-middles (or the upstream DNS resolver) to manipulate records.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-300"
          ],
          "VendorSeverity": {
            "alma": 2,
            "amazon": 2,
            "cbl-mariner": 2,
            "nvd": 2,
            "oracle-oval": 2,
            "redhat": 2,
            "rocky": 2,
            "ubuntu": 1
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N",
              "V3Score": 5.9
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N",
              "V3Score": 5.9
            }
          },
          "References": [
            "https://access.redhat.com/errata/RHSA-2024:2463",
            "https://access.redhat.com/errata/RHSA-2024:3203",
            "https://access.redhat.com/security/cve/CVE-2023-7008",
            "https://bugzilla.redhat.com/2222672",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2222261",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2222672",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-7008",
            "https://errata.almalinux.org/9/ALSA-2024-2463.html",
            "https://errata.rockylinux.org/RLSA-2024:2463",
            "https://github.com/systemd/systemd/issues/25676",
            "https://linux.oracle.com/cve/CVE-2023-7008.html",
            "https://linux.oracle.com/errata/ELSA-2024-3203.html",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/4GMDEG5PKONWNHOEYSUDRT6JEOISRMN2/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/QHNBXGKJWISJETTTDTZKTBFIBJUOSLKL/",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-7008",
            "https://www.cve.org/CVERecord?id=CVE-2023-7008"
          ],
          "PublishedDate": "2023-12-23T13:15:07.573Z",
          "LastModifiedDate": "2024-05-22T17:16:10.83Z"
        },
        {
          "VulnerabilityID": "CVE-2013-4392",
          "PkgID": "libsystemd0@241-7~deb10u9",
          "PkgName": "libsystemd0",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libsystemd0@241-7~deb10u9?arch=amd64\u0026distro=debian-10.13",
            "UID": "aa67c4ff0e17a1d0"
          },
          "InstalledVersion": "241-7~deb10u9",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2013-4392",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "systemd: TOCTOU race condition when updating file permissions and SELinux security contexts",
          "Description": "systemd, when updating file permissions, allows local users to change the permissions and SELinux security contexts for arbitrary files via a symlink attack on unspecified files.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-59"
          ],
          "VendorSeverity": {
            "debian": 1,
            "nvd": 1,
            "redhat": 2
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:L/AC:M/Au:N/C:P/I:P/A:N",
              "V2Score": 3.3
            },
            "redhat": {
              "V2Vector": "AV:L/AC:M/Au:N/C:P/I:P/A:N",
              "V2Score": 3.3
            }
          },
          "References": [
            "http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=725357",
            "http://www.openwall.com/lists/oss-security/2013/10/01/9",
            "https://access.redhat.com/security/cve/CVE-2013-4392",
            "https://bugzilla.redhat.com/show_bug.cgi?id=859060",
            "https://nvd.nist.gov/vuln/detail/CVE-2013-4392",
            "https://www.cve.org/CVERecord?id=CVE-2013-4392"
          ],
          "PublishedDate": "2013-10-28T22:55:03.773Z",
          "LastModifiedDate": "2022-01-31T17:49:14.387Z"
        },
        {
          "VulnerabilityID": "CVE-2019-20386",
          "PkgID": "libsystemd0@241-7~deb10u9",
          "PkgName": "libsystemd0",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libsystemd0@241-7~deb10u9?arch=amd64\u0026distro=debian-10.13",
            "UID": "aa67c4ff0e17a1d0"
          },
          "InstalledVersion": "241-7~deb10u9",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2019-20386",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "systemd: memory leak in button_open() in login/logind-button.c when udev events are received",
          "Description": "An issue was discovered in button_open in login/logind-button.c in systemd before 243. When executing the udevadm trigger command, a memory leak may occur.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-401"
          ],
          "VendorSeverity": {
            "amazon": 2,
            "cbl-mariner": 1,
            "debian": 1,
            "nvd": 1,
            "oracle-oval": 1,
            "photon": 1,
            "redhat": 1,
            "ubuntu": 1
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:L/AC:L/Au:N/C:N/I:N/A:P",
              "V3Vector": "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
              "V2Score": 2.1,
              "V3Score": 2.4
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
              "V3Score": 2.4
            }
          },
          "References": [
            "http://lists.opensuse.org/opensuse-security-announce/2020-02/msg00014.html",
            "https://access.redhat.com/security/cve/CVE-2019-20386",
            "https://github.com/systemd/systemd/commit/b2774a3ae692113e1f47a336a6c09bac9cfb49ad",
            "https://linux.oracle.com/cve/CVE-2019-20386.html",
            "https://linux.oracle.com/errata/ELSA-2020-4553.html",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/HZPCOMW5X6IZZXASCDD2CNW2DLF3YADC/",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-20386",
            "https://security.netapp.com/advisory/ntap-20200210-0002/",
            "https://ubuntu.com/security/notices/USN-4269-1",
            "https://usn.ubuntu.com/4269-1/",
            "https://www.cve.org/CVERecord?id=CVE-2019-20386"
          ],
          "PublishedDate": "2020-01-21T06:15:11.827Z",
          "LastModifiedDate": "2023-11-07T03:09:08.387Z"
        },
        {
          "VulnerabilityID": "CVE-2020-13529",
          "PkgID": "libsystemd0@241-7~deb10u9",
          "PkgName": "libsystemd0",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libsystemd0@241-7~deb10u9?arch=amd64\u0026distro=debian-10.13",
            "UID": "aa67c4ff0e17a1d0"
          },
          "InstalledVersion": "241-7~deb10u9",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2020-13529",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "systemd: DHCP FORCERENEW authentication not implemented can cause a system running the DHCP client to have its network reconfigured",
          "Description": "An exploitable denial-of-service vulnerability exists in Systemd 245. A specially crafted DHCP FORCERENEW packet can cause a server running the DHCP client to be vulnerable to a DHCP ACK spoofing attack. An attacker can forge a pair of FORCERENEW and DCHP ACK packets to reconfigure the server.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-290"
          ],
          "VendorSeverity": {
            "alma": 2,
            "amazon": 3,
            "debian": 1,
            "nvd": 2,
            "oracle-oval": 2,
            "photon": 2,
            "redhat": 2,
            "ubuntu": 1
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:A/AC:M/Au:N/C:N/I:N/A:P",
              "V3Vector": "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:C/C:N/I:N/A:H",
              "V2Score": 2.9,
              "V3Score": 6.1
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:C/C:N/I:N/A:H",
              "V3Score": 6.1
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2021/08/04/2",
            "http://www.openwall.com/lists/oss-security/2021/08/17/3",
            "http://www.openwall.com/lists/oss-security/2021/09/07/3",
            "https://access.redhat.com/security/cve/CVE-2020-13529",
            "https://linux.oracle.com/cve/CVE-2020-13529.html",
            "https://linux.oracle.com/errata/ELSA-2021-4361.html",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/42TMJVNYRY65B4QCJICBYOEIVZV3KUYI/",
            "https://nvd.nist.gov/vuln/detail/CVE-2020-13529",
            "https://security.gentoo.org/glsa/202107-48",
            "https://security.netapp.com/advisory/ntap-20210625-0005/",
            "https://talosintelligence.com/vulnerability_reports/TALOS-2020-1142",
            "https://ubuntu.com/security/notices/USN-5013-1",
            "https://ubuntu.com/security/notices/USN-5013-2",
            "https://www.cve.org/CVERecord?id=CVE-2020-13529"
          ],
          "PublishedDate": "2021-05-10T16:15:07.373Z",
          "LastModifiedDate": "2023-11-07T03:16:42.717Z"
        },
        {
          "VulnerabilityID": "CVE-2023-31437",
          "PkgID": "libsystemd0@241-7~deb10u9",
          "PkgName": "libsystemd0",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libsystemd0@241-7~deb10u9?arch=amd64\u0026distro=debian-10.13",
            "UID": "aa67c4ff0e17a1d0"
          },
          "InstalledVersion": "241-7~deb10u9",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-31437",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "An issue was discovered in systemd 253. An attacker can modify a seale ...",
          "Description": "An issue was discovered in systemd 253. An attacker can modify a sealed log file such that, in some views, not all existing and sealed log messages are displayed. NOTE: the vendor reportedly sent \"a reply denying that any of the finding was a security vulnerability.\"",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-354"
          ],
          "VendorSeverity": {
            "debian": 1,
            "nvd": 2
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
              "V3Score": 5.3
            }
          },
          "References": [
            "https://github.com/kastel-security/Journald",
            "https://github.com/kastel-security/Journald/blob/main/journald-publication.pdf",
            "https://github.com/systemd/systemd/releases"
          ],
          "PublishedDate": "2023-06-13T17:15:14.657Z",
          "LastModifiedDate": "2024-08-02T15:16:07.647Z"
        },
        {
          "VulnerabilityID": "CVE-2023-31438",
          "PkgID": "libsystemd0@241-7~deb10u9",
          "PkgName": "libsystemd0",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libsystemd0@241-7~deb10u9?arch=amd64\u0026distro=debian-10.13",
            "UID": "aa67c4ff0e17a1d0"
          },
          "InstalledVersion": "241-7~deb10u9",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-31438",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "An issue was discovered in systemd 253. An attacker can truncate a sea ...",
          "Description": "An issue was discovered in systemd 253. An attacker can truncate a sealed log file and then resume log sealing such that checking the integrity shows no error, despite modifications. NOTE: the vendor reportedly sent \"a reply denying that any of the finding was a security vulnerability.\"",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-354"
          ],
          "VendorSeverity": {
            "debian": 1,
            "nvd": 2
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
              "V3Score": 5.3
            }
          },
          "References": [
            "https://github.com/kastel-security/Journald",
            "https://github.com/kastel-security/Journald/blob/main/journald-publication.pdf",
            "https://github.com/systemd/systemd/pull/28886",
            "https://github.com/systemd/systemd/releases"
          ],
          "PublishedDate": "2023-06-13T17:15:14.707Z",
          "LastModifiedDate": "2024-08-02T15:16:07.753Z"
        },
        {
          "VulnerabilityID": "CVE-2023-31439",
          "PkgID": "libsystemd0@241-7~deb10u9",
          "PkgName": "libsystemd0",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libsystemd0@241-7~deb10u9?arch=amd64\u0026distro=debian-10.13",
            "UID": "aa67c4ff0e17a1d0"
          },
          "InstalledVersion": "241-7~deb10u9",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-31439",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "An issue was discovered in systemd 253. An attacker can modify the con ...",
          "Description": "An issue was discovered in systemd 253. An attacker can modify the contents of past events in a sealed log file and then adjust the file such that checking the integrity shows no error, despite modifications. NOTE: the vendor reportedly sent \"a reply denying that any of the finding was a security vulnerability.\"",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-354"
          ],
          "VendorSeverity": {
            "debian": 1,
            "nvd": 2
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
              "V3Score": 5.3
            }
          },
          "References": [
            "https://github.com/kastel-security/Journald",
            "https://github.com/kastel-security/Journald/blob/main/journald-publication.pdf",
            "https://github.com/systemd/systemd/pull/28885",
            "https://github.com/systemd/systemd/releases"
          ],
          "PublishedDate": "2023-06-13T17:15:14.753Z",
          "LastModifiedDate": "2024-08-02T15:16:07.843Z"
        },
        {
          "VulnerabilityID": "CVE-2018-1000654",
          "PkgID": "libtasn1-6@4.13-3+deb10u1",
          "PkgName": "libtasn1-6",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libtasn1-6@4.13-3%2Bdeb10u1?arch=amd64\u0026distro=debian-10.13",
            "UID": "e431b4eecd0855fc"
          },
          "InstalledVersion": "4.13-3+deb10u1",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2018-1000654",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "libtasn1: Infinite loop in _asn1_expand_object_id(ptree) leads to memory exhaustion",
          "Description": "GNU Libtasn1-4.13 libtasn1-4.13 version libtasn1-4.13, libtasn1-4.12 contains a DoS, specifically CPU usage will reach 100% when running asn1Paser against the POC due to an issue in _asn1_expand_object_id(p_tree), after a long time, the program will be killed. This attack appears to be exploitable via parsing a crafted file.",
          "Severity": "LOW",
          "VendorSeverity": {
            "debian": 1,
            "nvd": 2,
            "photon": 2,
            "redhat": 1,
            "ubuntu": 1
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:C",
              "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
              "V2Score": 7.1,
              "V3Score": 5.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
              "V3Score": 4
            }
          },
          "References": [
            "http://lists.opensuse.org/opensuse-security-announce/2019-06/msg00009.html",
            "http://lists.opensuse.org/opensuse-security-announce/2019-06/msg00018.html",
            "http://www.securityfocus.com/bid/105151",
            "https://access.redhat.com/security/cve/CVE-2018-1000654",
            "https://gitlab.com/gnutls/libtasn1/issues/4",
            "https://lists.apache.org/thread.html/rf9fa47ab66495c78bb4120b0754dd9531ca2ff0430f6685ac9b07772%40%3Cdev.mina.apache.org%3E",
            "https://nvd.nist.gov/vuln/detail/CVE-2018-1000654",
            "https://ubuntu.com/security/notices/USN-5352-1",
            "https://www.cve.org/CVERecord?id=CVE-2018-1000654"
          ],
          "PublishedDate": "2018-08-20T19:31:44.87Z",
          "LastModifiedDate": "2023-11-07T02:51:12.86Z"
        },
        {
          "VulnerabilityID": "CVE-2021-39537",
          "VendorIDs": [
            "DLA-3682-1"
          ],
          "PkgID": "libtinfo6@6.1+20181013-2+deb10u3",
          "PkgName": "libtinfo6",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libtinfo6@6.1%2B20181013-2%2Bdeb10u3?arch=amd64\u0026distro=debian-10.13",
            "UID": "ca93d43f479a0cfd"
          },
          "InstalledVersion": "6.1+20181013-2+deb10u3",
          "FixedVersion": "6.1+20181013-2+deb10u5",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2021-39537",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "ncurses: heap-based buffer overflow in _nc_captoinfo() in captoinfo.c",
          "Description": "An issue was discovered in ncurses through v6.2-1. _nc_captoinfo in captoinfo.c has a heap-based buffer overflow.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-787"
          ],
          "VendorSeverity": {
            "amazon": 2,
            "cbl-mariner": 3,
            "nvd": 3,
            "photon": 3,
            "redhat": 1,
            "ubuntu": 1
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
              "V2Score": 6.8,
              "V3Score": 8.8
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
              "V3Score": 5.5
            }
          },
          "References": [
            "http://cvsweb.netbsd.org/bsdweb.cgi/pkgsrc/devel/ncurses/patches/patch-ncurses_tinfo_captoinfo.c?rev=1.1\u0026content-type=text/x-cvsweb-markup",
            "http://seclists.org/fulldisclosure/2022/Oct/28",
            "http://seclists.org/fulldisclosure/2022/Oct/41",
            "http://seclists.org/fulldisclosure/2022/Oct/43",
            "http://seclists.org/fulldisclosure/2022/Oct/45",
            "https://access.redhat.com/security/cve/CVE-2021-39537",
            "https://lists.debian.org/debian-lts-announce/2023/12/msg00004.html",
            "https://lists.gnu.org/archive/html/bug-ncurses/2020-08/msg00006.html",
            "https://lists.gnu.org/archive/html/bug-ncurses/2021-10/msg00023.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-39537",
            "https://security.netapp.com/advisory/ntap-20230427-0012/",
            "https://support.apple.com/kb/HT213443",
            "https://support.apple.com/kb/HT213444",
            "https://support.apple.com/kb/HT213488",
            "https://ubuntu.com/security/notices/USN-5477-1",
            "https://ubuntu.com/security/notices/USN-6099-1",
            "https://www.cve.org/CVERecord?id=CVE-2021-39537"
          ],
          "PublishedDate": "2021-09-20T16:15:12.477Z",
          "LastModifiedDate": "2023-12-03T20:15:06.86Z"
        },
        {
          "VulnerabilityID": "CVE-2023-29491",
          "VendorIDs": [
            "DLA-3682-1"
          ],
          "PkgID": "libtinfo6@6.1+20181013-2+deb10u3",
          "PkgName": "libtinfo6",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libtinfo6@6.1%2B20181013-2%2Bdeb10u3?arch=amd64\u0026distro=debian-10.13",
            "UID": "ca93d43f479a0cfd"
          },
          "InstalledVersion": "6.1+20181013-2+deb10u3",
          "FixedVersion": "6.1+20181013-2+deb10u5",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-29491",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "ncurses: Local users can trigger security-relevant memory corruption via malformed data",
          "Description": "ncurses before 6.4 20230408, when used by a setuid application, allows local users to trigger security-relevant memory corruption via malformed data in a terminfo database file that is found in $HOME/.terminfo or reached via the TERMINFO or TERM environment variable.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-787"
          ],
          "VendorSeverity": {
            "alma": 2,
            "amazon": 3,
            "cbl-mariner": 3,
            "nvd": 3,
            "oracle-oval": 2,
            "photon": 3,
            "redhat": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
              "V3Score": 7.8
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
              "V3Score": 7.8
            }
          },
          "References": [
            "http://ncurses.scripts.mit.edu/?p=ncurses.git%3Ba=commit%3Bh=eb51b1ea1f75a0ec17c9c5937cb28df1e8eeec56",
            "http://ncurses.scripts.mit.edu/?p=ncurses.git;a=commit;h=eb51b1ea1f75a0ec17c9c5937cb28df1e8eeec56",
            "http://www.openwall.com/lists/oss-security/2023/04/19/10",
            "http://www.openwall.com/lists/oss-security/2023/04/19/11",
            "https://access.redhat.com/errata/RHSA-2023:6698",
            "https://access.redhat.com/security/cve/CVE-2023-29491",
            "https://bugzilla.redhat.com/2191704",
            "https://errata.almalinux.org/9/ALSA-2023-6698.html",
            "https://invisible-island.net/ncurses/NEWS.html#index-t20230408",
            "https://linux.oracle.com/cve/CVE-2023-29491.html",
            "https://linux.oracle.com/errata/ELSA-2023-6698.html",
            "https://lists.debian.org/debian-lts-announce/2023/12/msg00004.html",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/LU4MYMKFEZQ5VSCVLRIZGDQOUW3T44GT/",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-29491",
            "https://security.netapp.com/advisory/ntap-20230517-0009/",
            "https://support.apple.com/kb/HT213843",
            "https://support.apple.com/kb/HT213844",
            "https://support.apple.com/kb/HT213845",
            "https://ubuntu.com/security/notices/USN-6099-1",
            "https://www.cve.org/CVERecord?id=CVE-2023-29491",
            "https://www.openwall.com/lists/oss-security/2023/04/12/5",
            "https://www.openwall.com/lists/oss-security/2023/04/13/4"
          ],
          "PublishedDate": "2023-04-14T01:15:08.57Z",
          "LastModifiedDate": "2024-01-31T03:15:07.86Z"
        },
        {
          "VulnerabilityID": "CVE-2020-19189",
          "VendorIDs": [
            "DLA-3586-1"
          ],
          "PkgID": "libtinfo6@6.1+20181013-2+deb10u3",
          "PkgName": "libtinfo6",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libtinfo6@6.1%2B20181013-2%2Bdeb10u3?arch=amd64\u0026distro=debian-10.13",
            "UID": "ca93d43f479a0cfd"
          },
          "InstalledVersion": "6.1+20181013-2+deb10u3",
          "FixedVersion": "6.1+20181013-2+deb10u4",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2020-19189",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "ncurses: Heap buffer overflow in postprocess_terminfo function in tinfo/parse_entry.c:997",
          "Description": "Buffer Overflow vulnerability in postprocess_terminfo function in tinfo/parse_entry.c:997 in ncurses 6.1 allows remote attackers to cause a denial of service via crafted command.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-787"
          ],
          "VendorSeverity": {
            "amazon": 2,
            "nvd": 2,
            "redhat": 1,
            "ubuntu": 2
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
              "V3Score": 6.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
              "V3Score": 6.5
            }
          },
          "References": [
            "http://seclists.org/fulldisclosure/2023/Dec/10",
            "http://seclists.org/fulldisclosure/2023/Dec/11",
            "http://seclists.org/fulldisclosure/2023/Dec/9",
            "https://access.redhat.com/security/cve/CVE-2020-19189",
            "https://github.com/zjuchenyuan/fuzzpoc/blob/master/infotocap_poc5.md",
            "https://lists.debian.org/debian-lts-announce/2023/09/msg00033.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2020-19189",
            "https://security.netapp.com/advisory/ntap-20231006-0005/",
            "https://support.apple.com/kb/HT214036",
            "https://support.apple.com/kb/HT214037",
            "https://support.apple.com/kb/HT214038",
            "https://ubuntu.com/security/notices/USN-6451-1",
            "https://www.cve.org/CVERecord?id=CVE-2020-19189"
          ],
          "PublishedDate": "2023-08-22T19:16:01.02Z",
          "LastModifiedDate": "2023-12-13T01:15:07.683Z"
        },
        {
          "VulnerabilityID": "CVE-2023-50495",
          "PkgID": "libtinfo6@6.1+20181013-2+deb10u3",
          "PkgName": "libtinfo6",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libtinfo6@6.1%2B20181013-2%2Bdeb10u3?arch=amd64\u0026distro=debian-10.13",
            "UID": "ca93d43f479a0cfd"
          },
          "InstalledVersion": "6.1+20181013-2+deb10u3",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-50495",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "ncurses: segmentation fault via _nc_wrap_entry()",
          "Description": "NCurse v6.4-20230418 was discovered to contain a segmentation fault via the component _nc_wrap_entry().",
          "Severity": "MEDIUM",
          "VendorSeverity": {
            "amazon": 2,
            "nvd": 2,
            "redhat": 1,
            "ubuntu": 1
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
              "V3Score": 6.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
              "V3Score": 6.5
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2023-50495",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/LU4MYMKFEZQ5VSCVLRIZGDQOUW3T44GT/",
            "https://lists.gnu.org/archive/html/bug-ncurses/2023-04/msg00020.html",
            "https://lists.gnu.org/archive/html/bug-ncurses/2023-04/msg00029.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-50495",
            "https://security.netapp.com/advisory/ntap-20240119-0008/",
            "https://ubuntu.com/security/notices/USN-6684-1",
            "https://www.cve.org/CVERecord?id=CVE-2023-50495"
          ],
          "PublishedDate": "2023-12-12T15:15:07.867Z",
          "LastModifiedDate": "2024-01-31T03:15:08.49Z"
        },
        {
          "VulnerabilityID": "CVE-2023-45918",
          "PkgID": "libtinfo6@6.1+20181013-2+deb10u3",
          "PkgName": "libtinfo6",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libtinfo6@6.1%2B20181013-2%2Bdeb10u3?arch=amd64\u0026distro=debian-10.13",
            "UID": "ca93d43f479a0cfd"
          },
          "InstalledVersion": "6.1+20181013-2+deb10u3",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-45918",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "ncurses: NULL pointer dereference in tgetstr in tinfo/lib_termcap.c",
          "Description": "ncurses 6.4-20230610 has a NULL pointer dereference in tgetstr in tinfo/lib_termcap.c.",
          "Severity": "LOW",
          "VendorSeverity": {
            "amazon": 2,
            "redhat": 1,
            "ubuntu": 1
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L",
              "V3Score": 3.3
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2023-45918",
            "https://lists.gnu.org/archive/html/bug-ncurses/2023-06/msg00005.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-45918",
            "https://security.netapp.com/advisory/ntap-20240315-0006/",
            "https://www.cve.org/CVERecord?id=CVE-2023-45918"
          ],
          "PublishedDate": "2024-02-16T22:15:07.88Z",
          "LastModifiedDate": "2024-03-15T11:15:08.51Z"
        },
        {
          "VulnerabilityID": "CVE-2019-3843",
          "PkgID": "libudev1@241-7~deb10u9",
          "PkgName": "libudev1",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libudev1@241-7~deb10u9?arch=amd64\u0026distro=debian-10.13",
            "UID": "910f8e0ab1fb72e1"
          },
          "InstalledVersion": "241-7~deb10u9",
          "Status": "will_not_fix",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2019-3843",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "systemd: services with DynamicUser can create SUID/SGID binaries",
          "Description": "It was discovered that a systemd service that uses DynamicUser property can create a SUID/SGID binary that would be allowed to run as the transient service UID/GID even after the service is terminated. A local attacker may use this flaw to access resources that will be owned by a potentially different service in the future, when the UID/GID will be recycled.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-269",
            "CWE-266"
          ],
          "VendorSeverity": {
            "cbl-mariner": 3,
            "nvd": 3,
            "oracle-oval": 2,
            "photon": 3,
            "redhat": 2,
            "ubuntu": 1
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:L/AC:L/Au:N/C:P/I:P/A:P",
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
              "V2Score": 4.6,
              "V3Score": 7.8
            },
            "redhat": {
              "V3Vector": "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:L",
              "V3Score": 4.5
            }
          },
          "References": [
            "http://www.securityfocus.com/bid/108116",
            "https://access.redhat.com/security/cve/CVE-2019-3843",
            "https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2019-3843",
            "https://github.com/systemd/systemd-stable/pull/54 (backport for v241-stable)",
            "https://linux.oracle.com/cve/CVE-2019-3843.html",
            "https://linux.oracle.com/errata/ELSA-2020-1794.html",
            "https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b%40%3Cissues.bookkeeper.apache.org%3E",
            "https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4%40%3Cissues.bookkeeper.apache.org%3E",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/5JXQAKSTMABZ46EVCRMW62DHWYHTTFES/",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-3843",
            "https://security.netapp.com/advisory/ntap-20190619-0002/",
            "https://ubuntu.com/security/notices/USN-4269-1",
            "https://usn.ubuntu.com/4269-1/",
            "https://www.cve.org/CVERecord?id=CVE-2019-3843"
          ],
          "PublishedDate": "2019-04-26T21:29:00.36Z",
          "LastModifiedDate": "2023-11-07T03:10:14.033Z"
        },
        {
          "VulnerabilityID": "CVE-2019-3844",
          "PkgID": "libudev1@241-7~deb10u9",
          "PkgName": "libudev1",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libudev1@241-7~deb10u9?arch=amd64\u0026distro=debian-10.13",
            "UID": "910f8e0ab1fb72e1"
          },
          "InstalledVersion": "241-7~deb10u9",
          "Status": "will_not_fix",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2019-3844",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "systemd: services with DynamicUser can get new privileges and create SGID binaries",
          "Description": "It was discovered that a systemd service that uses DynamicUser property can get new privileges through the execution of SUID binaries, which would allow to create binaries owned by the service transient group with the setgid bit set. A local attacker may use this flaw to access resources that will be owned by a potentially different service in the future, when the GID will be recycled.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-268"
          ],
          "VendorSeverity": {
            "cbl-mariner": 3,
            "nvd": 3,
            "oracle-oval": 2,
            "photon": 3,
            "redhat": 2,
            "ubuntu": 1
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:L/AC:L/Au:N/C:P/I:P/A:P",
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
              "V2Score": 4.6,
              "V3Score": 7.8
            },
            "redhat": {
              "V3Vector": "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:L",
              "V3Score": 4.5
            }
          },
          "References": [
            "http://www.securityfocus.com/bid/108096",
            "https://access.redhat.com/security/cve/CVE-2019-3844",
            "https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2019-3844",
            "https://linux.oracle.com/cve/CVE-2019-3844.html",
            "https://linux.oracle.com/errata/ELSA-2020-1794.html",
            "https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b%40%3Cissues.bookkeeper.apache.org%3E",
            "https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4%40%3Cissues.bookkeeper.apache.org%3E",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-3844",
            "https://security.netapp.com/advisory/ntap-20190619-0002/",
            "https://ubuntu.com/security/notices/USN-4269-1",
            "https://usn.ubuntu.com/4269-1/",
            "https://www.cve.org/CVERecord?id=CVE-2019-3844"
          ],
          "PublishedDate": "2019-04-26T21:29:00.423Z",
          "LastModifiedDate": "2023-11-07T03:10:14.13Z"
        },
        {
          "VulnerabilityID": "CVE-2023-50387",
          "PkgID": "libudev1@241-7~deb10u9",
          "PkgName": "libudev1",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libudev1@241-7~deb10u9?arch=amd64\u0026distro=debian-10.13",
            "UID": "910f8e0ab1fb72e1"
          },
          "InstalledVersion": "241-7~deb10u9",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-50387",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "bind9: KeyTrap - Extreme CPU consumption in DNSSEC validator",
          "Description": "Certain DNSSEC aspects of the DNS protocol (in RFC 4033, 4034, 4035, 6840, and related RFCs) allow remote attackers to cause a denial of service (CPU consumption) via one or more DNSSEC responses, aka the \"KeyTrap\" issue. One of the concerns is that, when there is a zone with many DNSKEY and RRSIG records, the protocol specification implies that an algorithm must evaluate all combinations of DNSKEY and RRSIG records.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-770"
          ],
          "VendorSeverity": {
            "alma": 3,
            "amazon": 3,
            "azure": 3,
            "cbl-mariner": 3,
            "nvd": 3,
            "oracle-oval": 3,
            "photon": 3,
            "redhat": 3,
            "rocky": 3,
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
            "http://www.openwall.com/lists/oss-security/2024/02/16/2",
            "http://www.openwall.com/lists/oss-security/2024/02/16/3",
            "https://access.redhat.com/errata/RHSA-2024:2551",
            "https://access.redhat.com/security/cve/CVE-2023-50387",
            "https://blog.powerdns.com/2024/02/13/powerdns-recursor-4-8-6-4-9-3-5-0-2-released",
            "https://bugzilla.redhat.com/2263896",
            "https://bugzilla.redhat.com/2263897",
            "https://bugzilla.redhat.com/2263909",
            "https://bugzilla.redhat.com/2263911",
            "https://bugzilla.redhat.com/2263914",
            "https://bugzilla.redhat.com/2263917",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2263896",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2263897",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2263909",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2263911",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2263914",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2263917",
            "https://bugzilla.suse.com/show_bug.cgi?id=1219823",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4408",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-50387",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-50868",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-5517",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-5679",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-6516",
            "https://docs.powerdns.com/recursor/security-advisories/powerdns-advisory-2024-01.html",
            "https://errata.almalinux.org/9/ALSA-2024-2551.html",
            "https://errata.rockylinux.org/RLSA-2024:2551",
            "https://gitlab.nic.cz/knot/knot-resolver/-/releases/v5.7.1",
            "https://kb.isc.org/docs/cve-2023-50387",
            "https://linux.oracle.com/cve/CVE-2023-50387.html",
            "https://linux.oracle.com/errata/ELSA-2024-3741.html",
            "https://lists.debian.org/debian-lts-announce/2024/02/msg00006.html",
            "https://lists.debian.org/debian-lts-announce/2024/05/msg00011.html",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/6FV5O347JTX7P5OZA6NGO4MKTXRXMKOZ/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/BUIP7T7Z4T3UHLXFWG6XIVDP4GYPD3AI/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/HVRDSJVZKMCXKKPP6PNR62T7RWZ3YSDZ/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/IGSLGKUAQTW5JPPZCMF5YPEYALLRUZZ6/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/PNNHZSZPG2E7NBMBNYPGHCFI4V4XRWNQ/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/RGS7JN6FZXUSTC2XKQHH27574XOULYYJ/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/SVYA42BLXUCIDLD35YIJPJSHDIADNYMP/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/TEXGOYGW7DBS3N2QSSQONZ4ENIRQEAPG/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/UQESRWMJCF4JEYJEAKLRM6CT55GLJAB7/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/ZDZFMEKQTZ4L7RY46FCENWFB5MDT263R/",
            "https://lists.thekelleys.org.uk/pipermail/dnsmasq-discuss/2024q1/017430.html",
            "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-50387",
            "https://news.ycombinator.com/item?id=39367411",
            "https://news.ycombinator.com/item?id=39372384",
            "https://nlnetlabs.nl/downloads/unbound/CVE-2023-50387_CVE-2023-50868.txt",
            "https://nlnetlabs.nl/news/2024/Feb/13/unbound-1.19.1-released/",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-50387",
            "https://security.netapp.com/advisory/ntap-20240307-0007/",
            "https://ubuntu.com/security/notices/USN-6633-1",
            "https://ubuntu.com/security/notices/USN-6642-1",
            "https://ubuntu.com/security/notices/USN-6657-1",
            "https://ubuntu.com/security/notices/USN-6657-2",
            "https://ubuntu.com/security/notices/USN-6665-1",
            "https://ubuntu.com/security/notices/USN-6723-1",
            "https://www.athene-center.de/aktuelles/key-trap",
            "https://www.athene-center.de/fileadmin/content/PDF/Technical_Report_KeyTrap.pdf",
            "https://www.cve.org/CVERecord?id=CVE-2023-50387",
            "https://www.isc.org/blogs/2024-bind-security-release/",
            "https://www.knot-resolver.cz/2024-02-13-knot-resolver-5.7.1.html",
            "https://www.securityweek.com/keytrap-dns-attack-could-disable-large-parts-of-internet-researchers/",
            "https://www.theregister.com/2024/02/13/dnssec_vulnerability_internet/"
          ],
          "PublishedDate": "2024-02-14T16:15:45.3Z",
          "LastModifiedDate": "2024-06-10T17:16:15.963Z"
        },
        {
          "VulnerabilityID": "CVE-2023-50868",
          "PkgID": "libudev1@241-7~deb10u9",
          "PkgName": "libudev1",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libudev1@241-7~deb10u9?arch=amd64\u0026distro=debian-10.13",
            "UID": "910f8e0ab1fb72e1"
          },
          "InstalledVersion": "241-7~deb10u9",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-50868",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "bind9: Preparing an NSEC3 closest encloser proof can exhaust CPU resources",
          "Description": "The Closest Encloser Proof aspect of the DNS protocol (in RFC 5155 when RFC 9276 guidance is skipped) allows remote attackers to cause a denial of service (CPU consumption for SHA-1 computations) via DNSSEC responses in a random subdomain attack, aka the \"NSEC3\" issue. The RFC 5155 specification implies that an algorithm must perform thousands of iterations of a hash function in certain situations.",
          "Severity": "HIGH",
          "VendorSeverity": {
            "alma": 3,
            "amazon": 3,
            "azure": 3,
            "cbl-mariner": 3,
            "oracle-oval": 3,
            "photon": 3,
            "redhat": 3,
            "rocky": 3,
            "ubuntu": 2
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 7.5
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2024/02/16/2",
            "http://www.openwall.com/lists/oss-security/2024/02/16/3",
            "https://access.redhat.com/errata/RHSA-2024:2551",
            "https://access.redhat.com/security/cve/CVE-2023-50868",
            "https://blog.powerdns.com/2024/02/13/powerdns-recursor-4-8-6-4-9-3-5-0-2-released",
            "https://bugzilla.redhat.com/2263896",
            "https://bugzilla.redhat.com/2263897",
            "https://bugzilla.redhat.com/2263909",
            "https://bugzilla.redhat.com/2263911",
            "https://bugzilla.redhat.com/2263914",
            "https://bugzilla.redhat.com/2263917",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2263896",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2263897",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2263909",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2263911",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2263914",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2263917",
            "https://bugzilla.suse.com/show_bug.cgi?id=1219826",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4408",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-50387",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-50868",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-5517",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-5679",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-6516",
            "https://datatracker.ietf.org/doc/html/rfc5155",
            "https://docs.powerdns.com/recursor/security-advisories/powerdns-advisory-2024-01.html",
            "https://errata.almalinux.org/9/ALSA-2024-2551.html",
            "https://errata.rockylinux.org/RLSA-2024:2551",
            "https://gitlab.nic.cz/knot/knot-resolver/-/releases/v5.7.1",
            "https://kb.isc.org/docs/cve-2023-50868",
            "https://linux.oracle.com/cve/CVE-2023-50868.html",
            "https://linux.oracle.com/errata/ELSA-2024-3741.html",
            "https://lists.debian.org/debian-lts-announce/2024/02/msg00006.html",
            "https://lists.debian.org/debian-lts-announce/2024/05/msg00011.html",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/6FV5O347JTX7P5OZA6NGO4MKTXRXMKOZ/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/BUIP7T7Z4T3UHLXFWG6XIVDP4GYPD3AI/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/HVRDSJVZKMCXKKPP6PNR62T7RWZ3YSDZ/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/IGSLGKUAQTW5JPPZCMF5YPEYALLRUZZ6/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/PNNHZSZPG2E7NBMBNYPGHCFI4V4XRWNQ/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/RGS7JN6FZXUSTC2XKQHH27574XOULYYJ/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/SVYA42BLXUCIDLD35YIJPJSHDIADNYMP/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/TEXGOYGW7DBS3N2QSSQONZ4ENIRQEAPG/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/UQESRWMJCF4JEYJEAKLRM6CT55GLJAB7/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/ZDZFMEKQTZ4L7RY46FCENWFB5MDT263R/",
            "https://lists.thekelleys.org.uk/pipermail/dnsmasq-discuss/2024q1/017430.html",
            "https://nlnetlabs.nl/downloads/unbound/CVE-2023-50387_CVE-2023-50868.txt",
            "https://nlnetlabs.nl/news/2024/Feb/13/unbound-1.19.1-released/",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-50868",
            "https://security.netapp.com/advisory/ntap-20240307-0008/",
            "https://ubuntu.com/security/notices/USN-6633-1",
            "https://ubuntu.com/security/notices/USN-6642-1",
            "https://ubuntu.com/security/notices/USN-6657-1",
            "https://ubuntu.com/security/notices/USN-6657-2",
            "https://ubuntu.com/security/notices/USN-6665-1",
            "https://ubuntu.com/security/notices/USN-6723-1",
            "https://www.cve.org/CVERecord?id=CVE-2023-50868",
            "https://www.isc.org/blogs/2024-bind-security-release/",
            "https://www.knot-resolver.cz/2024-02-13-knot-resolver-5.7.1.html"
          ],
          "PublishedDate": "2024-02-14T16:15:45.377Z",
          "LastModifiedDate": "2024-06-10T17:16:16.2Z"
        },
        {
          "VulnerabilityID": "CVE-2021-3997",
          "PkgID": "libudev1@241-7~deb10u9",
          "PkgName": "libudev1",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libudev1@241-7~deb10u9?arch=amd64\u0026distro=debian-10.13",
            "UID": "910f8e0ab1fb72e1"
          },
          "InstalledVersion": "241-7~deb10u9",
          "Status": "will_not_fix",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2021-3997",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "systemd: Uncontrolled recursion in systemd-tmpfiles when removing files",
          "Description": "A flaw was found in systemd. An uncontrolled recursion in systemd-tmpfiles may lead to a denial of service at boot time when too many nested directories are created in /tmp.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-674"
          ],
          "VendorSeverity": {
            "amazon": 2,
            "cbl-mariner": 2,
            "nvd": 2,
            "photon": 2,
            "redhat": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 5.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 5.5
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2021-3997",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2024639",
            "https://github.com/systemd/systemd/commit/5b1cf7a9be37e20133c0208005274ce4a5b5c6a1",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-3997",
            "https://security.gentoo.org/glsa/202305-15",
            "https://ubuntu.com/security/notices/USN-5226-1",
            "https://www.cve.org/CVERecord?id=CVE-2021-3997",
            "https://www.openwall.com/lists/oss-security/2022/01/10/2"
          ],
          "PublishedDate": "2022-08-23T20:15:08.67Z",
          "LastModifiedDate": "2023-05-03T12:15:15.95Z"
        },
        {
          "VulnerabilityID": "CVE-2022-3821",
          "VendorIDs": [
            "DLA-3474-1"
          ],
          "PkgID": "libudev1@241-7~deb10u9",
          "PkgName": "libudev1",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libudev1@241-7~deb10u9?arch=amd64\u0026distro=debian-10.13",
            "UID": "910f8e0ab1fb72e1"
          },
          "InstalledVersion": "241-7~deb10u9",
          "FixedVersion": "241-7~deb10u10",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2022-3821",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "systemd: buffer overrun in format_timespan() function",
          "Description": "An off-by-one Error issue was discovered in Systemd in format_timespan() function of time-util.c. An attacker could supply specific values for time and accuracy that leads to buffer overrun in format_timespan(), leading to a Denial of Service.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-193"
          ],
          "VendorSeverity": {
            "alma": 2,
            "amazon": 2,
            "azure": 2,
            "cbl-mariner": 2,
            "nvd": 2,
            "oracle-oval": 2,
            "photon": 2,
            "redhat": 2,
            "rocky": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 5.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 5.5
            }
          },
          "References": [
            "https://access.redhat.com/errata/RHSA-2023:0336",
            "https://access.redhat.com/security/cve/CVE-2022-3821",
            "https://bugzilla.redhat.com/2139327",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2139327",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-3821",
            "https://errata.almalinux.org/9/ALSA-2023-0336.html",
            "https://errata.rockylinux.org/RLSA-2023:0336",
            "https://github.com/systemd/systemd/commit/9102c625a673a3246d7e73d8737f3494446bad4e",
            "https://github.com/systemd/systemd/issues/23928",
            "https://github.com/systemd/systemd/pull/23933",
            "https://linux.oracle.com/cve/CVE-2022-3821.html",
            "https://linux.oracle.com/errata/ELSA-2023-0336.html",
            "https://lists.debian.org/debian-lts-announce/2023/06/msg00036.html",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/RVBQC2VLSDVQAPJTEMTREXDL4HYLXG2P/",
            "https://nvd.nist.gov/vuln/detail/CVE-2022-3821",
            "https://security.gentoo.org/glsa/202305-15",
            "https://ubuntu.com/security/notices/USN-5928-1",
            "https://www.cve.org/CVERecord?id=CVE-2022-3821"
          ],
          "PublishedDate": "2022-11-08T22:15:16.7Z",
          "LastModifiedDate": "2023-11-07T03:51:50.43Z"
        },
        {
          "VulnerabilityID": "CVE-2022-4415",
          "PkgID": "libudev1@241-7~deb10u9",
          "PkgName": "libudev1",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libudev1@241-7~deb10u9?arch=amd64\u0026distro=debian-10.13",
            "UID": "910f8e0ab1fb72e1"
          },
          "InstalledVersion": "241-7~deb10u9",
          "Status": "will_not_fix",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2022-4415",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "systemd: local information leak due to systemd-coredump not respecting fs.suid_dumpable kernel setting",
          "Description": "A vulnerability was found in systemd. This security flaw can cause a local information leak due to systemd-coredump not respecting the fs.suid_dumpable kernel setting.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-200"
          ],
          "VendorSeverity": {
            "alma": 2,
            "amazon": 2,
            "azure": 2,
            "cbl-mariner": 2,
            "nvd": 2,
            "oracle-oval": 2,
            "photon": 2,
            "redhat": 2,
            "rocky": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
              "V3Score": 5.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
              "V3Score": 5.5
            }
          },
          "References": [
            "https://access.redhat.com/errata/RHSA-2023:0954",
            "https://access.redhat.com/security/cve/CVE-2022-4415",
            "https://bugzilla.redhat.com/2149063",
            "https://bugzilla.redhat.com/2155515",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2149063",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2155515",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-4415",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-45873",
            "https://errata.almalinux.org/9/ALSA-2023-0954.html",
            "https://errata.rockylinux.org/RLSA-2023:0954",
            "https://github.com/systemd/systemd/commit/b7641425659243c09473cd8fb3aef2c0d4a3eb9c",
            "https://linux.oracle.com/cve/CVE-2022-4415.html",
            "https://linux.oracle.com/errata/ELSA-2023-0954.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2022-4415",
            "https://ubuntu.com/security/notices/USN-5928-1",
            "https://www.cve.org/CVERecord?id=CVE-2022-4415",
            "https://www.openwall.com/lists/oss-security/2022/12/21/3"
          ],
          "PublishedDate": "2023-01-11T15:15:09.59Z",
          "LastModifiedDate": "2023-02-02T16:19:28.633Z"
        },
        {
          "VulnerabilityID": "CVE-2023-7008",
          "PkgID": "libudev1@241-7~deb10u9",
          "PkgName": "libudev1",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libudev1@241-7~deb10u9?arch=amd64\u0026distro=debian-10.13",
            "UID": "910f8e0ab1fb72e1"
          },
          "InstalledVersion": "241-7~deb10u9",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-7008",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "systemd-resolved: Unsigned name response in signed zone is not refused when DNSSEC=yes",
          "Description": "A vulnerability was found in systemd-resolved. This issue may allow systemd-resolved to accept records of DNSSEC-signed domains even when they have no signature, allowing man-in-the-middles (or the upstream DNS resolver) to manipulate records.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-300"
          ],
          "VendorSeverity": {
            "alma": 2,
            "amazon": 2,
            "cbl-mariner": 2,
            "nvd": 2,
            "oracle-oval": 2,
            "redhat": 2,
            "rocky": 2,
            "ubuntu": 1
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N",
              "V3Score": 5.9
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N",
              "V3Score": 5.9
            }
          },
          "References": [
            "https://access.redhat.com/errata/RHSA-2024:2463",
            "https://access.redhat.com/errata/RHSA-2024:3203",
            "https://access.redhat.com/security/cve/CVE-2023-7008",
            "https://bugzilla.redhat.com/2222672",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2222261",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2222672",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-7008",
            "https://errata.almalinux.org/9/ALSA-2024-2463.html",
            "https://errata.rockylinux.org/RLSA-2024:2463",
            "https://github.com/systemd/systemd/issues/25676",
            "https://linux.oracle.com/cve/CVE-2023-7008.html",
            "https://linux.oracle.com/errata/ELSA-2024-3203.html",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/4GMDEG5PKONWNHOEYSUDRT6JEOISRMN2/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/QHNBXGKJWISJETTTDTZKTBFIBJUOSLKL/",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-7008",
            "https://www.cve.org/CVERecord?id=CVE-2023-7008"
          ],
          "PublishedDate": "2023-12-23T13:15:07.573Z",
          "LastModifiedDate": "2024-05-22T17:16:10.83Z"
        },
        {
          "VulnerabilityID": "CVE-2013-4392",
          "PkgID": "libudev1@241-7~deb10u9",
          "PkgName": "libudev1",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libudev1@241-7~deb10u9?arch=amd64\u0026distro=debian-10.13",
            "UID": "910f8e0ab1fb72e1"
          },
          "InstalledVersion": "241-7~deb10u9",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2013-4392",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "systemd: TOCTOU race condition when updating file permissions and SELinux security contexts",
          "Description": "systemd, when updating file permissions, allows local users to change the permissions and SELinux security contexts for arbitrary files via a symlink attack on unspecified files.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-59"
          ],
          "VendorSeverity": {
            "debian": 1,
            "nvd": 1,
            "redhat": 2
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:L/AC:M/Au:N/C:P/I:P/A:N",
              "V2Score": 3.3
            },
            "redhat": {
              "V2Vector": "AV:L/AC:M/Au:N/C:P/I:P/A:N",
              "V2Score": 3.3
            }
          },
          "References": [
            "http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=725357",
            "http://www.openwall.com/lists/oss-security/2013/10/01/9",
            "https://access.redhat.com/security/cve/CVE-2013-4392",
            "https://bugzilla.redhat.com/show_bug.cgi?id=859060",
            "https://nvd.nist.gov/vuln/detail/CVE-2013-4392",
            "https://www.cve.org/CVERecord?id=CVE-2013-4392"
          ],
          "PublishedDate": "2013-10-28T22:55:03.773Z",
          "LastModifiedDate": "2022-01-31T17:49:14.387Z"
        },
        {
          "VulnerabilityID": "CVE-2019-20386",
          "PkgID": "libudev1@241-7~deb10u9",
          "PkgName": "libudev1",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libudev1@241-7~deb10u9?arch=amd64\u0026distro=debian-10.13",
            "UID": "910f8e0ab1fb72e1"
          },
          "InstalledVersion": "241-7~deb10u9",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2019-20386",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "systemd: memory leak in button_open() in login/logind-button.c when udev events are received",
          "Description": "An issue was discovered in button_open in login/logind-button.c in systemd before 243. When executing the udevadm trigger command, a memory leak may occur.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-401"
          ],
          "VendorSeverity": {
            "amazon": 2,
            "cbl-mariner": 1,
            "debian": 1,
            "nvd": 1,
            "oracle-oval": 1,
            "photon": 1,
            "redhat": 1,
            "ubuntu": 1
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:L/AC:L/Au:N/C:N/I:N/A:P",
              "V3Vector": "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
              "V2Score": 2.1,
              "V3Score": 2.4
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
              "V3Score": 2.4
            }
          },
          "References": [
            "http://lists.opensuse.org/opensuse-security-announce/2020-02/msg00014.html",
            "https://access.redhat.com/security/cve/CVE-2019-20386",
            "https://github.com/systemd/systemd/commit/b2774a3ae692113e1f47a336a6c09bac9cfb49ad",
            "https://linux.oracle.com/cve/CVE-2019-20386.html",
            "https://linux.oracle.com/errata/ELSA-2020-4553.html",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/HZPCOMW5X6IZZXASCDD2CNW2DLF3YADC/",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-20386",
            "https://security.netapp.com/advisory/ntap-20200210-0002/",
            "https://ubuntu.com/security/notices/USN-4269-1",
            "https://usn.ubuntu.com/4269-1/",
            "https://www.cve.org/CVERecord?id=CVE-2019-20386"
          ],
          "PublishedDate": "2020-01-21T06:15:11.827Z",
          "LastModifiedDate": "2023-11-07T03:09:08.387Z"
        },
        {
          "VulnerabilityID": "CVE-2020-13529",
          "PkgID": "libudev1@241-7~deb10u9",
          "PkgName": "libudev1",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libudev1@241-7~deb10u9?arch=amd64\u0026distro=debian-10.13",
            "UID": "910f8e0ab1fb72e1"
          },
          "InstalledVersion": "241-7~deb10u9",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2020-13529",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "systemd: DHCP FORCERENEW authentication not implemented can cause a system running the DHCP client to have its network reconfigured",
          "Description": "An exploitable denial-of-service vulnerability exists in Systemd 245. A specially crafted DHCP FORCERENEW packet can cause a server running the DHCP client to be vulnerable to a DHCP ACK spoofing attack. An attacker can forge a pair of FORCERENEW and DCHP ACK packets to reconfigure the server.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-290"
          ],
          "VendorSeverity": {
            "alma": 2,
            "amazon": 3,
            "debian": 1,
            "nvd": 2,
            "oracle-oval": 2,
            "photon": 2,
            "redhat": 2,
            "ubuntu": 1
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:A/AC:M/Au:N/C:N/I:N/A:P",
              "V3Vector": "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:C/C:N/I:N/A:H",
              "V2Score": 2.9,
              "V3Score": 6.1
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:C/C:N/I:N/A:H",
              "V3Score": 6.1
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2021/08/04/2",
            "http://www.openwall.com/lists/oss-security/2021/08/17/3",
            "http://www.openwall.com/lists/oss-security/2021/09/07/3",
            "https://access.redhat.com/security/cve/CVE-2020-13529",
            "https://linux.oracle.com/cve/CVE-2020-13529.html",
            "https://linux.oracle.com/errata/ELSA-2021-4361.html",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/42TMJVNYRY65B4QCJICBYOEIVZV3KUYI/",
            "https://nvd.nist.gov/vuln/detail/CVE-2020-13529",
            "https://security.gentoo.org/glsa/202107-48",
            "https://security.netapp.com/advisory/ntap-20210625-0005/",
            "https://talosintelligence.com/vulnerability_reports/TALOS-2020-1142",
            "https://ubuntu.com/security/notices/USN-5013-1",
            "https://ubuntu.com/security/notices/USN-5013-2",
            "https://www.cve.org/CVERecord?id=CVE-2020-13529"
          ],
          "PublishedDate": "2021-05-10T16:15:07.373Z",
          "LastModifiedDate": "2023-11-07T03:16:42.717Z"
        },
        {
          "VulnerabilityID": "CVE-2023-31437",
          "PkgID": "libudev1@241-7~deb10u9",
          "PkgName": "libudev1",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libudev1@241-7~deb10u9?arch=amd64\u0026distro=debian-10.13",
            "UID": "910f8e0ab1fb72e1"
          },
          "InstalledVersion": "241-7~deb10u9",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-31437",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "An issue was discovered in systemd 253. An attacker can modify a seale ...",
          "Description": "An issue was discovered in systemd 253. An attacker can modify a sealed log file such that, in some views, not all existing and sealed log messages are displayed. NOTE: the vendor reportedly sent \"a reply denying that any of the finding was a security vulnerability.\"",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-354"
          ],
          "VendorSeverity": {
            "debian": 1,
            "nvd": 2
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
              "V3Score": 5.3
            }
          },
          "References": [
            "https://github.com/kastel-security/Journald",
            "https://github.com/kastel-security/Journald/blob/main/journald-publication.pdf",
            "https://github.com/systemd/systemd/releases"
          ],
          "PublishedDate": "2023-06-13T17:15:14.657Z",
          "LastModifiedDate": "2024-08-02T15:16:07.647Z"
        },
        {
          "VulnerabilityID": "CVE-2023-31438",
          "PkgID": "libudev1@241-7~deb10u9",
          "PkgName": "libudev1",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libudev1@241-7~deb10u9?arch=amd64\u0026distro=debian-10.13",
            "UID": "910f8e0ab1fb72e1"
          },
          "InstalledVersion": "241-7~deb10u9",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-31438",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "An issue was discovered in systemd 253. An attacker can truncate a sea ...",
          "Description": "An issue was discovered in systemd 253. An attacker can truncate a sealed log file and then resume log sealing such that checking the integrity shows no error, despite modifications. NOTE: the vendor reportedly sent \"a reply denying that any of the finding was a security vulnerability.\"",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-354"
          ],
          "VendorSeverity": {
            "debian": 1,
            "nvd": 2
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
              "V3Score": 5.3
            }
          },
          "References": [
            "https://github.com/kastel-security/Journald",
            "https://github.com/kastel-security/Journald/blob/main/journald-publication.pdf",
            "https://github.com/systemd/systemd/pull/28886",
            "https://github.com/systemd/systemd/releases"
          ],
          "PublishedDate": "2023-06-13T17:15:14.707Z",
          "LastModifiedDate": "2024-08-02T15:16:07.753Z"
        },
        {
          "VulnerabilityID": "CVE-2023-31439",
          "PkgID": "libudev1@241-7~deb10u9",
          "PkgName": "libudev1",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libudev1@241-7~deb10u9?arch=amd64\u0026distro=debian-10.13",
            "UID": "910f8e0ab1fb72e1"
          },
          "InstalledVersion": "241-7~deb10u9",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-31439",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "An issue was discovered in systemd 253. An attacker can modify the con ...",
          "Description": "An issue was discovered in systemd 253. An attacker can modify the contents of past events in a sealed log file and then adjust the file such that checking the integrity shows no error, despite modifications. NOTE: the vendor reportedly sent \"a reply denying that any of the finding was a security vulnerability.\"",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-354"
          ],
          "VendorSeverity": {
            "debian": 1,
            "nvd": 2
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
              "V3Score": 5.3
            }
          },
          "References": [
            "https://github.com/kastel-security/Journald",
            "https://github.com/kastel-security/Journald/blob/main/journald-publication.pdf",
            "https://github.com/systemd/systemd/pull/28885",
            "https://github.com/systemd/systemd/releases"
          ],
          "PublishedDate": "2023-06-13T17:15:14.753Z",
          "LastModifiedDate": "2024-08-02T15:16:07.843Z"
        },
        {
          "VulnerabilityID": "CVE-2024-28085",
          "VendorIDs": [
            "DLA-3782-1"
          ],
          "PkgID": "libuuid1@2.33.1-0.1",
          "PkgName": "libuuid1",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libuuid1@2.33.1-0.1?arch=amd64\u0026distro=debian-10.13",
            "UID": "4feef3f42b91580a"
          },
          "InstalledVersion": "2.33.1-0.1",
          "FixedVersion": "2.33.1-0.1+deb10u1",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-28085",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "util-linux: CVE-2024-28085: wall: escape sequence injection",
          "Description": "wall in util-linux through 2.40, often installed with setgid tty permissions, allows escape sequences to be sent to other users' terminals through argv. (Specifically, escape sequences received from stdin are blocked, but escape sequences received from argv are not blocked.) There may be plausible scenarios where this leads to account takeover.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-150"
          ],
          "VendorSeverity": {
            "cbl-mariner": 4,
            "photon": 3,
            "redhat": 3,
            "ubuntu": 2
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N",
              "V3Score": 8.4
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2024/03/27/5",
            "http://www.openwall.com/lists/oss-security/2024/03/27/6",
            "http://www.openwall.com/lists/oss-security/2024/03/27/7",
            "http://www.openwall.com/lists/oss-security/2024/03/27/8",
            "http://www.openwall.com/lists/oss-security/2024/03/27/9",
            "http://www.openwall.com/lists/oss-security/2024/03/28/1",
            "http://www.openwall.com/lists/oss-security/2024/03/28/2",
            "http://www.openwall.com/lists/oss-security/2024/03/28/3",
            "https://access.redhat.com/security/cve/CVE-2024-28085",
            "https://github.com/skyler-ferrante/CVE-2024-28085",
            "https://github.com/util-linux/util-linux/security/advisories/GHSA-xv2h-c6ww-mrjq",
            "https://lists.debian.org/debian-lts-announce/2024/04/msg00005.html",
            "https://mirrors.edge.kernel.org/pub/linux/utils/util-linux/",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-28085",
            "https://people.rit.edu/sjf5462/6831711781/wall_2_27_2024.txt",
            "https://security.netapp.com/advisory/ntap-20240531-0003/",
            "https://ubuntu.com/security/notices/USN-6719-1",
            "https://ubuntu.com/security/notices/USN-6719-2",
            "https://www.cve.org/CVERecord?id=CVE-2024-28085",
            "https://www.openwall.com/lists/oss-security/2024/03/27/5"
          ],
          "PublishedDate": "2024-03-27T19:15:48.367Z",
          "LastModifiedDate": "2024-08-26T21:35:09.31Z"
        },
        {
          "VulnerabilityID": "CVE-2021-37600",
          "VendorIDs": [
            "DLA-3782-1"
          ],
          "PkgID": "libuuid1@2.33.1-0.1",
          "PkgName": "libuuid1",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libuuid1@2.33.1-0.1?arch=amd64\u0026distro=debian-10.13",
            "UID": "4feef3f42b91580a"
          },
          "InstalledVersion": "2.33.1-0.1",
          "FixedVersion": "2.33.1-0.1+deb10u1",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2021-37600",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "util-linux: integer overflow can lead to buffer overflow in get_sem_elements() in sys-utils/ipcutils.c",
          "Description": "An integer overflow in util-linux through 2.37.1 can potentially cause a buffer overflow if an attacker were able to use system resources in a way that leads to a large number in the /proc/sysvipc/sem file. NOTE: this is unexploitable in GNU C Library environments, and possibly in all realistic environments.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-190"
          ],
          "VendorSeverity": {
            "amazon": 1,
            "cbl-mariner": 2,
            "nvd": 2,
            "photon": 2,
            "redhat": 1,
            "ubuntu": 1
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:L/AC:H/Au:N/C:N/I:N/A:P",
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
              "V2Score": 1.2,
              "V3Score": 5.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:H",
              "V3Score": 4.7
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2021-37600",
            "https://github.com/karelzak/util-linux/commit/1c9143d0c1f979c3daf10e1c37b5b1e916c22a1c",
            "https://github.com/karelzak/util-linux/issues/1395",
            "https://lists.debian.org/debian-lts-announce/2024/04/msg00005.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-37600",
            "https://security.gentoo.org/glsa/202401-08",
            "https://security.netapp.com/advisory/ntap-20210902-0002/",
            "https://www.cve.org/CVERecord?id=CVE-2021-37600"
          ],
          "PublishedDate": "2021-07-30T14:15:18.737Z",
          "LastModifiedDate": "2024-08-04T02:15:24.44Z"
        },
        {
          "VulnerabilityID": "CVE-2022-0563",
          "PkgID": "libuuid1@2.33.1-0.1",
          "PkgName": "libuuid1",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/libuuid1@2.33.1-0.1?arch=amd64\u0026distro=debian-10.13",
            "UID": "4feef3f42b91580a"
          },
          "InstalledVersion": "2.33.1-0.1",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2022-0563",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "util-linux: partial disclosure of arbitrary files in chfn and chsh when compiled with libreadline",
          "Description": "A flaw was found in the util-linux chfn and chsh utilities when compiled with Readline support. The Readline library uses an \"INPUTRC\" environment variable to get a path to the library config file. When the library cannot parse the specified file, it prints an error message containing data from the file. This flaw allows an unprivileged user to read root-owned files, potentially leading to privilege escalation. This flaw affects util-linux versions prior to 2.37.4.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-209"
          ],
          "VendorSeverity": {
            "amazon": 2,
            "cbl-mariner": 2,
            "debian": 1,
            "nvd": 2,
            "photon": 2,
            "redhat": 2
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:L/AC:M/Au:N/C:P/I:N/A:N",
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
              "V2Score": 1.9,
              "V3Score": 5.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
              "V3Score": 5.5
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2022-0563",
            "https://blog.trailofbits.com/2023/02/16/suid-logic-bug-linux-readline/",
            "https://lore.kernel.org/util-linux/20220214110609.msiwlm457ngoic6w%40ws.net.home/T/#u",
            "https://lore.kernel.org/util-linux/20220214110609.msiwlm457ngoic6w@ws.net.home/T/#u",
            "https://nvd.nist.gov/vuln/detail/CVE-2022-0563",
            "https://security.gentoo.org/glsa/202401-08",
            "https://security.netapp.com/advisory/ntap-20220331-0002/",
            "https://www.cve.org/CVERecord?id=CVE-2022-0563"
          ],
          "PublishedDate": "2022-02-21T19:15:08.393Z",
          "LastModifiedDate": "2024-01-07T09:15:08.713Z"
        },
        {
          "VulnerabilityID": "CVE-2023-4641",
          "PkgID": "login@1:4.5-1.1",
          "PkgName": "login",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/login@4.5-1.1?arch=amd64\u0026distro=debian-10.13\u0026epoch=1",
            "UID": "831a84c1c6d3cc04"
          },
          "InstalledVersion": "1:4.5-1.1",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-4641",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "shadow-utils: possible password leak during passwd(1) change",
          "Description": "A flaw was found in shadow-utils. When asking for a new password, shadow-utils asks the password twice. If the password fails on the second attempt, shadow-utils fails in cleaning the buffer used to store the first entry. This may allow an attacker with enough access to retrieve the password from the memory.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-287",
            "CWE-303"
          ],
          "VendorSeverity": {
            "alma": 1,
            "amazon": 1,
            "nvd": 2,
            "oracle-oval": 1,
            "photon": 2,
            "redhat": 1,
            "ubuntu": 1
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
              "V3Score": 5.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N",
              "V3Score": 4.7
            }
          },
          "References": [
            "https://access.redhat.com/errata/RHSA-2023:6632",
            "https://access.redhat.com/errata/RHSA-2023:7112",
            "https://access.redhat.com/errata/RHSA-2024:0417",
            "https://access.redhat.com/errata/RHSA-2024:2577",
            "https://access.redhat.com/security/cve/CVE-2023-4641",
            "https://bugzilla.redhat.com/2215945",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2215945",
            "https://errata.almalinux.org/9/ALSA-2023-6632.html",
            "https://linux.oracle.com/cve/CVE-2023-4641.html",
            "https://linux.oracle.com/errata/ELSA-2023-7112.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-4641",
            "https://ubuntu.com/security/notices/USN-6640-1",
            "https://www.cve.org/CVERecord?id=CVE-2023-4641"
          ],
          "PublishedDate": "2023-12-27T16:15:13.363Z",
          "LastModifiedDate": "2024-05-03T16:15:11.09Z"
        },
        {
          "VulnerabilityID": "CVE-2007-5686",
          "PkgID": "login@1:4.5-1.1",
          "PkgName": "login",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/login@4.5-1.1?arch=amd64\u0026distro=debian-10.13\u0026epoch=1",
            "UID": "831a84c1c6d3cc04"
          },
          "InstalledVersion": "1:4.5-1.1",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2007-5686",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "initscripts in rPath Linux 1 sets insecure permissions for the /var/lo ...",
          "Description": "initscripts in rPath Linux 1 sets insecure permissions for the /var/log/btmp file, which allows local users to obtain sensitive information regarding authentication attempts.  NOTE: because sshd detects the insecure permissions and does not log certain events, this also prevents sshd from logging failed authentication attempts by remote attackers.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-264"
          ],
          "VendorSeverity": {
            "debian": 1,
            "nvd": 2
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:L/AC:L/Au:N/C:C/I:N/A:N",
              "V2Score": 4.9
            }
          },
          "References": [
            "http://secunia.com/advisories/27215",
            "http://www.securityfocus.com/archive/1/482129/100/100/threaded",
            "http://www.securityfocus.com/archive/1/482857/100/0/threaded",
            "http://www.securityfocus.com/bid/26048",
            "http://www.vupen.com/english/advisories/2007/3474",
            "https://issues.rpath.com/browse/RPL-1825"
          ],
          "PublishedDate": "2007-10-28T17:08:00Z",
          "LastModifiedDate": "2018-10-15T21:45:59.05Z"
        },
        {
          "VulnerabilityID": "CVE-2013-4235",
          "PkgID": "login@1:4.5-1.1",
          "PkgName": "login",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/login@4.5-1.1?arch=amd64\u0026distro=debian-10.13\u0026epoch=1",
            "UID": "831a84c1c6d3cc04"
          },
          "InstalledVersion": "1:4.5-1.1",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2013-4235",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "shadow-utils: TOCTOU race conditions by copying and removing directory trees",
          "Description": "shadow: TOCTOU (time-of-check time-of-use) race condition when copying and removing directory trees",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-367"
          ],
          "VendorSeverity": {
            "debian": 1,
            "nvd": 2,
            "photon": 2,
            "redhat": 1,
            "ubuntu": 1
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:L/AC:M/Au:N/C:N/I:P/A:P",
              "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N",
              "V2Score": 3.3,
              "V3Score": 4.7
            },
            "redhat": {
              "V2Vector": "AV:L/AC:H/Au:N/C:P/I:P/A:P",
              "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:N/I:H/A:N",
              "V2Score": 3.7,
              "V3Score": 4.4
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2013-4235",
            "https://access.redhat.com/security/cve/cve-2013-4235",
            "https://bugs.launchpad.net/ubuntu/+source/shadow/+bug/1998169",
            "https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2013-4235",
            "https://github.com/shadow-maint/shadow/issues/317",
            "https://github.com/shadow-maint/shadow/pull/545",
            "https://lists.apache.org/thread.html/rf9fa47ab66495c78bb4120b0754dd9531ca2ff0430f6685ac9b07772%40%3Cdev.mina.apache.org%3E",
            "https://nvd.nist.gov/vuln/detail/CVE-2013-4235",
            "https://security-tracker.debian.org/tracker/CVE-2013-4235",
            "https://security.gentoo.org/glsa/202210-26",
            "https://ubuntu.com/security/notices/USN-5745-1",
            "https://ubuntu.com/security/notices/USN-5745-2",
            "https://www.cve.org/CVERecord?id=CVE-2013-4235"
          ],
          "PublishedDate": "2019-12-03T15:15:10.963Z",
          "LastModifiedDate": "2023-02-13T00:28:41.337Z"
        },
        {
          "VulnerabilityID": "CVE-2018-7169",
          "PkgID": "login@1:4.5-1.1",
          "PkgName": "login",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/login@4.5-1.1?arch=amd64\u0026distro=debian-10.13\u0026epoch=1",
            "UID": "831a84c1c6d3cc04"
          },
          "InstalledVersion": "1:4.5-1.1",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2018-7169",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "shadow-utils: newgidmap allows unprivileged user to drop supplementary groups potentially allowing privilege escalation",
          "Description": "An issue was discovered in shadow 4.5. newgidmap (in shadow-utils) is setuid and allows an unprivileged user to be placed in a user namespace where setgroups(2) is permitted. This allows an attacker to remove themselves from a supplementary group, which may allow access to certain filesystem paths if the administrator has used \"group blacklisting\" (e.g., chmod g-rwx) to restrict access to paths. This flaw effectively reverts a security feature in the kernel (in particular, the /proc/self/setgroups knob) to prevent this sort of privilege escalation.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-732"
          ],
          "VendorSeverity": {
            "debian": 1,
            "nvd": 2,
            "photon": 2,
            "redhat": 2,
            "ubuntu": 1
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:P/I:N/A:N",
              "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
              "V2Score": 5,
              "V3Score": 5.3
            },
            "redhat": {
              "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
              "V3Score": 4.4
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2018-7169",
            "https://bugs.launchpad.net/ubuntu/+source/shadow/+bug/1729357",
            "https://github.com/shadow-maint/shadow/pull/97",
            "https://nvd.nist.gov/vuln/detail/CVE-2018-7169",
            "https://security.gentoo.org/glsa/201805-09",
            "https://ubuntu.com/security/notices/USN-5254-1",
            "https://www.cve.org/CVERecord?id=CVE-2018-7169"
          ],
          "PublishedDate": "2018-02-15T20:29:00.867Z",
          "LastModifiedDate": "2019-10-03T00:03:26.223Z"
        },
        {
          "VulnerabilityID": "CVE-2019-19882",
          "PkgID": "login@1:4.5-1.1",
          "PkgName": "login",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/login@4.5-1.1?arch=amd64\u0026distro=debian-10.13\u0026epoch=1",
            "UID": "831a84c1c6d3cc04"
          },
          "InstalledVersion": "1:4.5-1.1",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2019-19882",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "shadow-utils: local users can obtain root access because setuid programs are misconfigured",
          "Description": "shadow 4.8, in certain circumstances affecting at least Gentoo, Arch Linux, and Void Linux, allows local users to obtain root access because setuid programs are misconfigured. Specifically, this affects shadow 4.8 when compiled using --with-libpam but without explicitly passing --disable-account-tools-setuid, and without a PAM configuration suitable for use with setuid account management tools. This combination leads to account management tools (groupadd, groupdel, groupmod, useradd, userdel, usermod) that can easily be used by unprivileged local users to escalate privileges to root in multiple ways. This issue became much more relevant in approximately December 2019 when an unrelated bug was fixed (i.e., the chmod calls to suidusbins were fixed in the upstream Makefile which is now included in the release version 4.8).",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-732"
          ],
          "VendorSeverity": {
            "debian": 1,
            "nvd": 3,
            "redhat": 3
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:L/AC:M/Au:N/C:C/I:C/A:C",
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
              "V2Score": 6.9,
              "V3Score": 7.8
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
              "V3Score": 7.8
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2019-19882",
            "https://bugs.archlinux.org/task/64836",
            "https://bugs.gentoo.org/702252",
            "https://github.com/shadow-maint/shadow/commit/edf7547ad5aa650be868cf2dac58944773c12d75",
            "https://github.com/shadow-maint/shadow/pull/199",
            "https://github.com/void-linux/void-packages/pull/17580",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-19882",
            "https://security.gentoo.org/glsa/202008-09",
            "https://www.cve.org/CVERecord?id=CVE-2019-19882"
          ],
          "PublishedDate": "2019-12-18T16:15:26.963Z",
          "LastModifiedDate": "2020-08-25T15:15:11.903Z"
        },
        {
          "VulnerabilityID": "CVE-2023-29383",
          "PkgID": "login@1:4.5-1.1",
          "PkgName": "login",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/login@4.5-1.1?arch=amd64\u0026distro=debian-10.13\u0026epoch=1",
            "UID": "831a84c1c6d3cc04"
          },
          "InstalledVersion": "1:4.5-1.1",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-29383",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "shadow: Improper input validation in shadow-utils package utility chfn",
          "Description": "In Shadow 4.13, it is possible to inject control characters into fields provided to the SUID program chfn (change finger). Although it is not possible to exploit this directly (e.g., adding a new user fails because \\n is in the block list), it is possible to misrepresent the /etc/passwd file when viewed. Use of \\r manipulations and Unicode characters to work around blocking of the : character make it possible to give the impression that a new user has been added. In other words, an adversary may be able to convince a system administrator to take the system offline (an indirect, social-engineered denial of service) by demonstrating that \"cat /etc/passwd\" shows a rogue user account.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-74"
          ],
          "VendorSeverity": {
            "nvd": 1,
            "photon": 1,
            "redhat": 2,
            "ubuntu": 1
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N",
              "V3Score": 3.3
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
              "V3Score": 5.5
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2023-29383",
            "https://github.com/shadow-maint/shadow/commit/e5905c4b84d4fb90aefcd96ee618411ebfac663d",
            "https://github.com/shadow-maint/shadow/pull/687",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-29383",
            "https://www.cve.org/CVERecord?id=CVE-2023-29383",
            "https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/cve-2023-29383-abusing-linux-chfn-to-misrepresent-etc-passwd/",
            "https://www.trustwave.com/en-us/resources/security-resources/security-advisories/?fid=31797"
          ],
          "PublishedDate": "2023-04-14T22:15:07.68Z",
          "LastModifiedDate": "2023-04-24T18:05:30.313Z"
        },
        {
          "VulnerabilityID": "TEMP-0628843-DBAD28",
          "PkgID": "login@1:4.5-1.1",
          "PkgName": "login",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/login@4.5-1.1?arch=amd64\u0026distro=debian-10.13\u0026epoch=1",
            "UID": "831a84c1c6d3cc04"
          },
          "InstalledVersion": "1:4.5-1.1",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://security-tracker.debian.org/tracker/TEMP-0628843-DBAD28",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "[more related to CVE-2005-4890]",
          "Severity": "LOW",
          "VendorSeverity": {
            "debian": 1
          }
        },
        {
          "VulnerabilityID": "CVE-2024-28085",
          "VendorIDs": [
            "DLA-3782-1"
          ],
          "PkgID": "mount@2.33.1-0.1",
          "PkgName": "mount",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/mount@2.33.1-0.1?arch=amd64\u0026distro=debian-10.13",
            "UID": "7280c86e3102d8ff"
          },
          "InstalledVersion": "2.33.1-0.1",
          "FixedVersion": "2.33.1-0.1+deb10u1",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-28085",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "util-linux: CVE-2024-28085: wall: escape sequence injection",
          "Description": "wall in util-linux through 2.40, often installed with setgid tty permissions, allows escape sequences to be sent to other users' terminals through argv. (Specifically, escape sequences received from stdin are blocked, but escape sequences received from argv are not blocked.) There may be plausible scenarios where this leads to account takeover.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-150"
          ],
          "VendorSeverity": {
            "cbl-mariner": 4,
            "photon": 3,
            "redhat": 3,
            "ubuntu": 2
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N",
              "V3Score": 8.4
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2024/03/27/5",
            "http://www.openwall.com/lists/oss-security/2024/03/27/6",
            "http://www.openwall.com/lists/oss-security/2024/03/27/7",
            "http://www.openwall.com/lists/oss-security/2024/03/27/8",
            "http://www.openwall.com/lists/oss-security/2024/03/27/9",
            "http://www.openwall.com/lists/oss-security/2024/03/28/1",
            "http://www.openwall.com/lists/oss-security/2024/03/28/2",
            "http://www.openwall.com/lists/oss-security/2024/03/28/3",
            "https://access.redhat.com/security/cve/CVE-2024-28085",
            "https://github.com/skyler-ferrante/CVE-2024-28085",
            "https://github.com/util-linux/util-linux/security/advisories/GHSA-xv2h-c6ww-mrjq",
            "https://lists.debian.org/debian-lts-announce/2024/04/msg00005.html",
            "https://mirrors.edge.kernel.org/pub/linux/utils/util-linux/",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-28085",
            "https://people.rit.edu/sjf5462/6831711781/wall_2_27_2024.txt",
            "https://security.netapp.com/advisory/ntap-20240531-0003/",
            "https://ubuntu.com/security/notices/USN-6719-1",
            "https://ubuntu.com/security/notices/USN-6719-2",
            "https://www.cve.org/CVERecord?id=CVE-2024-28085",
            "https://www.openwall.com/lists/oss-security/2024/03/27/5"
          ],
          "PublishedDate": "2024-03-27T19:15:48.367Z",
          "LastModifiedDate": "2024-08-26T21:35:09.31Z"
        },
        {
          "VulnerabilityID": "CVE-2021-37600",
          "VendorIDs": [
            "DLA-3782-1"
          ],
          "PkgID": "mount@2.33.1-0.1",
          "PkgName": "mount",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/mount@2.33.1-0.1?arch=amd64\u0026distro=debian-10.13",
            "UID": "7280c86e3102d8ff"
          },
          "InstalledVersion": "2.33.1-0.1",
          "FixedVersion": "2.33.1-0.1+deb10u1",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2021-37600",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "util-linux: integer overflow can lead to buffer overflow in get_sem_elements() in sys-utils/ipcutils.c",
          "Description": "An integer overflow in util-linux through 2.37.1 can potentially cause a buffer overflow if an attacker were able to use system resources in a way that leads to a large number in the /proc/sysvipc/sem file. NOTE: this is unexploitable in GNU C Library environments, and possibly in all realistic environments.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-190"
          ],
          "VendorSeverity": {
            "amazon": 1,
            "cbl-mariner": 2,
            "nvd": 2,
            "photon": 2,
            "redhat": 1,
            "ubuntu": 1
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:L/AC:H/Au:N/C:N/I:N/A:P",
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
              "V2Score": 1.2,
              "V3Score": 5.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:H",
              "V3Score": 4.7
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2021-37600",
            "https://github.com/karelzak/util-linux/commit/1c9143d0c1f979c3daf10e1c37b5b1e916c22a1c",
            "https://github.com/karelzak/util-linux/issues/1395",
            "https://lists.debian.org/debian-lts-announce/2024/04/msg00005.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-37600",
            "https://security.gentoo.org/glsa/202401-08",
            "https://security.netapp.com/advisory/ntap-20210902-0002/",
            "https://www.cve.org/CVERecord?id=CVE-2021-37600"
          ],
          "PublishedDate": "2021-07-30T14:15:18.737Z",
          "LastModifiedDate": "2024-08-04T02:15:24.44Z"
        },
        {
          "VulnerabilityID": "CVE-2022-0563",
          "PkgID": "mount@2.33.1-0.1",
          "PkgName": "mount",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/mount@2.33.1-0.1?arch=amd64\u0026distro=debian-10.13",
            "UID": "7280c86e3102d8ff"
          },
          "InstalledVersion": "2.33.1-0.1",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2022-0563",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "util-linux: partial disclosure of arbitrary files in chfn and chsh when compiled with libreadline",
          "Description": "A flaw was found in the util-linux chfn and chsh utilities when compiled with Readline support. The Readline library uses an \"INPUTRC\" environment variable to get a path to the library config file. When the library cannot parse the specified file, it prints an error message containing data from the file. This flaw allows an unprivileged user to read root-owned files, potentially leading to privilege escalation. This flaw affects util-linux versions prior to 2.37.4.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-209"
          ],
          "VendorSeverity": {
            "amazon": 2,
            "cbl-mariner": 2,
            "debian": 1,
            "nvd": 2,
            "photon": 2,
            "redhat": 2
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:L/AC:M/Au:N/C:P/I:N/A:N",
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
              "V2Score": 1.9,
              "V3Score": 5.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
              "V3Score": 5.5
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2022-0563",
            "https://blog.trailofbits.com/2023/02/16/suid-logic-bug-linux-readline/",
            "https://lore.kernel.org/util-linux/20220214110609.msiwlm457ngoic6w%40ws.net.home/T/#u",
            "https://lore.kernel.org/util-linux/20220214110609.msiwlm457ngoic6w@ws.net.home/T/#u",
            "https://nvd.nist.gov/vuln/detail/CVE-2022-0563",
            "https://security.gentoo.org/glsa/202401-08",
            "https://security.netapp.com/advisory/ntap-20220331-0002/",
            "https://www.cve.org/CVERecord?id=CVE-2022-0563"
          ],
          "PublishedDate": "2022-02-21T19:15:08.393Z",
          "LastModifiedDate": "2024-01-07T09:15:08.713Z"
        },
        {
          "VulnerabilityID": "CVE-2021-39537",
          "VendorIDs": [
            "DLA-3682-1"
          ],
          "PkgID": "ncurses-base@6.1+20181013-2+deb10u3",
          "PkgName": "ncurses-base",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/ncurses-base@6.1%2B20181013-2%2Bdeb10u3?arch=all\u0026distro=debian-10.13",
            "UID": "1806e8dbd664cc8f"
          },
          "InstalledVersion": "6.1+20181013-2+deb10u3",
          "FixedVersion": "6.1+20181013-2+deb10u5",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2021-39537",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "ncurses: heap-based buffer overflow in _nc_captoinfo() in captoinfo.c",
          "Description": "An issue was discovered in ncurses through v6.2-1. _nc_captoinfo in captoinfo.c has a heap-based buffer overflow.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-787"
          ],
          "VendorSeverity": {
            "amazon": 2,
            "cbl-mariner": 3,
            "nvd": 3,
            "photon": 3,
            "redhat": 1,
            "ubuntu": 1
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
              "V2Score": 6.8,
              "V3Score": 8.8
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
              "V3Score": 5.5
            }
          },
          "References": [
            "http://cvsweb.netbsd.org/bsdweb.cgi/pkgsrc/devel/ncurses/patches/patch-ncurses_tinfo_captoinfo.c?rev=1.1\u0026content-type=text/x-cvsweb-markup",
            "http://seclists.org/fulldisclosure/2022/Oct/28",
            "http://seclists.org/fulldisclosure/2022/Oct/41",
            "http://seclists.org/fulldisclosure/2022/Oct/43",
            "http://seclists.org/fulldisclosure/2022/Oct/45",
            "https://access.redhat.com/security/cve/CVE-2021-39537",
            "https://lists.debian.org/debian-lts-announce/2023/12/msg00004.html",
            "https://lists.gnu.org/archive/html/bug-ncurses/2020-08/msg00006.html",
            "https://lists.gnu.org/archive/html/bug-ncurses/2021-10/msg00023.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-39537",
            "https://security.netapp.com/advisory/ntap-20230427-0012/",
            "https://support.apple.com/kb/HT213443",
            "https://support.apple.com/kb/HT213444",
            "https://support.apple.com/kb/HT213488",
            "https://ubuntu.com/security/notices/USN-5477-1",
            "https://ubuntu.com/security/notices/USN-6099-1",
            "https://www.cve.org/CVERecord?id=CVE-2021-39537"
          ],
          "PublishedDate": "2021-09-20T16:15:12.477Z",
          "LastModifiedDate": "2023-12-03T20:15:06.86Z"
        },
        {
          "VulnerabilityID": "CVE-2023-29491",
          "VendorIDs": [
            "DLA-3682-1"
          ],
          "PkgID": "ncurses-base@6.1+20181013-2+deb10u3",
          "PkgName": "ncurses-base",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/ncurses-base@6.1%2B20181013-2%2Bdeb10u3?arch=all\u0026distro=debian-10.13",
            "UID": "1806e8dbd664cc8f"
          },
          "InstalledVersion": "6.1+20181013-2+deb10u3",
          "FixedVersion": "6.1+20181013-2+deb10u5",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-29491",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "ncurses: Local users can trigger security-relevant memory corruption via malformed data",
          "Description": "ncurses before 6.4 20230408, when used by a setuid application, allows local users to trigger security-relevant memory corruption via malformed data in a terminfo database file that is found in $HOME/.terminfo or reached via the TERMINFO or TERM environment variable.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-787"
          ],
          "VendorSeverity": {
            "alma": 2,
            "amazon": 3,
            "cbl-mariner": 3,
            "nvd": 3,
            "oracle-oval": 2,
            "photon": 3,
            "redhat": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
              "V3Score": 7.8
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
              "V3Score": 7.8
            }
          },
          "References": [
            "http://ncurses.scripts.mit.edu/?p=ncurses.git%3Ba=commit%3Bh=eb51b1ea1f75a0ec17c9c5937cb28df1e8eeec56",
            "http://ncurses.scripts.mit.edu/?p=ncurses.git;a=commit;h=eb51b1ea1f75a0ec17c9c5937cb28df1e8eeec56",
            "http://www.openwall.com/lists/oss-security/2023/04/19/10",
            "http://www.openwall.com/lists/oss-security/2023/04/19/11",
            "https://access.redhat.com/errata/RHSA-2023:6698",
            "https://access.redhat.com/security/cve/CVE-2023-29491",
            "https://bugzilla.redhat.com/2191704",
            "https://errata.almalinux.org/9/ALSA-2023-6698.html",
            "https://invisible-island.net/ncurses/NEWS.html#index-t20230408",
            "https://linux.oracle.com/cve/CVE-2023-29491.html",
            "https://linux.oracle.com/errata/ELSA-2023-6698.html",
            "https://lists.debian.org/debian-lts-announce/2023/12/msg00004.html",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/LU4MYMKFEZQ5VSCVLRIZGDQOUW3T44GT/",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-29491",
            "https://security.netapp.com/advisory/ntap-20230517-0009/",
            "https://support.apple.com/kb/HT213843",
            "https://support.apple.com/kb/HT213844",
            "https://support.apple.com/kb/HT213845",
            "https://ubuntu.com/security/notices/USN-6099-1",
            "https://www.cve.org/CVERecord?id=CVE-2023-29491",
            "https://www.openwall.com/lists/oss-security/2023/04/12/5",
            "https://www.openwall.com/lists/oss-security/2023/04/13/4"
          ],
          "PublishedDate": "2023-04-14T01:15:08.57Z",
          "LastModifiedDate": "2024-01-31T03:15:07.86Z"
        },
        {
          "VulnerabilityID": "CVE-2020-19189",
          "VendorIDs": [
            "DLA-3586-1"
          ],
          "PkgID": "ncurses-base@6.1+20181013-2+deb10u3",
          "PkgName": "ncurses-base",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/ncurses-base@6.1%2B20181013-2%2Bdeb10u3?arch=all\u0026distro=debian-10.13",
            "UID": "1806e8dbd664cc8f"
          },
          "InstalledVersion": "6.1+20181013-2+deb10u3",
          "FixedVersion": "6.1+20181013-2+deb10u4",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2020-19189",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "ncurses: Heap buffer overflow in postprocess_terminfo function in tinfo/parse_entry.c:997",
          "Description": "Buffer Overflow vulnerability in postprocess_terminfo function in tinfo/parse_entry.c:997 in ncurses 6.1 allows remote attackers to cause a denial of service via crafted command.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-787"
          ],
          "VendorSeverity": {
            "amazon": 2,
            "nvd": 2,
            "redhat": 1,
            "ubuntu": 2
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
              "V3Score": 6.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
              "V3Score": 6.5
            }
          },
          "References": [
            "http://seclists.org/fulldisclosure/2023/Dec/10",
            "http://seclists.org/fulldisclosure/2023/Dec/11",
            "http://seclists.org/fulldisclosure/2023/Dec/9",
            "https://access.redhat.com/security/cve/CVE-2020-19189",
            "https://github.com/zjuchenyuan/fuzzpoc/blob/master/infotocap_poc5.md",
            "https://lists.debian.org/debian-lts-announce/2023/09/msg00033.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2020-19189",
            "https://security.netapp.com/advisory/ntap-20231006-0005/",
            "https://support.apple.com/kb/HT214036",
            "https://support.apple.com/kb/HT214037",
            "https://support.apple.com/kb/HT214038",
            "https://ubuntu.com/security/notices/USN-6451-1",
            "https://www.cve.org/CVERecord?id=CVE-2020-19189"
          ],
          "PublishedDate": "2023-08-22T19:16:01.02Z",
          "LastModifiedDate": "2023-12-13T01:15:07.683Z"
        },
        {
          "VulnerabilityID": "CVE-2023-50495",
          "PkgID": "ncurses-base@6.1+20181013-2+deb10u3",
          "PkgName": "ncurses-base",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/ncurses-base@6.1%2B20181013-2%2Bdeb10u3?arch=all\u0026distro=debian-10.13",
            "UID": "1806e8dbd664cc8f"
          },
          "InstalledVersion": "6.1+20181013-2+deb10u3",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-50495",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "ncurses: segmentation fault via _nc_wrap_entry()",
          "Description": "NCurse v6.4-20230418 was discovered to contain a segmentation fault via the component _nc_wrap_entry().",
          "Severity": "MEDIUM",
          "VendorSeverity": {
            "amazon": 2,
            "nvd": 2,
            "redhat": 1,
            "ubuntu": 1
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
              "V3Score": 6.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
              "V3Score": 6.5
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2023-50495",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/LU4MYMKFEZQ5VSCVLRIZGDQOUW3T44GT/",
            "https://lists.gnu.org/archive/html/bug-ncurses/2023-04/msg00020.html",
            "https://lists.gnu.org/archive/html/bug-ncurses/2023-04/msg00029.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-50495",
            "https://security.netapp.com/advisory/ntap-20240119-0008/",
            "https://ubuntu.com/security/notices/USN-6684-1",
            "https://www.cve.org/CVERecord?id=CVE-2023-50495"
          ],
          "PublishedDate": "2023-12-12T15:15:07.867Z",
          "LastModifiedDate": "2024-01-31T03:15:08.49Z"
        },
        {
          "VulnerabilityID": "CVE-2023-45918",
          "PkgID": "ncurses-base@6.1+20181013-2+deb10u3",
          "PkgName": "ncurses-base",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/ncurses-base@6.1%2B20181013-2%2Bdeb10u3?arch=all\u0026distro=debian-10.13",
            "UID": "1806e8dbd664cc8f"
          },
          "InstalledVersion": "6.1+20181013-2+deb10u3",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-45918",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "ncurses: NULL pointer dereference in tgetstr in tinfo/lib_termcap.c",
          "Description": "ncurses 6.4-20230610 has a NULL pointer dereference in tgetstr in tinfo/lib_termcap.c.",
          "Severity": "LOW",
          "VendorSeverity": {
            "amazon": 2,
            "redhat": 1,
            "ubuntu": 1
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L",
              "V3Score": 3.3
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2023-45918",
            "https://lists.gnu.org/archive/html/bug-ncurses/2023-06/msg00005.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-45918",
            "https://security.netapp.com/advisory/ntap-20240315-0006/",
            "https://www.cve.org/CVERecord?id=CVE-2023-45918"
          ],
          "PublishedDate": "2024-02-16T22:15:07.88Z",
          "LastModifiedDate": "2024-03-15T11:15:08.51Z"
        },
        {
          "VulnerabilityID": "CVE-2021-39537",
          "VendorIDs": [
            "DLA-3682-1"
          ],
          "PkgID": "ncurses-bin@6.1+20181013-2+deb10u3",
          "PkgName": "ncurses-bin",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/ncurses-bin@6.1%2B20181013-2%2Bdeb10u3?arch=amd64\u0026distro=debian-10.13",
            "UID": "e5f2943107431649"
          },
          "InstalledVersion": "6.1+20181013-2+deb10u3",
          "FixedVersion": "6.1+20181013-2+deb10u5",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2021-39537",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "ncurses: heap-based buffer overflow in _nc_captoinfo() in captoinfo.c",
          "Description": "An issue was discovered in ncurses through v6.2-1. _nc_captoinfo in captoinfo.c has a heap-based buffer overflow.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-787"
          ],
          "VendorSeverity": {
            "amazon": 2,
            "cbl-mariner": 3,
            "nvd": 3,
            "photon": 3,
            "redhat": 1,
            "ubuntu": 1
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
              "V2Score": 6.8,
              "V3Score": 8.8
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
              "V3Score": 5.5
            }
          },
          "References": [
            "http://cvsweb.netbsd.org/bsdweb.cgi/pkgsrc/devel/ncurses/patches/patch-ncurses_tinfo_captoinfo.c?rev=1.1\u0026content-type=text/x-cvsweb-markup",
            "http://seclists.org/fulldisclosure/2022/Oct/28",
            "http://seclists.org/fulldisclosure/2022/Oct/41",
            "http://seclists.org/fulldisclosure/2022/Oct/43",
            "http://seclists.org/fulldisclosure/2022/Oct/45",
            "https://access.redhat.com/security/cve/CVE-2021-39537",
            "https://lists.debian.org/debian-lts-announce/2023/12/msg00004.html",
            "https://lists.gnu.org/archive/html/bug-ncurses/2020-08/msg00006.html",
            "https://lists.gnu.org/archive/html/bug-ncurses/2021-10/msg00023.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-39537",
            "https://security.netapp.com/advisory/ntap-20230427-0012/",
            "https://support.apple.com/kb/HT213443",
            "https://support.apple.com/kb/HT213444",
            "https://support.apple.com/kb/HT213488",
            "https://ubuntu.com/security/notices/USN-5477-1",
            "https://ubuntu.com/security/notices/USN-6099-1",
            "https://www.cve.org/CVERecord?id=CVE-2021-39537"
          ],
          "PublishedDate": "2021-09-20T16:15:12.477Z",
          "LastModifiedDate": "2023-12-03T20:15:06.86Z"
        },
        {
          "VulnerabilityID": "CVE-2023-29491",
          "VendorIDs": [
            "DLA-3682-1"
          ],
          "PkgID": "ncurses-bin@6.1+20181013-2+deb10u3",
          "PkgName": "ncurses-bin",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/ncurses-bin@6.1%2B20181013-2%2Bdeb10u3?arch=amd64\u0026distro=debian-10.13",
            "UID": "e5f2943107431649"
          },
          "InstalledVersion": "6.1+20181013-2+deb10u3",
          "FixedVersion": "6.1+20181013-2+deb10u5",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-29491",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "ncurses: Local users can trigger security-relevant memory corruption via malformed data",
          "Description": "ncurses before 6.4 20230408, when used by a setuid application, allows local users to trigger security-relevant memory corruption via malformed data in a terminfo database file that is found in $HOME/.terminfo or reached via the TERMINFO or TERM environment variable.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-787"
          ],
          "VendorSeverity": {
            "alma": 2,
            "amazon": 3,
            "cbl-mariner": 3,
            "nvd": 3,
            "oracle-oval": 2,
            "photon": 3,
            "redhat": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
              "V3Score": 7.8
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
              "V3Score": 7.8
            }
          },
          "References": [
            "http://ncurses.scripts.mit.edu/?p=ncurses.git%3Ba=commit%3Bh=eb51b1ea1f75a0ec17c9c5937cb28df1e8eeec56",
            "http://ncurses.scripts.mit.edu/?p=ncurses.git;a=commit;h=eb51b1ea1f75a0ec17c9c5937cb28df1e8eeec56",
            "http://www.openwall.com/lists/oss-security/2023/04/19/10",
            "http://www.openwall.com/lists/oss-security/2023/04/19/11",
            "https://access.redhat.com/errata/RHSA-2023:6698",
            "https://access.redhat.com/security/cve/CVE-2023-29491",
            "https://bugzilla.redhat.com/2191704",
            "https://errata.almalinux.org/9/ALSA-2023-6698.html",
            "https://invisible-island.net/ncurses/NEWS.html#index-t20230408",
            "https://linux.oracle.com/cve/CVE-2023-29491.html",
            "https://linux.oracle.com/errata/ELSA-2023-6698.html",
            "https://lists.debian.org/debian-lts-announce/2023/12/msg00004.html",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/LU4MYMKFEZQ5VSCVLRIZGDQOUW3T44GT/",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-29491",
            "https://security.netapp.com/advisory/ntap-20230517-0009/",
            "https://support.apple.com/kb/HT213843",
            "https://support.apple.com/kb/HT213844",
            "https://support.apple.com/kb/HT213845",
            "https://ubuntu.com/security/notices/USN-6099-1",
            "https://www.cve.org/CVERecord?id=CVE-2023-29491",
            "https://www.openwall.com/lists/oss-security/2023/04/12/5",
            "https://www.openwall.com/lists/oss-security/2023/04/13/4"
          ],
          "PublishedDate": "2023-04-14T01:15:08.57Z",
          "LastModifiedDate": "2024-01-31T03:15:07.86Z"
        },
        {
          "VulnerabilityID": "CVE-2020-19189",
          "VendorIDs": [
            "DLA-3586-1"
          ],
          "PkgID": "ncurses-bin@6.1+20181013-2+deb10u3",
          "PkgName": "ncurses-bin",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/ncurses-bin@6.1%2B20181013-2%2Bdeb10u3?arch=amd64\u0026distro=debian-10.13",
            "UID": "e5f2943107431649"
          },
          "InstalledVersion": "6.1+20181013-2+deb10u3",
          "FixedVersion": "6.1+20181013-2+deb10u4",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2020-19189",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "ncurses: Heap buffer overflow in postprocess_terminfo function in tinfo/parse_entry.c:997",
          "Description": "Buffer Overflow vulnerability in postprocess_terminfo function in tinfo/parse_entry.c:997 in ncurses 6.1 allows remote attackers to cause a denial of service via crafted command.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-787"
          ],
          "VendorSeverity": {
            "amazon": 2,
            "nvd": 2,
            "redhat": 1,
            "ubuntu": 2
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
              "V3Score": 6.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
              "V3Score": 6.5
            }
          },
          "References": [
            "http://seclists.org/fulldisclosure/2023/Dec/10",
            "http://seclists.org/fulldisclosure/2023/Dec/11",
            "http://seclists.org/fulldisclosure/2023/Dec/9",
            "https://access.redhat.com/security/cve/CVE-2020-19189",
            "https://github.com/zjuchenyuan/fuzzpoc/blob/master/infotocap_poc5.md",
            "https://lists.debian.org/debian-lts-announce/2023/09/msg00033.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2020-19189",
            "https://security.netapp.com/advisory/ntap-20231006-0005/",
            "https://support.apple.com/kb/HT214036",
            "https://support.apple.com/kb/HT214037",
            "https://support.apple.com/kb/HT214038",
            "https://ubuntu.com/security/notices/USN-6451-1",
            "https://www.cve.org/CVERecord?id=CVE-2020-19189"
          ],
          "PublishedDate": "2023-08-22T19:16:01.02Z",
          "LastModifiedDate": "2023-12-13T01:15:07.683Z"
        },
        {
          "VulnerabilityID": "CVE-2023-50495",
          "PkgID": "ncurses-bin@6.1+20181013-2+deb10u3",
          "PkgName": "ncurses-bin",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/ncurses-bin@6.1%2B20181013-2%2Bdeb10u3?arch=amd64\u0026distro=debian-10.13",
            "UID": "e5f2943107431649"
          },
          "InstalledVersion": "6.1+20181013-2+deb10u3",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-50495",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "ncurses: segmentation fault via _nc_wrap_entry()",
          "Description": "NCurse v6.4-20230418 was discovered to contain a segmentation fault via the component _nc_wrap_entry().",
          "Severity": "MEDIUM",
          "VendorSeverity": {
            "amazon": 2,
            "nvd": 2,
            "redhat": 1,
            "ubuntu": 1
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
              "V3Score": 6.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
              "V3Score": 6.5
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2023-50495",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/LU4MYMKFEZQ5VSCVLRIZGDQOUW3T44GT/",
            "https://lists.gnu.org/archive/html/bug-ncurses/2023-04/msg00020.html",
            "https://lists.gnu.org/archive/html/bug-ncurses/2023-04/msg00029.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-50495",
            "https://security.netapp.com/advisory/ntap-20240119-0008/",
            "https://ubuntu.com/security/notices/USN-6684-1",
            "https://www.cve.org/CVERecord?id=CVE-2023-50495"
          ],
          "PublishedDate": "2023-12-12T15:15:07.867Z",
          "LastModifiedDate": "2024-01-31T03:15:08.49Z"
        },
        {
          "VulnerabilityID": "CVE-2023-45918",
          "PkgID": "ncurses-bin@6.1+20181013-2+deb10u3",
          "PkgName": "ncurses-bin",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/ncurses-bin@6.1%2B20181013-2%2Bdeb10u3?arch=amd64\u0026distro=debian-10.13",
            "UID": "e5f2943107431649"
          },
          "InstalledVersion": "6.1+20181013-2+deb10u3",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-45918",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "ncurses: NULL pointer dereference in tgetstr in tinfo/lib_termcap.c",
          "Description": "ncurses 6.4-20230610 has a NULL pointer dereference in tgetstr in tinfo/lib_termcap.c.",
          "Severity": "LOW",
          "VendorSeverity": {
            "amazon": 2,
            "redhat": 1,
            "ubuntu": 1
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L",
              "V3Score": 3.3
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2023-45918",
            "https://lists.gnu.org/archive/html/bug-ncurses/2023-06/msg00005.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-45918",
            "https://security.netapp.com/advisory/ntap-20240315-0006/",
            "https://www.cve.org/CVERecord?id=CVE-2023-45918"
          ],
          "PublishedDate": "2024-02-16T22:15:07.88Z",
          "LastModifiedDate": "2024-03-15T11:15:08.51Z"
        },
        {
          "VulnerabilityID": "CVE-2023-3446",
          "VendorIDs": [
            "DLA-3530-1"
          ],
          "PkgID": "openssl@1.1.1n-0+deb10u5",
          "PkgName": "openssl",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/openssl@1.1.1n-0%2Bdeb10u5?arch=amd64\u0026distro=debian-10.13",
            "UID": "3fa2132c4e190930"
          },
          "InstalledVersion": "1.1.1n-0+deb10u5",
          "FixedVersion": "1.1.1n-0+deb10u6",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:824416e234237961c9c5d4f41dfe5b295a3c35a671ee52889bfb08d8e257ec4c",
            "DiffID": "sha256:ae2d55769c5efcb6230d27c88eef033128fa1d238bdafe50812402f471152bb7"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-3446",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "openssl: Excessive time spent checking DH keys and parameters",
          "Description": "Issue summary: Checking excessively long DH keys or parameters may be very slow.\n\nImpact summary: Applications that use the functions DH_check(), DH_check_ex()\nor EVP_PKEY_param_check() to check a DH key or DH parameters may experience long\ndelays. Where the key or parameters that are being checked have been obtained\nfrom an untrusted source this may lead to a Denial of Service.\n\nThe function DH_check() performs various checks on DH parameters. One of those\nchecks confirms that the modulus ('p' parameter) is not too large. Trying to use\na very large modulus is slow and OpenSSL will not normally use a modulus which\nis over 10,000 bits in length.\n\nHowever the DH_check() function checks numerous aspects of the key or parameters\nthat have been supplied. Some of those checks use the supplied modulus value\neven if it has already been found to be too large.\n\nAn application that calls DH_check() and supplies a key or parameters obtained\nfrom an untrusted source could be vulernable to a Denial of Service attack.\n\nThe function DH_check() is itself called by a number of other OpenSSL functions.\nAn application calling any of those other functions may similarly be affected.\nThe other functions affected by this are DH_check_ex() and\nEVP_PKEY_param_check().\n\nAlso vulnerable are the OpenSSL dhparam and pkeyparam command line applications\nwhen using the '-check' option.\n\nThe OpenSSL SSL/TLS implementation is not affected by this issue.\nThe OpenSSL 3.0 and 3.1 FIPS providers are not affected by this issue.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-1333"
          ],
          "VendorSeverity": {
            "alma": 1,
            "amazon": 2,
            "cbl-mariner": 2,
            "nvd": 2,
            "oracle-oval": 1,
            "photon": 2,
            "redhat": 1,
            "rocky": 3,
            "ubuntu": 1
          },
          "CVSS": {
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
            "http://www.openwall.com/lists/oss-security/2023/07/19/4",
            "http://www.openwall.com/lists/oss-security/2023/07/19/5",
            "http://www.openwall.com/lists/oss-security/2023/07/19/6",
            "http://www.openwall.com/lists/oss-security/2023/07/31/1",
            "http://www.openwall.com/lists/oss-security/2024/05/16/1",
            "https://access.redhat.com/errata/RHSA-2024:2447",
            "https://access.redhat.com/security/cve/CVE-2023-3446",
            "https://bugzilla.redhat.com/2223016",
            "https://bugzilla.redhat.com/2224962",
            "https://bugzilla.redhat.com/2227852",
            "https://bugzilla.redhat.com/2248616",
            "https://bugzilla.redhat.com/2257571",
            "https://bugzilla.redhat.com/2258502",
            "https://bugzilla.redhat.com/2259944",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2224962",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2257582",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2257583",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2258677",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2258688",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2258691",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2258694",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2258700",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-36763",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-36764",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-3446",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-45229",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-45231",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-45232",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-45233",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-45235",
            "https://errata.almalinux.org/9/ALSA-2024-2447.html",
            "https://errata.rockylinux.org/RLSA-2024:2264",
            "https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=1fa20cf2f506113c761777127a38bce5068740eb",
            "https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=8780a896543a654e757db1b9396383f9d8095528",
            "https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=9a0a4d3c1e7138915563c0df4fe6a3f9377b839c",
            "https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=fc9867c1e03c22ebf56943be205202e576aabf23",
            "https://linux.oracle.com/cve/CVE-2023-3446.html",
            "https://linux.oracle.com/errata/ELSA-2024-2447.html",
            "https://lists.debian.org/debian-lts-announce/2023/08/msg00019.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-3446",
            "https://security.gentoo.org/glsa/202402-08",
            "https://security.netapp.com/advisory/ntap-20230803-0011/",
            "https://ubuntu.com/security/notices/USN-6435-1",
            "https://ubuntu.com/security/notices/USN-6435-2",
            "https://ubuntu.com/security/notices/USN-6450-1",
            "https://ubuntu.com/security/notices/USN-6709-1",
            "https://www.cve.org/CVERecord?id=CVE-2023-3446",
            "https://www.openssl.org/news/secadv/20230719.txt"
          ],
          "PublishedDate": "2023-07-19T12:15:10.003Z",
          "LastModifiedDate": "2024-06-10T17:16:12.867Z"
        },
        {
          "VulnerabilityID": "CVE-2023-3817",
          "VendorIDs": [
            "DLA-3530-1"
          ],
          "PkgID": "openssl@1.1.1n-0+deb10u5",
          "PkgName": "openssl",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/openssl@1.1.1n-0%2Bdeb10u5?arch=amd64\u0026distro=debian-10.13",
            "UID": "3fa2132c4e190930"
          },
          "InstalledVersion": "1.1.1n-0+deb10u5",
          "FixedVersion": "1.1.1n-0+deb10u6",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:824416e234237961c9c5d4f41dfe5b295a3c35a671ee52889bfb08d8e257ec4c",
            "DiffID": "sha256:ae2d55769c5efcb6230d27c88eef033128fa1d238bdafe50812402f471152bb7"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-3817",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "OpenSSL: Excessive time spent checking DH q parameter value",
          "Description": "Issue summary: Checking excessively long DH keys or parameters may be very slow.\n\nImpact summary: Applications that use the functions DH_check(), DH_check_ex()\nor EVP_PKEY_param_check() to check a DH key or DH parameters may experience long\ndelays. Where the key or parameters that are being checked have been obtained\nfrom an untrusted source this may lead to a Denial of Service.\n\nThe function DH_check() performs various checks on DH parameters. After fixing\nCVE-2023-3446 it was discovered that a large q parameter value can also trigger\nan overly long computation during some of these checks. A correct q value,\nif present, cannot be larger than the modulus p parameter, thus it is\nunnecessary to perform these checks if q is larger than p.\n\nAn application that calls DH_check() and supplies a key or parameters obtained\nfrom an untrusted source could be vulnerable to a Denial of Service attack.\n\nThe function DH_check() is itself called by a number of other OpenSSL functions.\nAn application calling any of those other functions may similarly be affected.\nThe other functions affected by this are DH_check_ex() and\nEVP_PKEY_param_check().\n\nAlso vulnerable are the OpenSSL dhparam and pkeyparam command line applications\nwhen using the \"-check\" option.\n\nThe OpenSSL SSL/TLS implementation is not affected by this issue.\n\nThe OpenSSL 3.0 and 3.1 FIPS providers are not affected by this issue.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-834"
          ],
          "VendorSeverity": {
            "alma": 1,
            "amazon": 2,
            "azure": 2,
            "cbl-mariner": 2,
            "nvd": 2,
            "oracle-oval": 1,
            "photon": 2,
            "redhat": 1,
            "ubuntu": 1
          },
          "CVSS": {
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
            "http://seclists.org/fulldisclosure/2023/Jul/43",
            "http://www.openwall.com/lists/oss-security/2023/07/31/1",
            "http://www.openwall.com/lists/oss-security/2023/09/22/11",
            "http://www.openwall.com/lists/oss-security/2023/09/22/9",
            "http://www.openwall.com/lists/oss-security/2023/11/06/2",
            "https://access.redhat.com/errata/RHSA-2024:2447",
            "https://access.redhat.com/security/cve/CVE-2023-3817",
            "https://bugzilla.redhat.com/2223016",
            "https://bugzilla.redhat.com/2224962",
            "https://bugzilla.redhat.com/2227852",
            "https://bugzilla.redhat.com/2248616",
            "https://bugzilla.redhat.com/2257571",
            "https://bugzilla.redhat.com/2258502",
            "https://bugzilla.redhat.com/2259944",
            "https://errata.almalinux.org/9/ALSA-2024-2447.html",
            "https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=6a1eb62c29db6cb5eec707f9338aee00f44e26f5",
            "https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=869ad69aadd985c7b8ca6f4e5dd0eb274c9f3644",
            "https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=9002fd07327a91f35ba6c1307e71fa6fd4409b7f",
            "https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=91ddeba0f2269b017dc06c46c993a788974b1aa5",
            "https://linux.oracle.com/cve/CVE-2023-3817.html",
            "https://linux.oracle.com/errata/ELSA-2024-2447.html",
            "https://lists.debian.org/debian-lts-announce/2023/08/msg00019.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-3817",
            "https://security.gentoo.org/glsa/202402-08",
            "https://security.netapp.com/advisory/ntap-20230818-0014/",
            "https://security.netapp.com/advisory/ntap-20231027-0008/",
            "https://security.netapp.com/advisory/ntap-20240621-0006/",
            "https://ubuntu.com/security/notices/USN-6435-1",
            "https://ubuntu.com/security/notices/USN-6435-2",
            "https://ubuntu.com/security/notices/USN-6450-1",
            "https://ubuntu.com/security/notices/USN-6709-1",
            "https://www.cve.org/CVERecord?id=CVE-2023-3817",
            "https://www.openssl.org/news/secadv/20230731.txt"
          ],
          "PublishedDate": "2023-07-31T16:15:10.497Z",
          "LastModifiedDate": "2024-06-21T19:15:28.01Z"
        },
        {
          "VulnerabilityID": "CVE-2023-5678",
          "PkgID": "openssl@1.1.1n-0+deb10u5",
          "PkgName": "openssl",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/openssl@1.1.1n-0%2Bdeb10u5?arch=amd64\u0026distro=debian-10.13",
            "UID": "3fa2132c4e190930"
          },
          "InstalledVersion": "1.1.1n-0+deb10u5",
          "Status": "fix_deferred",
          "Layer": {
            "Digest": "sha256:824416e234237961c9c5d4f41dfe5b295a3c35a671ee52889bfb08d8e257ec4c",
            "DiffID": "sha256:ae2d55769c5efcb6230d27c88eef033128fa1d238bdafe50812402f471152bb7"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-5678",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "openssl: Generating excessively long X9.42 DH keys or checking excessively long X9.42 DH keys or parameters may be very slow",
          "Description": "Issue summary: Generating excessively long X9.42 DH keys or checking\nexcessively long X9.42 DH keys or parameters may be very slow.\n\nImpact summary: Applications that use the functions DH_generate_key() to\ngenerate an X9.42 DH key may experience long delays.  Likewise, applications\nthat use DH_check_pub_key(), DH_check_pub_key_ex() or EVP_PKEY_public_check()\nto check an X9.42 DH key or X9.42 DH parameters may experience long delays.\nWhere the key or parameters that are being checked have been obtained from\nan untrusted source this may lead to a Denial of Service.\n\nWhile DH_check() performs all the necessary checks (as of CVE-2023-3817),\nDH_check_pub_key() doesn't make any of these checks, and is therefore\nvulnerable for excessively large P and Q parameters.\n\nLikewise, while DH_generate_key() performs a check for an excessively large\nP, it doesn't check for an excessively large Q.\n\nAn application that calls DH_generate_key() or DH_check_pub_key() and\nsupplies a key or parameters obtained from an untrusted source could be\nvulnerable to a Denial of Service attack.\n\nDH_generate_key() and DH_check_pub_key() are also called by a number of\nother OpenSSL functions.  An application calling any of those other\nfunctions may similarly be affected.  The other functions affected by this\nare DH_check_pub_key_ex(), EVP_PKEY_public_check(), and EVP_PKEY_generate().\n\nAlso vulnerable are the OpenSSL pkey command line application when using the\n\"-pubcheck\" option, as well as the OpenSSL genpkey command line application.\n\nThe OpenSSL SSL/TLS implementation is not affected by this issue.\n\nThe OpenSSL 3.0 and 3.1 FIPS providers are not affected by this issue.\n\n",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-754"
          ],
          "VendorSeverity": {
            "alma": 1,
            "amazon": 2,
            "azure": 2,
            "cbl-mariner": 2,
            "nvd": 2,
            "oracle-oval": 1,
            "photon": 2,
            "redhat": 1,
            "ubuntu": 1
          },
          "CVSS": {
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
            "http://www.openwall.com/lists/oss-security/2024/03/11/1",
            "https://access.redhat.com/errata/RHSA-2024:2447",
            "https://access.redhat.com/security/cve/CVE-2023-5678",
            "https://bugzilla.redhat.com/2223016",
            "https://bugzilla.redhat.com/2224962",
            "https://bugzilla.redhat.com/2227852",
            "https://bugzilla.redhat.com/2248616",
            "https://bugzilla.redhat.com/2257571",
            "https://bugzilla.redhat.com/2258502",
            "https://bugzilla.redhat.com/2259944",
            "https://errata.almalinux.org/9/ALSA-2024-2447.html",
            "https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=34efaef6c103d636ab507a0cc34dca4d3aecc055",
            "https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=710fee740904b6290fef0dd5536fbcedbc38ff0c",
            "https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=db925ae2e65d0d925adef429afc37f75bd1c2017",
            "https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=ddeb4b6c6d527e54ce9a99cba785c0f7776e54b6",
            "https://linux.oracle.com/cve/CVE-2023-5678.html",
            "https://linux.oracle.com/errata/ELSA-2024-2447.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-5678",
            "https://security.netapp.com/advisory/ntap-20231130-0010/",
            "https://ubuntu.com/security/notices/USN-6622-1",
            "https://ubuntu.com/security/notices/USN-6632-1",
            "https://ubuntu.com/security/notices/USN-6709-1",
            "https://www.cve.org/CVERecord?id=CVE-2023-5678",
            "https://www.openssl.org/news/secadv/20231106.txt"
          ],
          "PublishedDate": "2023-11-06T16:15:42.67Z",
          "LastModifiedDate": "2024-05-01T18:15:12.393Z"
        },
        {
          "VulnerabilityID": "CVE-2024-0727",
          "PkgID": "openssl@1.1.1n-0+deb10u5",
          "PkgName": "openssl",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/openssl@1.1.1n-0%2Bdeb10u5?arch=amd64\u0026distro=debian-10.13",
            "UID": "3fa2132c4e190930"
          },
          "InstalledVersion": "1.1.1n-0+deb10u5",
          "Status": "fix_deferred",
          "Layer": {
            "Digest": "sha256:824416e234237961c9c5d4f41dfe5b295a3c35a671ee52889bfb08d8e257ec4c",
            "DiffID": "sha256:ae2d55769c5efcb6230d27c88eef033128fa1d238bdafe50812402f471152bb7"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-0727",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "openssl: denial of service via null dereference",
          "Description": "Issue summary: Processing a maliciously formatted PKCS12 file may lead OpenSSL\nto crash leading to a potential Denial of Service attack\n\nImpact summary: Applications loading files in the PKCS12 format from untrusted\nsources might terminate abruptly.\n\nA file in PKCS12 format can contain certificates and keys and may come from an\nuntrusted source. The PKCS12 specification allows certain fields to be NULL, but\nOpenSSL does not correctly check for this case. This can lead to a NULL pointer\ndereference that results in OpenSSL crashing. If an application processes PKCS12\nfiles from an untrusted source using the OpenSSL APIs then that application will\nbe vulnerable to this issue.\n\nOpenSSL APIs that are vulnerable to this are: PKCS12_parse(),\nPKCS12_unpack_p7data(), PKCS12_unpack_p7encdata(), PKCS12_unpack_authsafes()\nand PKCS12_newpass().\n\nWe have also fixed a similar issue in SMIME_write_PKCS7(). However since this\nfunction is related to writing data we do not consider it security significant.\n\nThe FIPS modules in 3.2, 3.1 and 3.0 are not affected by this issue.",
          "Severity": "MEDIUM",
          "VendorSeverity": {
            "alma": 1,
            "amazon": 2,
            "azure": 2,
            "cbl-mariner": 2,
            "ghsa": 2,
            "nvd": 2,
            "oracle-oval": 1,
            "photon": 2,
            "redhat": 1,
            "ubuntu": 1
          },
          "CVSS": {
            "ghsa": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
              "V3Score": 5.5
            },
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
              "V3Score": 5.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
              "V3Score": 5.5
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2024/03/11/1",
            "https://access.redhat.com/errata/RHSA-2024:2447",
            "https://access.redhat.com/security/cve/CVE-2024-0727",
            "https://bugzilla.redhat.com/2223016",
            "https://bugzilla.redhat.com/2224962",
            "https://bugzilla.redhat.com/2227852",
            "https://bugzilla.redhat.com/2248616",
            "https://bugzilla.redhat.com/2257571",
            "https://bugzilla.redhat.com/2258502",
            "https://bugzilla.redhat.com/2259944",
            "https://errata.almalinux.org/9/ALSA-2024-2447.html",
            "https://github.com/alexcrichton/openssl-src-rs/commit/add20f73b6b42be7451af2e1044d4e0e778992b2",
            "https://github.com/github/advisory-database/pull/3472",
            "https://github.com/openssl/openssl/commit/09df4395b5071217b76dc7d3d2e630eb8c5a79c2",
            "https://github.com/openssl/openssl/commit/775acfdbd0c6af9ac855f34969cdab0c0c90844a",
            "https://github.com/openssl/openssl/commit/d135eeab8a5dbf72b3da5240bab9ddb7678dbd2c",
            "https://github.com/openssl/openssl/pull/23362",
            "https://github.com/pyca/cryptography/commit/3519591d255d4506fbcd0d04037d45271903c64d",
            "https://github.openssl.org/openssl/extended-releases/commit/03b3941d60c4bce58fab69a0c22377ab439bc0e8",
            "https://github.openssl.org/openssl/extended-releases/commit/aebaa5883e31122b404e450732dc833dc9dee539",
            "https://linux.oracle.com/cve/CVE-2024-0727.html",
            "https://linux.oracle.com/errata/ELSA-2024-2447.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-0727",
            "https://security.netapp.com/advisory/ntap-20240208-0006",
            "https://security.netapp.com/advisory/ntap-20240208-0006/",
            "https://ubuntu.com/security/notices/USN-6622-1",
            "https://ubuntu.com/security/notices/USN-6632-1",
            "https://ubuntu.com/security/notices/USN-6709-1",
            "https://www.cve.org/CVERecord?id=CVE-2024-0727",
            "https://www.openssl.org/news/secadv/20240125.txt"
          ],
          "PublishedDate": "2024-01-26T09:15:07.637Z",
          "LastModifiedDate": "2024-05-01T18:15:13.057Z"
        },
        {
          "VulnerabilityID": "CVE-2024-4741",
          "PkgID": "openssl@1.1.1n-0+deb10u5",
          "PkgName": "openssl",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/openssl@1.1.1n-0%2Bdeb10u5?arch=amd64\u0026distro=debian-10.13",
            "UID": "3fa2132c4e190930"
          },
          "InstalledVersion": "1.1.1n-0+deb10u5",
          "Status": "fix_deferred",
          "Layer": {
            "Digest": "sha256:824416e234237961c9c5d4f41dfe5b295a3c35a671ee52889bfb08d8e257ec4c",
            "DiffID": "sha256:ae2d55769c5efcb6230d27c88eef033128fa1d238bdafe50812402f471152bb7"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-4741",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
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
          "PkgID": "openssl@1.1.1n-0+deb10u5",
          "PkgName": "openssl",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/openssl@1.1.1n-0%2Bdeb10u5?arch=amd64\u0026distro=debian-10.13",
            "UID": "3fa2132c4e190930"
          },
          "InstalledVersion": "1.1.1n-0+deb10u5",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:824416e234237961c9c5d4f41dfe5b295a3c35a671ee52889bfb08d8e257ec4c",
            "DiffID": "sha256:ae2d55769c5efcb6230d27c88eef033128fa1d238bdafe50812402f471152bb7"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-5535",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
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
          "PkgID": "openssl@1.1.1n-0+deb10u5",
          "PkgName": "openssl",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/openssl@1.1.1n-0%2Bdeb10u5?arch=amd64\u0026distro=debian-10.13",
            "UID": "3fa2132c4e190930"
          },
          "InstalledVersion": "1.1.1n-0+deb10u5",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:824416e234237961c9c5d4f41dfe5b295a3c35a671ee52889bfb08d8e257ec4c",
            "DiffID": "sha256:ae2d55769c5efcb6230d27c88eef033128fa1d238bdafe50812402f471152bb7"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-6119",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
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
          "VulnerabilityID": "CVE-2024-2511",
          "PkgID": "openssl@1.1.1n-0+deb10u5",
          "PkgName": "openssl",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/openssl@1.1.1n-0%2Bdeb10u5?arch=amd64\u0026distro=debian-10.13",
            "UID": "3fa2132c4e190930"
          },
          "InstalledVersion": "1.1.1n-0+deb10u5",
          "Status": "fix_deferred",
          "Layer": {
            "Digest": "sha256:824416e234237961c9c5d4f41dfe5b295a3c35a671ee52889bfb08d8e257ec4c",
            "DiffID": "sha256:ae2d55769c5efcb6230d27c88eef033128fa1d238bdafe50812402f471152bb7"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-2511",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "openssl: Unbounded memory growth with session handling in TLSv1.3",
          "Description": "Issue summary: Some non-default TLS server configurations can cause unbounded\nmemory growth when processing TLSv1.3 sessions\n\nImpact summary: An attacker may exploit certain server configurations to trigger\nunbounded memory growth that would lead to a Denial of Service\n\nThis problem can occur in TLSv1.3 if the non-default SSL_OP_NO_TICKET option is\nbeing used (but not if early_data support is also configured and the default\nanti-replay protection is in use). In this case, under certain conditions, the\nsession cache can get into an incorrect state and it will fail to flush properly\nas it fills. The session cache will continue to grow in an unbounded manner. A\nmalicious client could deliberately create the scenario for this failure to\nforce a Denial of Service. It may also happen by accident in normal operation.\n\nThis issue only affects TLS servers supporting TLSv1.3. It does not affect TLS\nclients.\n\nThe FIPS modules in 3.2, 3.1 and 3.0 are not affected by this issue. OpenSSL\n1.0.2 is also not affected by this issue.",
          "Severity": "LOW",
          "VendorSeverity": {
            "amazon": 2,
            "azure": 1,
            "cbl-mariner": 3,
            "photon": 3,
            "redhat": 1,
            "ubuntu": 1
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L",
              "V3Score": 3.7
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2024/04/08/5",
            "https://access.redhat.com/security/cve/CVE-2024-2511",
            "https://github.com/openssl/openssl/commit/7e4d731b1c07201ad9374c1cd9ac5263bdf35bce",
            "https://github.com/openssl/openssl/commit/b52867a9f618bb955bed2a3ce3db4d4f97ed8e5d",
            "https://github.com/openssl/openssl/commit/e9d7083e241670332e0443da0f0d4ffb52829f08",
            "https://github.openssl.org/openssl/extended-releases/commit/5f8d25770ae6437db119dfc951e207271a326640",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-2511",
            "https://security.netapp.com/advisory/ntap-20240503-0013/",
            "https://ubuntu.com/security/notices/USN-6937-1",
            "https://www.cve.org/CVERecord?id=CVE-2024-2511",
            "https://www.openssl.org/news/secadv/20240408.txt",
            "https://www.openssl.org/news/vulnerabilities.html"
          ],
          "PublishedDate": "2024-04-08T14:15:07.66Z",
          "LastModifiedDate": "2024-05-03T13:15:21.93Z"
        },
        {
          "VulnerabilityID": "CVE-2023-4641",
          "PkgID": "passwd@1:4.5-1.1",
          "PkgName": "passwd",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/passwd@4.5-1.1?arch=amd64\u0026distro=debian-10.13\u0026epoch=1",
            "UID": "c44fae08ce6b1859"
          },
          "InstalledVersion": "1:4.5-1.1",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-4641",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "shadow-utils: possible password leak during passwd(1) change",
          "Description": "A flaw was found in shadow-utils. When asking for a new password, shadow-utils asks the password twice. If the password fails on the second attempt, shadow-utils fails in cleaning the buffer used to store the first entry. This may allow an attacker with enough access to retrieve the password from the memory.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-287",
            "CWE-303"
          ],
          "VendorSeverity": {
            "alma": 1,
            "amazon": 1,
            "nvd": 2,
            "oracle-oval": 1,
            "photon": 2,
            "redhat": 1,
            "ubuntu": 1
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
              "V3Score": 5.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N",
              "V3Score": 4.7
            }
          },
          "References": [
            "https://access.redhat.com/errata/RHSA-2023:6632",
            "https://access.redhat.com/errata/RHSA-2023:7112",
            "https://access.redhat.com/errata/RHSA-2024:0417",
            "https://access.redhat.com/errata/RHSA-2024:2577",
            "https://access.redhat.com/security/cve/CVE-2023-4641",
            "https://bugzilla.redhat.com/2215945",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2215945",
            "https://errata.almalinux.org/9/ALSA-2023-6632.html",
            "https://linux.oracle.com/cve/CVE-2023-4641.html",
            "https://linux.oracle.com/errata/ELSA-2023-7112.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-4641",
            "https://ubuntu.com/security/notices/USN-6640-1",
            "https://www.cve.org/CVERecord?id=CVE-2023-4641"
          ],
          "PublishedDate": "2023-12-27T16:15:13.363Z",
          "LastModifiedDate": "2024-05-03T16:15:11.09Z"
        },
        {
          "VulnerabilityID": "CVE-2007-5686",
          "PkgID": "passwd@1:4.5-1.1",
          "PkgName": "passwd",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/passwd@4.5-1.1?arch=amd64\u0026distro=debian-10.13\u0026epoch=1",
            "UID": "c44fae08ce6b1859"
          },
          "InstalledVersion": "1:4.5-1.1",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2007-5686",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "initscripts in rPath Linux 1 sets insecure permissions for the /var/lo ...",
          "Description": "initscripts in rPath Linux 1 sets insecure permissions for the /var/log/btmp file, which allows local users to obtain sensitive information regarding authentication attempts.  NOTE: because sshd detects the insecure permissions and does not log certain events, this also prevents sshd from logging failed authentication attempts by remote attackers.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-264"
          ],
          "VendorSeverity": {
            "debian": 1,
            "nvd": 2
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:L/AC:L/Au:N/C:C/I:N/A:N",
              "V2Score": 4.9
            }
          },
          "References": [
            "http://secunia.com/advisories/27215",
            "http://www.securityfocus.com/archive/1/482129/100/100/threaded",
            "http://www.securityfocus.com/archive/1/482857/100/0/threaded",
            "http://www.securityfocus.com/bid/26048",
            "http://www.vupen.com/english/advisories/2007/3474",
            "https://issues.rpath.com/browse/RPL-1825"
          ],
          "PublishedDate": "2007-10-28T17:08:00Z",
          "LastModifiedDate": "2018-10-15T21:45:59.05Z"
        },
        {
          "VulnerabilityID": "CVE-2013-4235",
          "PkgID": "passwd@1:4.5-1.1",
          "PkgName": "passwd",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/passwd@4.5-1.1?arch=amd64\u0026distro=debian-10.13\u0026epoch=1",
            "UID": "c44fae08ce6b1859"
          },
          "InstalledVersion": "1:4.5-1.1",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2013-4235",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "shadow-utils: TOCTOU race conditions by copying and removing directory trees",
          "Description": "shadow: TOCTOU (time-of-check time-of-use) race condition when copying and removing directory trees",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-367"
          ],
          "VendorSeverity": {
            "debian": 1,
            "nvd": 2,
            "photon": 2,
            "redhat": 1,
            "ubuntu": 1
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:L/AC:M/Au:N/C:N/I:P/A:P",
              "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N",
              "V2Score": 3.3,
              "V3Score": 4.7
            },
            "redhat": {
              "V2Vector": "AV:L/AC:H/Au:N/C:P/I:P/A:P",
              "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:N/I:H/A:N",
              "V2Score": 3.7,
              "V3Score": 4.4
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2013-4235",
            "https://access.redhat.com/security/cve/cve-2013-4235",
            "https://bugs.launchpad.net/ubuntu/+source/shadow/+bug/1998169",
            "https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2013-4235",
            "https://github.com/shadow-maint/shadow/issues/317",
            "https://github.com/shadow-maint/shadow/pull/545",
            "https://lists.apache.org/thread.html/rf9fa47ab66495c78bb4120b0754dd9531ca2ff0430f6685ac9b07772%40%3Cdev.mina.apache.org%3E",
            "https://nvd.nist.gov/vuln/detail/CVE-2013-4235",
            "https://security-tracker.debian.org/tracker/CVE-2013-4235",
            "https://security.gentoo.org/glsa/202210-26",
            "https://ubuntu.com/security/notices/USN-5745-1",
            "https://ubuntu.com/security/notices/USN-5745-2",
            "https://www.cve.org/CVERecord?id=CVE-2013-4235"
          ],
          "PublishedDate": "2019-12-03T15:15:10.963Z",
          "LastModifiedDate": "2023-02-13T00:28:41.337Z"
        },
        {
          "VulnerabilityID": "CVE-2018-7169",
          "PkgID": "passwd@1:4.5-1.1",
          "PkgName": "passwd",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/passwd@4.5-1.1?arch=amd64\u0026distro=debian-10.13\u0026epoch=1",
            "UID": "c44fae08ce6b1859"
          },
          "InstalledVersion": "1:4.5-1.1",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2018-7169",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "shadow-utils: newgidmap allows unprivileged user to drop supplementary groups potentially allowing privilege escalation",
          "Description": "An issue was discovered in shadow 4.5. newgidmap (in shadow-utils) is setuid and allows an unprivileged user to be placed in a user namespace where setgroups(2) is permitted. This allows an attacker to remove themselves from a supplementary group, which may allow access to certain filesystem paths if the administrator has used \"group blacklisting\" (e.g., chmod g-rwx) to restrict access to paths. This flaw effectively reverts a security feature in the kernel (in particular, the /proc/self/setgroups knob) to prevent this sort of privilege escalation.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-732"
          ],
          "VendorSeverity": {
            "debian": 1,
            "nvd": 2,
            "photon": 2,
            "redhat": 2,
            "ubuntu": 1
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:P/I:N/A:N",
              "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
              "V2Score": 5,
              "V3Score": 5.3
            },
            "redhat": {
              "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
              "V3Score": 4.4
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2018-7169",
            "https://bugs.launchpad.net/ubuntu/+source/shadow/+bug/1729357",
            "https://github.com/shadow-maint/shadow/pull/97",
            "https://nvd.nist.gov/vuln/detail/CVE-2018-7169",
            "https://security.gentoo.org/glsa/201805-09",
            "https://ubuntu.com/security/notices/USN-5254-1",
            "https://www.cve.org/CVERecord?id=CVE-2018-7169"
          ],
          "PublishedDate": "2018-02-15T20:29:00.867Z",
          "LastModifiedDate": "2019-10-03T00:03:26.223Z"
        },
        {
          "VulnerabilityID": "CVE-2019-19882",
          "PkgID": "passwd@1:4.5-1.1",
          "PkgName": "passwd",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/passwd@4.5-1.1?arch=amd64\u0026distro=debian-10.13\u0026epoch=1",
            "UID": "c44fae08ce6b1859"
          },
          "InstalledVersion": "1:4.5-1.1",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2019-19882",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "shadow-utils: local users can obtain root access because setuid programs are misconfigured",
          "Description": "shadow 4.8, in certain circumstances affecting at least Gentoo, Arch Linux, and Void Linux, allows local users to obtain root access because setuid programs are misconfigured. Specifically, this affects shadow 4.8 when compiled using --with-libpam but without explicitly passing --disable-account-tools-setuid, and without a PAM configuration suitable for use with setuid account management tools. This combination leads to account management tools (groupadd, groupdel, groupmod, useradd, userdel, usermod) that can easily be used by unprivileged local users to escalate privileges to root in multiple ways. This issue became much more relevant in approximately December 2019 when an unrelated bug was fixed (i.e., the chmod calls to suidusbins were fixed in the upstream Makefile which is now included in the release version 4.8).",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-732"
          ],
          "VendorSeverity": {
            "debian": 1,
            "nvd": 3,
            "redhat": 3
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:L/AC:M/Au:N/C:C/I:C/A:C",
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
              "V2Score": 6.9,
              "V3Score": 7.8
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
              "V3Score": 7.8
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2019-19882",
            "https://bugs.archlinux.org/task/64836",
            "https://bugs.gentoo.org/702252",
            "https://github.com/shadow-maint/shadow/commit/edf7547ad5aa650be868cf2dac58944773c12d75",
            "https://github.com/shadow-maint/shadow/pull/199",
            "https://github.com/void-linux/void-packages/pull/17580",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-19882",
            "https://security.gentoo.org/glsa/202008-09",
            "https://www.cve.org/CVERecord?id=CVE-2019-19882"
          ],
          "PublishedDate": "2019-12-18T16:15:26.963Z",
          "LastModifiedDate": "2020-08-25T15:15:11.903Z"
        },
        {
          "VulnerabilityID": "CVE-2023-29383",
          "PkgID": "passwd@1:4.5-1.1",
          "PkgName": "passwd",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/passwd@4.5-1.1?arch=amd64\u0026distro=debian-10.13\u0026epoch=1",
            "UID": "c44fae08ce6b1859"
          },
          "InstalledVersion": "1:4.5-1.1",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-29383",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "shadow: Improper input validation in shadow-utils package utility chfn",
          "Description": "In Shadow 4.13, it is possible to inject control characters into fields provided to the SUID program chfn (change finger). Although it is not possible to exploit this directly (e.g., adding a new user fails because \\n is in the block list), it is possible to misrepresent the /etc/passwd file when viewed. Use of \\r manipulations and Unicode characters to work around blocking of the : character make it possible to give the impression that a new user has been added. In other words, an adversary may be able to convince a system administrator to take the system offline (an indirect, social-engineered denial of service) by demonstrating that \"cat /etc/passwd\" shows a rogue user account.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-74"
          ],
          "VendorSeverity": {
            "nvd": 1,
            "photon": 1,
            "redhat": 2,
            "ubuntu": 1
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N",
              "V3Score": 3.3
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
              "V3Score": 5.5
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2023-29383",
            "https://github.com/shadow-maint/shadow/commit/e5905c4b84d4fb90aefcd96ee618411ebfac663d",
            "https://github.com/shadow-maint/shadow/pull/687",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-29383",
            "https://www.cve.org/CVERecord?id=CVE-2023-29383",
            "https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/cve-2023-29383-abusing-linux-chfn-to-misrepresent-etc-passwd/",
            "https://www.trustwave.com/en-us/resources/security-resources/security-advisories/?fid=31797"
          ],
          "PublishedDate": "2023-04-14T22:15:07.68Z",
          "LastModifiedDate": "2023-04-24T18:05:30.313Z"
        },
        {
          "VulnerabilityID": "TEMP-0628843-DBAD28",
          "PkgID": "passwd@1:4.5-1.1",
          "PkgName": "passwd",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/passwd@4.5-1.1?arch=amd64\u0026distro=debian-10.13\u0026epoch=1",
            "UID": "c44fae08ce6b1859"
          },
          "InstalledVersion": "1:4.5-1.1",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://security-tracker.debian.org/tracker/TEMP-0628843-DBAD28",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "[more related to CVE-2005-4890]",
          "Severity": "LOW",
          "VendorSeverity": {
            "debian": 1
          }
        },
        {
          "VulnerabilityID": "CVE-2020-16156",
          "PkgID": "perl-base@5.28.1-6+deb10u1",
          "PkgName": "perl-base",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/perl-base@5.28.1-6%2Bdeb10u1?arch=amd64\u0026distro=debian-10.13",
            "UID": "640629bdfa8406cb"
          },
          "InstalledVersion": "5.28.1-6+deb10u1",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2020-16156",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "perl-CPAN: Bypass of verification of signatures in CHECKSUMS files",
          "Description": "CPAN 2.28 allows Signature Verification Bypass.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-347"
          ],
          "VendorSeverity": {
            "amazon": 2,
            "nvd": 3,
            "redhat": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
              "V2Score": 6.8,
              "V3Score": 7.8
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
              "V3Score": 7.8
            }
          },
          "References": [
            "http://blogs.perl.org/users/neilb/2021/11/addressing-cpan-vulnerabilities-related-to-checksums.html",
            "https://access.redhat.com/security/cve/CVE-2020-16156",
            "https://blog.hackeriet.no/cpan-signature-verification-vulnerabilities/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/SD6RYOJII7HRJ6WVORFNVTYNOFY5JDXN/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/SZ32AJIV4RHJMLWLU5QULGKMMIHYOMDC/",
            "https://metacpan.org/pod/distribution/CPAN/scripts/cpan",
            "https://nvd.nist.gov/vuln/detail/CVE-2020-16156",
            "https://ubuntu.com/security/notices/USN-5689-1",
            "https://ubuntu.com/security/notices/USN-5689-2",
            "https://www.cve.org/CVERecord?id=CVE-2020-16156"
          ],
          "PublishedDate": "2021-12-13T18:15:07.943Z",
          "LastModifiedDate": "2023-11-07T03:18:12.83Z"
        },
        {
          "VulnerabilityID": "CVE-2023-31484",
          "PkgID": "perl-base@5.28.1-6+deb10u1",
          "PkgName": "perl-base",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/perl-base@5.28.1-6%2Bdeb10u1?arch=amd64\u0026distro=debian-10.13",
            "UID": "640629bdfa8406cb"
          },
          "InstalledVersion": "5.28.1-6+deb10u1",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-31484",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "perl: CPAN.pm does not verify TLS certificates when downloading distributions over HTTPS",
          "Description": "CPAN.pm before 2.35 does not verify TLS certificates when downloading distributions over HTTPS.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-295"
          ],
          "VendorSeverity": {
            "alma": 2,
            "amazon": 3,
            "cbl-mariner": 3,
            "nvd": 3,
            "oracle-oval": 2,
            "redhat": 2,
            "rocky": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
              "V3Score": 8.1
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
              "V3Score": 7.4
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2023/04/29/1",
            "http://www.openwall.com/lists/oss-security/2023/05/03/3",
            "http://www.openwall.com/lists/oss-security/2023/05/03/5",
            "http://www.openwall.com/lists/oss-security/2023/05/07/2",
            "https://access.redhat.com/errata/RHSA-2023:6539",
            "https://access.redhat.com/security/cve/CVE-2023-31484",
            "https://blog.hackeriet.no/perl-http-tiny-insecure-tls-default-affects-cpan-modules/",
            "https://bugzilla.redhat.com/2218667",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2218667",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-31484",
            "https://errata.almalinux.org/9/ALSA-2023-6539.html",
            "https://errata.rockylinux.org/RLSA-2023:6539",
            "https://github.com/andk/cpanpm/commit/9c98370287f4e709924aee7c58ef21c85289a7f0 (2.35-TRIAL)",
            "https://github.com/andk/cpanpm/pull/175",
            "https://linux.oracle.com/cve/CVE-2023-31484.html",
            "https://linux.oracle.com/errata/ELSA-2024-3094.html",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/BM6UW55CNFUTNGD5ZRKGUKKKFDJGMFHL/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/LEGCEOKFJVBJ2QQ6S2H4NAEWTUERC7SB/",
            "https://metacpan.org/dist/CPAN/changes",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-31484",
            "https://security.netapp.com/advisory/ntap-20240621-0007/",
            "https://ubuntu.com/security/notices/USN-6112-1",
            "https://ubuntu.com/security/notices/USN-6112-2",
            "https://www.cve.org/CVERecord?id=CVE-2023-31484",
            "https://www.openwall.com/lists/oss-security/2023/04/18/14"
          ],
          "PublishedDate": "2023-04-29T00:15:09Z",
          "LastModifiedDate": "2024-08-01T13:43:46.38Z"
        },
        {
          "VulnerabilityID": "CVE-2011-4116",
          "PkgID": "perl-base@5.28.1-6+deb10u1",
          "PkgName": "perl-base",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/perl-base@5.28.1-6%2Bdeb10u1?arch=amd64\u0026distro=debian-10.13",
            "UID": "640629bdfa8406cb"
          },
          "InstalledVersion": "5.28.1-6+deb10u1",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2011-4116",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "perl: File:: Temp insecure temporary file handling",
          "Description": "_is_safe in the File::Temp module for Perl does not properly handle symlinks.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-59"
          ],
          "VendorSeverity": {
            "debian": 1,
            "nvd": 3,
            "redhat": 1
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:N/I:P/A:N",
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
              "V2Score": 5,
              "V3Score": 7.5
            },
            "redhat": {
              "V2Vector": "AV:L/AC:M/Au:N/C:N/I:P/A:N",
              "V2Score": 1.9
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2011/11/04/2",
            "http://www.openwall.com/lists/oss-security/2011/11/04/4",
            "https://access.redhat.com/security/cve/CVE-2011-4116",
            "https://github.com/Perl-Toolchain-Gang/File-Temp/issues/14",
            "https://nvd.nist.gov/vuln/detail/CVE-2011-4116",
            "https://rt.cpan.org/Public/Bug/Display.html?id=69106",
            "https://seclists.org/oss-sec/2011/q4/238",
            "https://www.cve.org/CVERecord?id=CVE-2011-4116"
          ],
          "PublishedDate": "2020-01-31T18:15:11.343Z",
          "LastModifiedDate": "2020-02-05T22:10:26.29Z"
        },
        {
          "VulnerabilityID": "CVE-2023-31486",
          "PkgID": "perl-base@5.28.1-6+deb10u1",
          "PkgName": "perl-base",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/perl-base@5.28.1-6%2Bdeb10u1?arch=amd64\u0026distro=debian-10.13",
            "UID": "640629bdfa8406cb"
          },
          "InstalledVersion": "5.28.1-6+deb10u1",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-31486",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "http-tiny: insecure TLS cert default",
          "Description": "HTTP::Tiny before 0.083, a Perl core module since 5.13.9 and available standalone on CPAN, has an insecure default TLS configuration where users must opt in to verify certificates.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-295"
          ],
          "VendorSeverity": {
            "alma": 2,
            "amazon": 3,
            "cbl-mariner": 3,
            "debian": 1,
            "nvd": 3,
            "oracle-oval": 2,
            "photon": 3,
            "redhat": 2
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
              "V3Score": 8.1
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
              "V3Score": 8.1
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2023/04/29/1",
            "http://www.openwall.com/lists/oss-security/2023/05/03/3",
            "http://www.openwall.com/lists/oss-security/2023/05/03/5",
            "http://www.openwall.com/lists/oss-security/2023/05/07/2",
            "https://access.redhat.com/errata/RHSA-2023:6542",
            "https://access.redhat.com/security/cve/CVE-2023-31486",
            "https://blog.hackeriet.no/perl-http-tiny-insecure-tls-default-affects-cpan-modules/",
            "https://bugzilla.redhat.com/2228392",
            "https://errata.almalinux.org/9/ALSA-2023-6542.html",
            "https://github.com/chansen/p5-http-tiny/pull/153",
            "https://hackeriet.github.io/cpan-http-tiny-overview/",
            "https://linux.oracle.com/cve/CVE-2023-31486.html",
            "https://linux.oracle.com/errata/ELSA-2023-7174.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-31486",
            "https://www.cve.org/CVERecord?id=CVE-2023-31486",
            "https://www.openwall.com/lists/oss-security/2023/04/18/14",
            "https://www.openwall.com/lists/oss-security/2023/05/03/4",
            "https://www.reddit.com/r/perl/comments/111tadi/psa_httptiny_disabled_ssl_verification_by_default/"
          ],
          "PublishedDate": "2023-04-29T00:15:09.083Z",
          "LastModifiedDate": "2023-06-21T18:19:52.937Z"
        },
        {
          "VulnerabilityID": "TEMP-0517018-A83CE6",
          "PkgID": "sysvinit-utils@2.93-8",
          "PkgName": "sysvinit-utils",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/sysvinit-utils@2.93-8?arch=amd64\u0026distro=debian-10.13",
            "UID": "ad55e68f9ad670dd"
          },
          "InstalledVersion": "2.93-8",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://security-tracker.debian.org/tracker/TEMP-0517018-A83CE6",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "[sysvinit: no-root option in expert installer exposes locally exploitable security flaw]",
          "Severity": "LOW",
          "VendorSeverity": {
            "debian": 1
          }
        },
        {
          "VulnerabilityID": "CVE-2005-2541",
          "PkgID": "tar@1.30+dfsg-6",
          "PkgName": "tar",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/tar@1.30%2Bdfsg-6?arch=amd64\u0026distro=debian-10.13",
            "UID": "e44eb37ce90d4255"
          },
          "InstalledVersion": "1.30+dfsg-6",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2005-2541",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "tar: does not properly warn the user when extracting setuid or setgid files",
          "Description": "Tar 1.15.1 does not properly warn the user when extracting setuid or setgid files, which may allow local users or remote attackers to gain privileges.",
          "Severity": "LOW",
          "VendorSeverity": {
            "debian": 1,
            "nvd": 3,
            "redhat": 2
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:C/I:C/A:C",
              "V2Score": 10
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H",
              "V3Score": 7
            }
          },
          "References": [
            "http://marc.info/?l=bugtraq\u0026m=112327628230258\u0026w=2",
            "https://access.redhat.com/security/cve/CVE-2005-2541",
            "https://lists.apache.org/thread.html/rc713534b10f9daeee2e0990239fa407e2118e4aa9e88a7041177497c%40%3Cissues.guacamole.apache.org%3E",
            "https://nvd.nist.gov/vuln/detail/CVE-2005-2541",
            "https://www.cve.org/CVERecord?id=CVE-2005-2541"
          ],
          "PublishedDate": "2005-08-10T04:00:00Z",
          "LastModifiedDate": "2023-11-07T01:57:39.453Z"
        },
        {
          "VulnerabilityID": "CVE-2019-9923",
          "PkgID": "tar@1.30+dfsg-6",
          "PkgName": "tar",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/tar@1.30%2Bdfsg-6?arch=amd64\u0026distro=debian-10.13",
            "UID": "e44eb37ce90d4255"
          },
          "InstalledVersion": "1.30+dfsg-6",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2019-9923",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "tar: null-pointer dereference in pax_decode_header in sparse.c",
          "Description": "pax_decode_header in sparse.c in GNU Tar before 1.32 had a NULL pointer dereference when parsing certain archives that have malformed extended headers.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-476"
          ],
          "VendorSeverity": {
            "amazon": 2,
            "debian": 1,
            "nvd": 3,
            "photon": 3,
            "redhat": 1,
            "ubuntu": 1
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
              "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V2Score": 5,
              "V3Score": 7.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L",
              "V3Score": 3.3
            }
          },
          "References": [
            "http://git.savannah.gnu.org/cgit/tar.git/commit/?id=cb07844454d8cc9fb21f53ace75975f91185a120",
            "http://lists.opensuse.org/opensuse-security-announce/2019-04/msg00077.html",
            "http://savannah.gnu.org/bugs/?55369",
            "https://access.redhat.com/security/cve/CVE-2019-9923",
            "https://bugs.launchpad.net/ubuntu/+source/tar/+bug/1810241",
            "https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b%40%3Cissues.bookkeeper.apache.org%3E",
            "https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4%40%3Cissues.bookkeeper.apache.org%3E",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-9923",
            "https://ubuntu.com/security/notices/USN-4692-1",
            "https://www.cve.org/CVERecord?id=CVE-2019-9923"
          ],
          "PublishedDate": "2019-03-22T08:29:00.247Z",
          "LastModifiedDate": "2023-11-07T03:13:48.96Z"
        },
        {
          "VulnerabilityID": "CVE-2021-20193",
          "PkgID": "tar@1.30+dfsg-6",
          "PkgName": "tar",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/tar@1.30%2Bdfsg-6?arch=amd64\u0026distro=debian-10.13",
            "UID": "e44eb37ce90d4255"
          },
          "InstalledVersion": "1.30+dfsg-6",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2021-20193",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "tar: Memory leak in read_header() in list.c",
          "Description": "A flaw was found in the src/list.c of tar 1.33 and earlier. This flaw allows an attacker who can submit a crafted input file to tar to cause uncontrolled consumption of memory. The highest threat from this vulnerability is to system availability.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-125",
            "CWE-401"
          ],
          "VendorSeverity": {
            "debian": 1,
            "nvd": 2,
            "photon": 2,
            "redhat": 2,
            "ubuntu": 1
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:P",
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
              "V2Score": 4.3,
              "V3Score": 5.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L",
              "V3Score": 3.3
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2021-20193",
            "https://bugzilla.redhat.com/show_bug.cgi?id=1917565",
            "https://git.savannah.gnu.org/cgit/tar.git/commit/?id=d9d4435692150fa8ff68e1b1a473d187cc3fd777",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-20193",
            "https://savannah.gnu.org/bugs/?59897",
            "https://security.gentoo.org/glsa/202105-29",
            "https://ubuntu.com/security/notices/USN-5329-1",
            "https://www.cve.org/CVERecord?id=CVE-2021-20193"
          ],
          "PublishedDate": "2021-03-26T17:15:12.843Z",
          "LastModifiedDate": "2023-11-07T03:28:59.727Z"
        },
        {
          "VulnerabilityID": "CVE-2022-48303",
          "PkgID": "tar@1.30+dfsg-6",
          "PkgName": "tar",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/tar@1.30%2Bdfsg-6?arch=amd64\u0026distro=debian-10.13",
            "UID": "e44eb37ce90d4255"
          },
          "InstalledVersion": "1.30+dfsg-6",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2022-48303",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "tar: heap buffer overflow at from_header() in list.c via specially crafted checksum",
          "Description": "GNU Tar through 1.34 has a one-byte out-of-bounds read that results in use of uninitialized memory for a conditional jump. Exploitation to change the flow of control has not been demonstrated. The issue occurs in from_header in list.c via a V7 archive in which mtime has approximately 11 whitespace characters.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-125"
          ],
          "VendorSeverity": {
            "alma": 2,
            "amazon": 3,
            "debian": 1,
            "nvd": 2,
            "oracle-oval": 2,
            "photon": 2,
            "redhat": 2,
            "rocky": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
              "V3Score": 5.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
              "V3Score": 5.5
            }
          },
          "References": [
            "https://access.redhat.com/errata/RHSA-2023:0959",
            "https://access.redhat.com/security/cve/CVE-2022-48303",
            "https://bugzilla.redhat.com/2149722",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2149722",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-48303",
            "https://errata.almalinux.org/9/ALSA-2023-0959.html",
            "https://errata.rockylinux.org/RLSA-2023:0959",
            "https://linux.oracle.com/cve/CVE-2022-48303.html",
            "https://linux.oracle.com/errata/ELSA-2023-0959.html",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/CRY7VEL4AIG3GLIEVCTOXRZNSVYDYYUD/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/X5VQYCO52Z7GAVCLRYUITN7KXHLRZQS4/",
            "https://nvd.nist.gov/vuln/detail/CVE-2022-48303",
            "https://savannah.gnu.org/bugs/?62387",
            "https://savannah.gnu.org/patch/?10307",
            "https://ubuntu.com/security/notices/USN-5900-1",
            "https://ubuntu.com/security/notices/USN-5900-2",
            "https://www.cve.org/CVERecord?id=CVE-2022-48303"
          ],
          "PublishedDate": "2023-01-30T04:15:08.03Z",
          "LastModifiedDate": "2023-05-30T17:16:57.713Z"
        },
        {
          "VulnerabilityID": "CVE-2023-39804",
          "VendorIDs": [
            "DLA-3755-1"
          ],
          "PkgID": "tar@1.30+dfsg-6",
          "PkgName": "tar",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/tar@1.30%2Bdfsg-6?arch=amd64\u0026distro=debian-10.13",
            "UID": "e44eb37ce90d4255"
          },
          "InstalledVersion": "1.30+dfsg-6",
          "FixedVersion": "1.30+dfsg-6+deb10u1",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-39804",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "tar: Incorrectly handled extension attributes in PAX archives can lead to a crash",
          "Description": "In GNU tar before 1.35, mishandled extension attributes in a PAX archive can lead to an application crash in xheader.c.",
          "Severity": "LOW",
          "VendorSeverity": {
            "amazon": 1,
            "photon": 1,
            "redhat": 1,
            "ubuntu": 2
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L",
              "V3Score": 3.3
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2023-39804",
            "https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1058079",
            "https://git.savannah.gnu.org/cgit/tar.git/commit/?id=a339f05cd269013fa133d2f148d73f6f7d4247e4",
            "https://git.savannah.gnu.org/cgit/tar.git/tree/src/xheader.c?h=release_1_34#n1723",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-39804",
            "https://ubuntu.com/security/notices/USN-6543-1",
            "https://www.cve.org/CVERecord?id=CVE-2023-39804"
          ],
          "PublishedDate": "2024-03-27T04:15:08.897Z",
          "LastModifiedDate": "2024-03-27T12:29:30.307Z"
        },
        {
          "VulnerabilityID": "TEMP-0290435-0B57B5",
          "PkgID": "tar@1.30+dfsg-6",
          "PkgName": "tar",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/tar@1.30%2Bdfsg-6?arch=amd64\u0026distro=debian-10.13",
            "UID": "e44eb37ce90d4255"
          },
          "InstalledVersion": "1.30+dfsg-6",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://security-tracker.debian.org/tracker/TEMP-0290435-0B57B5",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "[tar's rmt command may have undesired side effects]",
          "Severity": "LOW",
          "VendorSeverity": {
            "debian": 1
          }
        },
        {
          "VulnerabilityID": "DLA-3684-1",
          "VendorIDs": [
            "DLA-3684-1"
          ],
          "PkgID": "tzdata@2021a-0+deb10u11",
          "PkgName": "tzdata",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/tzdata@2021a-0%2Bdeb10u11?arch=all\u0026distro=debian-10.13",
            "UID": "b430d18b92440fbc"
          },
          "InstalledVersion": "2021a-0+deb10u11",
          "FixedVersion": "2021a-0+deb10u12",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "tzdata - new timezone database",
          "Severity": "UNKNOWN"
        },
        {
          "VulnerabilityID": "DLA-3788-1",
          "VendorIDs": [
            "DLA-3788-1"
          ],
          "PkgID": "tzdata@2021a-0+deb10u11",
          "PkgName": "tzdata",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/tzdata@2021a-0%2Bdeb10u11?arch=all\u0026distro=debian-10.13",
            "UID": "b430d18b92440fbc"
          },
          "InstalledVersion": "2021a-0+deb10u11",
          "FixedVersion": "2024a-0+deb10u1",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "tzdata - new timezone database",
          "Severity": "UNKNOWN"
        },
        {
          "VulnerabilityID": "CVE-2024-28085",
          "VendorIDs": [
            "DLA-3782-1"
          ],
          "PkgID": "util-linux@2.33.1-0.1",
          "PkgName": "util-linux",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/util-linux@2.33.1-0.1?arch=amd64\u0026distro=debian-10.13",
            "UID": "79caf161d49d6f55"
          },
          "InstalledVersion": "2.33.1-0.1",
          "FixedVersion": "2.33.1-0.1+deb10u1",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-28085",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "util-linux: CVE-2024-28085: wall: escape sequence injection",
          "Description": "wall in util-linux through 2.40, often installed with setgid tty permissions, allows escape sequences to be sent to other users' terminals through argv. (Specifically, escape sequences received from stdin are blocked, but escape sequences received from argv are not blocked.) There may be plausible scenarios where this leads to account takeover.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-150"
          ],
          "VendorSeverity": {
            "cbl-mariner": 4,
            "photon": 3,
            "redhat": 3,
            "ubuntu": 2
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N",
              "V3Score": 8.4
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2024/03/27/5",
            "http://www.openwall.com/lists/oss-security/2024/03/27/6",
            "http://www.openwall.com/lists/oss-security/2024/03/27/7",
            "http://www.openwall.com/lists/oss-security/2024/03/27/8",
            "http://www.openwall.com/lists/oss-security/2024/03/27/9",
            "http://www.openwall.com/lists/oss-security/2024/03/28/1",
            "http://www.openwall.com/lists/oss-security/2024/03/28/2",
            "http://www.openwall.com/lists/oss-security/2024/03/28/3",
            "https://access.redhat.com/security/cve/CVE-2024-28085",
            "https://github.com/skyler-ferrante/CVE-2024-28085",
            "https://github.com/util-linux/util-linux/security/advisories/GHSA-xv2h-c6ww-mrjq",
            "https://lists.debian.org/debian-lts-announce/2024/04/msg00005.html",
            "https://mirrors.edge.kernel.org/pub/linux/utils/util-linux/",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-28085",
            "https://people.rit.edu/sjf5462/6831711781/wall_2_27_2024.txt",
            "https://security.netapp.com/advisory/ntap-20240531-0003/",
            "https://ubuntu.com/security/notices/USN-6719-1",
            "https://ubuntu.com/security/notices/USN-6719-2",
            "https://www.cve.org/CVERecord?id=CVE-2024-28085",
            "https://www.openwall.com/lists/oss-security/2024/03/27/5"
          ],
          "PublishedDate": "2024-03-27T19:15:48.367Z",
          "LastModifiedDate": "2024-08-26T21:35:09.31Z"
        },
        {
          "VulnerabilityID": "CVE-2021-37600",
          "VendorIDs": [
            "DLA-3782-1"
          ],
          "PkgID": "util-linux@2.33.1-0.1",
          "PkgName": "util-linux",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/util-linux@2.33.1-0.1?arch=amd64\u0026distro=debian-10.13",
            "UID": "79caf161d49d6f55"
          },
          "InstalledVersion": "2.33.1-0.1",
          "FixedVersion": "2.33.1-0.1+deb10u1",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2021-37600",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "util-linux: integer overflow can lead to buffer overflow in get_sem_elements() in sys-utils/ipcutils.c",
          "Description": "An integer overflow in util-linux through 2.37.1 can potentially cause a buffer overflow if an attacker were able to use system resources in a way that leads to a large number in the /proc/sysvipc/sem file. NOTE: this is unexploitable in GNU C Library environments, and possibly in all realistic environments.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-190"
          ],
          "VendorSeverity": {
            "amazon": 1,
            "cbl-mariner": 2,
            "nvd": 2,
            "photon": 2,
            "redhat": 1,
            "ubuntu": 1
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:L/AC:H/Au:N/C:N/I:N/A:P",
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
              "V2Score": 1.2,
              "V3Score": 5.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:H",
              "V3Score": 4.7
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2021-37600",
            "https://github.com/karelzak/util-linux/commit/1c9143d0c1f979c3daf10e1c37b5b1e916c22a1c",
            "https://github.com/karelzak/util-linux/issues/1395",
            "https://lists.debian.org/debian-lts-announce/2024/04/msg00005.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-37600",
            "https://security.gentoo.org/glsa/202401-08",
            "https://security.netapp.com/advisory/ntap-20210902-0002/",
            "https://www.cve.org/CVERecord?id=CVE-2021-37600"
          ],
          "PublishedDate": "2021-07-30T14:15:18.737Z",
          "LastModifiedDate": "2024-08-04T02:15:24.44Z"
        },
        {
          "VulnerabilityID": "CVE-2022-0563",
          "PkgID": "util-linux@2.33.1-0.1",
          "PkgName": "util-linux",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/util-linux@2.33.1-0.1?arch=amd64\u0026distro=debian-10.13",
            "UID": "79caf161d49d6f55"
          },
          "InstalledVersion": "2.33.1-0.1",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2022-0563",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "util-linux: partial disclosure of arbitrary files in chfn and chsh when compiled with libreadline",
          "Description": "A flaw was found in the util-linux chfn and chsh utilities when compiled with Readline support. The Readline library uses an \"INPUTRC\" environment variable to get a path to the library config file. When the library cannot parse the specified file, it prints an error message containing data from the file. This flaw allows an unprivileged user to read root-owned files, potentially leading to privilege escalation. This flaw affects util-linux versions prior to 2.37.4.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-209"
          ],
          "VendorSeverity": {
            "amazon": 2,
            "cbl-mariner": 2,
            "debian": 1,
            "nvd": 2,
            "photon": 2,
            "redhat": 2
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:L/AC:M/Au:N/C:P/I:N/A:N",
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
              "V2Score": 1.9,
              "V3Score": 5.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
              "V3Score": 5.5
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2022-0563",
            "https://blog.trailofbits.com/2023/02/16/suid-logic-bug-linux-readline/",
            "https://lore.kernel.org/util-linux/20220214110609.msiwlm457ngoic6w%40ws.net.home/T/#u",
            "https://lore.kernel.org/util-linux/20220214110609.msiwlm457ngoic6w@ws.net.home/T/#u",
            "https://nvd.nist.gov/vuln/detail/CVE-2022-0563",
            "https://security.gentoo.org/glsa/202401-08",
            "https://security.netapp.com/advisory/ntap-20220331-0002/",
            "https://www.cve.org/CVERecord?id=CVE-2022-0563"
          ],
          "PublishedDate": "2022-02-21T19:15:08.393Z",
          "LastModifiedDate": "2024-01-07T09:15:08.713Z"
        },
        {
          "VulnerabilityID": "CVE-2023-45853",
          "PkgID": "zlib1g@1:1.2.11.dfsg-1+deb10u2",
          "PkgName": "zlib1g",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/zlib1g@1.2.11.dfsg-1%2Bdeb10u2?arch=amd64\u0026distro=debian-10.13\u0026epoch=1",
            "UID": "2ff99491c02ef5bb"
          },
          "InstalledVersion": "1:1.2.11.dfsg-1+deb10u2",
          "Status": "will_not_fix",
          "Layer": {
            "Digest": "sha256:8b91b88d557765cd8c6802668755a3f6dc4337b6ce15a17e4857139e5fc964f3",
            "DiffID": "sha256:e2ef8a51359d088511d34c725305c220294a1fcd5fe5e5dbe4d698c7239ce2c9"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-45853",
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Title": "zlib: integer overflow and resultant heap-based buffer overflow in zipOpenNewFileInZip4_6",
          "Description": "MiniZip in zlib through 1.3 has an integer overflow and resultant heap-based buffer overflow in zipOpenNewFileInZip4_64 via a long filename, comment, or extra field. NOTE: MiniZip is not a supported part of the zlib product. NOTE: pyminizip through 0.2.6 is also vulnerable because it bundles an affected zlib version, and exposes the applicable MiniZip code through its compress API.",
          "Severity": "CRITICAL",
          "CweIDs": [
            "CWE-190"
          ],
          "VendorSeverity": {
            "amazon": 2,
            "azure": 4,
            "cbl-mariner": 4,
            "ghsa": 4,
            "nvd": 4,
            "photon": 4,
            "redhat": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "ghsa": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
              "V3Score": 9.8
            },
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
              "V3Score": 9.8
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L",
              "V3Score": 5.3
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2023/10/20/9",
            "http://www.openwall.com/lists/oss-security/2024/01/24/10",
            "https://access.redhat.com/security/cve/CVE-2023-45853",
            "https://chromium.googlesource.com/chromium/src/+/d709fb23806858847131027da95ef4c548813356",
            "https://chromium.googlesource.com/chromium/src/+/de29dd6c7151d3cd37cb4cf0036800ddfb1d8b61",
            "https://github.com/madler/zlib/blob/ac8f12c97d1afd9bafa9c710f827d40a407d3266/contrib/README.contrib#L1-L4",
            "https://github.com/madler/zlib/commit/73331a6a0481067628f065ffe87bb1d8f787d10c",
            "https://github.com/madler/zlib/pull/843",
            "https://github.com/smihica/pyminizip",
            "https://github.com/smihica/pyminizip/blob/master/zlib-1.2.11/contrib/minizip/zip.c",
            "https://lists.debian.org/debian-lts-announce/2023/11/msg00026.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-45853",
            "https://pypi.org/project/pyminizip/#history",
            "https://security.gentoo.org/glsa/202401-18",
            "https://security.netapp.com/advisory/ntap-20231130-0009",
            "https://security.netapp.com/advisory/ntap-20231130-0009/",
            "https://www.cve.org/CVERecord?id=CVE-2023-45853",
            "https://www.winimage.com/zLibDll/minizip.html"
          ],
          "PublishedDate": "2023-10-14T02:15:09.323Z",
          "LastModifiedDate": "2024-08-01T13:44:58.99Z"
        }
      ]
    },
    {
      "Target": "Python",
      "Class": "lang-pkgs",
      "Type": "python-pkg",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2024-1135",
          "PkgName": "gunicorn",
          "PkgPath": "usr/local/lib/python3.8/site-packages/gunicorn-20.1.0.dist-info/METADATA",
          "PkgIdentifier": {
            "PURL": "pkg:pypi/gunicorn@20.1.0",
            "UID": "26a35666ffa0fbf0"
          },
          "InstalledVersion": "20.1.0",
          "FixedVersion": "22.0.0",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:35eaeba325b9afc7c2607a5b112f632d5183379b1ed3a984460b396b1499f819",
            "DiffID": "sha256:581dc61be3f191c3f6d38ab7dc849818f4628cd351389bde1ef6283ea8303f32"
          },
          "SeveritySource": "ghsa",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-1135",
          "DataSource": {
            "ID": "ghsa",
            "Name": "GitHub Security Advisory pip",
            "URL": "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Apip"
          },
          "Title": "python-gunicorn: HTTP Request Smuggling due to improper validation of Transfer-Encoding headers",
          "Description": "Gunicorn fails to properly validate Transfer-Encoding headers, leading to HTTP Request Smuggling (HRS) vulnerabilities. By crafting requests with conflicting Transfer-Encoding headers, attackers can bypass security restrictions and access restricted endpoints. This issue is due to Gunicorn's handling of Transfer-Encoding headers, where it incorrectly processes requests with multiple, conflicting Transfer-Encoding headers, treating them as chunked regardless of the final encoding specified. This vulnerability allows for a range of attacks including cache poisoning, session manipulation, and data exposure.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-444"
          ],
          "VendorSeverity": {
            "ghsa": 3,
            "redhat": 3
          },
          "CVSS": {
            "ghsa": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N",
              "V3Score": 8.2
            },
            "redhat": {
              "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
              "V3Score": 7.5
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2024-1135",
            "https://github.com/advisories/GHSA-w3h3-4rj7-4ph4",
            "https://github.com/benoitc/gunicorn",
            "https://github.com/benoitc/gunicorn/commit/ac29c9b0a758d21f1e0fb3b3457239e523fa9f1d",
            "https://github.com/benoitc/gunicorn/releases/tag/22.0.0",
            "https://huntr.com/bounties/22158e34-cfd5-41ad-97e0-a780773d96c1",
            "https://lists.debian.org/debian-lts-announce/2024/06/msg00027.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-1135",
            "https://www.cve.org/CVERecord?id=CVE-2024-1135"
          ],
          "PublishedDate": "2024-04-16T00:15:07.797Z",
          "LastModifiedDate": "2024-06-30T23:15:02.563Z"
        },
        {
          "VulnerabilityID": "CVE-2023-5752",
          "PkgName": "pip",
          "PkgPath": "usr/local/lib/python3.8/site-packages/pip-23.0.1.dist-info/METADATA",
          "PkgIdentifier": {
            "PURL": "pkg:pypi/pip@23.0.1",
            "UID": "f91480242266b678"
          },
          "InstalledVersion": "23.0.1",
          "FixedVersion": "23.3",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:276dfcf5deffff3c5d540a8e0d9a18656a4c03637a8b4f4eec1f4a147799c901",
            "DiffID": "sha256:e6c5004ee77f450910ca26a9ef2e476ce766b3e4c83d034edfc28ff3736297a1"
          },
          "SeveritySource": "ghsa",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-5752",
          "DataSource": {
            "ID": "ghsa",
            "Name": "GitHub Security Advisory pip",
            "URL": "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Apip"
          },
          "Title": "pip: Mercurial configuration injectable in repo revision when installing via pip",
          "Description": "When installing a package from a Mercurial VCS URL  (ie \"pip install \nhg+...\") with pip prior to v23.3, the specified Mercurial revision could\n be used to inject arbitrary configuration options to the \"hg clone\" \ncall (ie \"--config\"). Controlling the Mercurial configuration can modify\n how and which repository is installed. This vulnerability does not \naffect users who aren't installing from Mercurial.\n",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-77"
          ],
          "VendorSeverity": {
            "amazon": 2,
            "azure": 1,
            "bitnami": 1,
            "ghsa": 2,
            "nvd": 1,
            "redhat": 1
          },
          "CVSS": {
            "bitnami": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N",
              "V3Score": 3.3
            },
            "ghsa": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",
              "V3Score": 5.5
            },
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N",
              "V3Score": 3.3
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N",
              "V3Score": 3.3
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2023-5752",
            "https://github.com/pypa/advisory-database/tree/main/vulns/pip/PYSEC-2023-228.yaml",
            "https://github.com/pypa/pip",
            "https://github.com/pypa/pip/commit/389cb799d0da9a840749fcd14878928467ed49b4",
            "https://github.com/pypa/pip/pull/12306",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/622OZXWG72ISQPLM5Y57YCVIMWHD4C3U",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/622OZXWG72ISQPLM5Y57YCVIMWHD4C3U/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/65UKKF5LBHEFDCUSPBHUN4IHYX7SRMHH",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/65UKKF5LBHEFDCUSPBHUN4IHYX7SRMHH/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FXUVMJM25PUAZRQZBF54OFVKTY3MINPW",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FXUVMJM25PUAZRQZBF54OFVKTY3MINPW/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/KFC2SPFG5FLCZBYY2K3T5MFW2D22NG6E",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/KFC2SPFG5FLCZBYY2K3T5MFW2D22NG6E/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/YBSB3SUPQ3VIFYUMHPO3MEQI4BJAXKCZ",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/YBSB3SUPQ3VIFYUMHPO3MEQI4BJAXKCZ/",
            "https://mail.python.org/archives/list/security-announce@python.org/thread/F4PL35U6X4VVHZ5ILJU3PWUWN7H7LZXL",
            "https://mail.python.org/archives/list/security-announce@python.org/thread/F4PL35U6X4VVHZ5ILJU3PWUWN7H7LZXL/",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-5752",
            "https://www.cve.org/CVERecord?id=CVE-2023-5752"
          ],
          "PublishedDate": "2023-10-25T18:17:44.867Z",
          "LastModifiedDate": "2024-06-10T18:15:24.66Z"
        },
        {
          "VulnerabilityID": "CVE-2022-40897",
          "PkgName": "setuptools",
          "PkgPath": "usr/local/lib/python3.8/site-packages/setuptools-57.5.0.dist-info/METADATA",
          "PkgIdentifier": {
            "PURL": "pkg:pypi/setuptools@57.5.0",
            "UID": "a52186826fd56ee6"
          },
          "InstalledVersion": "57.5.0",
          "FixedVersion": "65.5.1",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:276dfcf5deffff3c5d540a8e0d9a18656a4c03637a8b4f4eec1f4a147799c901",
            "DiffID": "sha256:e6c5004ee77f450910ca26a9ef2e476ce766b3e4c83d034edfc28ff3736297a1"
          },
          "SeveritySource": "ghsa",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2022-40897",
          "DataSource": {
            "ID": "ghsa",
            "Name": "GitHub Security Advisory pip",
            "URL": "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Apip"
          },
          "Title": "pypa-setuptools: Regular Expression Denial of Service (ReDoS) in package_index.py",
          "Description": "Python Packaging Authority (PyPA) setuptools before 65.5.1 allows remote attackers to cause a denial of service via HTML in a crafted package or custom PackageIndex page. There is a Regular Expression Denial of Service (ReDoS) in package_index.py.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-1333"
          ],
          "VendorSeverity": {
            "alma": 2,
            "amazon": 2,
            "bitnami": 2,
            "cbl-mariner": 2,
            "ghsa": 3,
            "nvd": 2,
            "oracle-oval": 2,
            "photon": 2,
            "redhat": 2,
            "rocky": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "bitnami": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 5.9
            },
            "ghsa": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 7.5
            },
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 5.9
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 5.9
            }
          },
          "References": [
            "https://access.redhat.com/errata/RHSA-2023:0952",
            "https://access.redhat.com/security/cve/CVE-2022-40897",
            "https://bugzilla.redhat.com/2158559",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2158559",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-40897",
            "https://errata.almalinux.org/9/ALSA-2023-0952.html",
            "https://errata.rockylinux.org/RLSA-2023:0952",
            "https://github.com/pypa/setuptools",
            "https://github.com/pypa/setuptools/blob/fe8a98e696241487ba6ac9f91faa38ade939ec5d/setuptools/package_index.py#L200",
            "https://github.com/pypa/setuptools/commit/43a9c9bfa6aa626ec2a22540bea28d2ca77964be",
            "https://github.com/pypa/setuptools/compare/v65.5.0...v65.5.1",
            "https://github.com/pypa/setuptools/issues/3659",
            "https://linux.oracle.com/cve/CVE-2022-40897.html",
            "https://linux.oracle.com/errata/ELSA-2024-2987.html",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/ADES3NLOE5QJKBLGNZNI2RGVOSQXA37R",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/ADES3NLOE5QJKBLGNZNI2RGVOSQXA37R/",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/YNA2BAH2ACBZ4TVJZKFLCR7L23BG5C3H",
            "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/YNA2BAH2ACBZ4TVJZKFLCR7L23BG5C3H/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ADES3NLOE5QJKBLGNZNI2RGVOSQXA37R",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/YNA2BAH2ACBZ4TVJZKFLCR7L23BG5C3H",
            "https://nvd.nist.gov/vuln/detail/CVE-2022-40897",
            "https://pyup.io/posts/pyup-discovers-redos-vulnerabilities-in-top-python-packages",
            "https://pyup.io/posts/pyup-discovers-redos-vulnerabilities-in-top-python-packages/",
            "https://pyup.io/vulnerabilities/CVE-2022-40897/52495",
            "https://pyup.io/vulnerabilities/CVE-2022-40897/52495/",
            "https://security.netapp.com/advisory/ntap-20230214-0001",
            "https://security.netapp.com/advisory/ntap-20230214-0001/",
            "https://security.netapp.com/advisory/ntap-20240621-0006",
            "https://security.netapp.com/advisory/ntap-20240621-0006/",
            "https://setuptools.pypa.io/en/latest",
            "https://ubuntu.com/security/notices/USN-5817-1",
            "https://www.cve.org/CVERecord?id=CVE-2022-40897"
          ],
          "PublishedDate": "2022-12-23T00:15:13.987Z",
          "LastModifiedDate": "2024-06-21T19:15:23.877Z"
        },
        {
          "VulnerabilityID": "CVE-2024-6345",
          "PkgName": "setuptools",
          "PkgPath": "usr/local/lib/python3.8/site-packages/setuptools-57.5.0.dist-info/METADATA",
          "PkgIdentifier": {
            "PURL": "pkg:pypi/setuptools@57.5.0",
            "UID": "a52186826fd56ee6"
          },
          "InstalledVersion": "57.5.0",
          "FixedVersion": "70.0.0",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:276dfcf5deffff3c5d540a8e0d9a18656a4c03637a8b4f4eec1f4a147799c901",
            "DiffID": "sha256:e6c5004ee77f450910ca26a9ef2e476ce766b3e4c83d034edfc28ff3736297a1"
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
      "Target": "/app/.github/workflows/dev.yml",
      "Class": "secret",
      "Secrets": [
        {
          "RuleID": "github-pat",
          "Category": "GitHub",
          "Severity": "CRITICAL",
          "Title": "GitHub Personal Access Token",
          "StartLine": 56,
          "EndLine": 56,
          "Code": {
            "Lines": [
              {
                "Number": 54,
                "Content": "      uses: peter-evans/repository-dispatch@v1",
                "IsCause": false,
                "Annotation": "",
                "Truncated": false,
                "Highlighted": "      uses: peter-evans/repository-dispatch@v1",
                "FirstCause": false,
                "LastCause": false
              },
              {
                "Number": 55,
                "Content": "      with:",
                "IsCause": false,
                "Annotation": "",
                "Truncated": false,
                "Highlighted": "      with:",
                "FirstCause": false,
                "LastCause": false
              },
              {
                "Number": 56,
                "Content": "        token: ****************************************",
                "IsCause": true,
                "Annotation": "",
                "Truncated": false,
                "Highlighted": "        token: ****************************************",
                "FirstCause": true,
                "LastCause": true
              },
              {
                "Number": 57,
                "Content": "        repository: Bifrost3-0/helm_charts",
                "IsCause": false,
                "Annotation": "",
                "Truncated": false,
                "Highlighted": "        repository: Bifrost3-0/helm_charts",
                "FirstCause": false,
                "LastCause": false
              }
            ]
          },
          "Match": "        token: ****************************************",
          "Layer": {
            "Digest": "sha256:d25cd6300347a6cf46d6c9bff938ccac0519c0bfb88fea01220d377242647b60",
            "DiffID": "sha256:b9417271bdacb17935d774c807076f33b0de23f5311a76a1561903124e424eb0",
            "CreatedBy": "COPY . . # buildkit"
          }
        }
      ]
    },
    {
      "Target": "/app/.github/workflows/main.yml",
      "Class": "secret",
      "Secrets": [
        {
          "RuleID": "github-fine-grained-pat",
          "Category": "GitHub",
          "Severity": "CRITICAL",
          "Title": "GitHub Fine-grained personal access tokens",
          "StartLine": 54,
          "EndLine": 54,
          "Code": {
            "Lines": [
              {
                "Number": 52,
                "Content": "      uses: peter-evans/repository-dispatch@v1",
                "IsCause": false,
                "Annotation": "",
                "Truncated": false,
                "Highlighted": "      uses: peter-evans/repository-dispatch@v1",
                "FirstCause": false,
                "LastCause": false
              },
              {
                "Number": 53,
                "Content": "      with:",
                "IsCause": false,
                "Annotation": "",
                "Truncated": false,
                "Highlighted": "      with:",
                "FirstCause": false,
                "LastCause": false
              },
              {
                "Number": 54,
                "Content": "        token: *********************************************************************************************",
                "IsCause": true,
                "Annotation": "",
                "Truncated": false,
                "Highlighted": "        token: *********************************************************************************************",
                "FirstCause": true,
                "LastCause": true
              },
              {
                "Number": 55,
                "Content": "        repository: Bifrost3-0/helm_charts",
                "IsCause": false,
                "Annotation": "",
                "Truncated": false,
                "Highlighted": "        repository: Bifrost3-0/helm_charts",
                "FirstCause": false,
                "LastCause": false
              }
            ]
          },
          "Match": "        token: *********************************************************************************************",
          "Layer": {
            "Digest": "sha256:d25cd6300347a6cf46d6c9bff938ccac0519c0bfb88fea01220d377242647b60",
            "DiffID": "sha256:b9417271bdacb17935d774c807076f33b0de23f5311a76a1561903124e424eb0",
            "CreatedBy": "COPY . . # buildkit"
          }
        }
      ]
    }
  ]
}
