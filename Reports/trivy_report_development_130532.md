Summary Report for mi-cuenta-publica-context
============================================

Workload Assessment
┌─────────────┬──────────────────────────────────┬───────────────────────────────┬────────────────────┬────────────────────┐
│  Namespace  │             Resource             │        Vulnerabilities        │ Misconfigurations  │      Secrets       │
│             │                                  ├─────┬──────┬──────┬──────┬────┼───┬───┬───┬────┬───┼────┬───┬───┬───┬───┤
│             │                                  │  C  │  H   │  M   │  L   │ U  │ C │ H │ M │ L  │ U │ C  │ H │ M │ L │ U │
├─────────────┼──────────────────────────────────┼─────┼──────┼──────┼──────┼────┼───┼───┼───┼────┼───┼────┼───┼───┼───┼───┤
│ development │ Deployment/viasat-dev            │  9  │  65  │ 115  │ 228  │ 3  │   │ 6 │ 6 │ 22 │   │ 1  │   │   │   │   │
│ development │ Deployment/newtect-flask-dev     │     │      │      │      │    │   │ 2 │ 3 │ 9  │   │    │   │   │   │   │
│ development │ Deployment/orchestatorv3-dev     │  9  │  65  │ 115  │ 228  │ 3  │   │ 5 │ 6 │ 21 │   │ 2  │   │   │   │   │
│ development │ Deployment/app-devspace          │  9  │  12  │  50  │ 4    │    │   │ 1 │ 3 │ 9  │   │    │   │   │   │   │
│ development │ Deployment/grafanaleo-dev        │  4  │  8   │  25  │ 65   │    │   │ 3 │ 3 │ 10 │   │ 2  │   │   │   │   │
│ development │ Deployment/incident-dev          │     │      │      │      │    │   │ 2 │ 3 │ 9  │   │    │   │   │   │   │
│ development │ Deployment/sesback-dev           │  9  │  65  │ 115  │ 228  │ 3  │   │ 5 │ 6 │ 21 │   │ 1  │   │   │   │   │
│ development │ Deployment/backshopingdev        │  9  │  66  │ 116  │ 228  │ 3  │   │ 5 │ 6 │ 21 │   │ 2  │   │   │   │   │
│ development │ Deployment/general-functions-dev │  1  │  6   │  8   │      │    │   │ 3 │ 3 │ 10 │   │ 14 │   │   │   │   │
│ development │ Deployment/authv3-dev            │  5  │  53  │  66  │ 92   │ 3  │   │ 4 │ 3 │ 11 │   │ 2  │   │   │   │   │
│ development │ Deployment/generalf-dev          │  9  │  64  │ 116  │ 229  │ 3  │   │ 5 │ 6 │ 21 │   │ 4  │   │   │   │   │
│ development │ Deployment/ses-dev               │     │      │      │      │    │   │ 2 │ 3 │ 9  │   │    │   │   │   │   │
│ development │ Deployment/orchestatorv2-dev     │  2  │  48  │  47  │ 83   │ 2  │   │ 2 │ 3 │ 9  │   │    │   │   │   │   │
│ development │ Deployment/starlink-flask-dev    │  4  │  10  │  26  │ 65   │    │   │ 3 │ 3 │ 10 │   │ 1  │   │ 1 │   │   │
│ development │ Deployment/backstoredev          │  9  │  65  │ 115  │ 228  │ 3  │   │ 4 │ 6 │ 20 │   │ 2  │   │   │   │   │
│ development │ Deployment/support               │     │      │      │      │    │   │ 2 │ 3 │ 9  │   │    │   │   │   │   │
│ development │ Deployment/python-dev            │ 166 │ 1316 │ 3167 │ 1524 │ 42 │   │ 6 │ 6 │ 20 │   │ 3  │   │   │   │   │
│ development │ Deployment/support-dev           │     │      │      │      │    │   │ 2 │ 3 │ 9  │   │    │   │   │   │   │
│ development │ Pod/ssh-ubuntu                   │     │      │  3   │ 4    │    │   │ 2 │ 5 │ 9  │   │    │   │   │   │   │
└─────────────┴──────────────────────────────────┴─────┴──────┴──────┴──────┴────┴───┴───┴───┴────┴───┴────┴───┴───┴───┴───┘
Severities: C=CRITICAL H=HIGH M=MEDIUM L=LOW U=UNKNOWN


Infra Assessment
┌───────────┬──────────┬───────────────────┬───────────────────┬───────────────────┐
│ Namespace │ Resource │  Vulnerabilities  │ Misconfigurations │      Secrets      │
│           │          ├───┬───┬───┬───┬───┼───┬───┬───┬───┬───┼───┬───┬───┬───┬───┤
│           │          │ C │ H │ M │ L │ U │ C │ H │ M │ L │ U │ C │ H │ M │ L │ U │
└───────────┴──────────┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┘
Severities: C=CRITICAL H=HIGH M=MEDIUM L=LOW U=UNKNOWN


RBAC Assessment
┌───────────┬──────────┬───────────────────┐
│ Namespace │ Resource │  RBAC Assessment  │
│           │          ├───┬───┬───┬───┬───┤
│           │          │ C │ H │ M │ L │ U │
└───────────┴──────────┴───┴───┴───┴───┴───┘
Severities: C=CRITICAL H=HIGH M=MEDIUM L=LOW U=UNKNOWN


