# System Architecture

## High-level component view

```mermaid
flowchart LR
    Client[Client Browser or Bot] --> Edge[React SPA or Nginx Edge]
    Edge --> API[Flask WAF API]
    API --> Capture[Request Capture]
    API --> Features[Feature Engineering]
    API --> Rules[Rule Engine]
    API --> Scoring[Hybrid Scoring]
    API --> Mitigation[Mitigation Logic]
    API --> Backend[Protected Backend App]
    API --> DB[(PostgreSQL or SQLite)]
    API --> Redis[(Redis Token Bucket)]
    API --> Models[(Model Registry)]
    API --> Audit[(Audit and Admin Data)]
```

## Request processing sequence

```mermaid
sequenceDiagram
    participant C as Client
    participant E as Nginx or Embedded UI
    participant W as WAF API
    participant R as Redis or Storage RL
    participant DB as Telemetry Store
    participant B as Backend App

    C->>E: HTTP request
    E->>W: Forwarded request
    W->>R: Consume token bucket token
    W->>W: Capture request and extract features
    W->>W: Run rules and hybrid scoring
    alt Block decision
        W->>DB: Persist blocked event
        W-->>E: 403 blocked
        E-->>C: 403 blocked
    else Allow or monitor
        W->>B: Forward request
        B-->>W: Backend response
        W->>DB: Persist decision and telemetry
        W-->>E: Backend response
        E-->>C: Backend response
    end
```

## Control-plane and analyst workflow

```mermaid
flowchart LR
    Viewer[Viewer] --> UI[React Command Center]
    Analyst[Analyst] --> UI
    Admin[Admin] --> UI
    UI --> Auth[Auth and Sessions]
    UI --> Review[Request Review]
    UI --> Blocks[Targeted Blocks and Blacklist]
    UI --> Settings[Runtime Settings]
    UI --> Users[User and Role Management]
    Auth --> Audit[(Audit Log)]
    Blocks --> API[WAF API]
    Review --> API
    Settings --> API
    Users --> API
```

## ML and data lifecycle

```mermaid
flowchart TD
    Traffic[Captured Requests] --> Store[(Requests Table)]
    Store --> Labeling[Analyst Labeling]
    Store --> Export[Dataset Export]
    Public[Public Datasets] --> Normalize[Preprocessing Script]
    Normalize --> TrainingData[Prepared CSV]
    Export --> TrainingData
    TrainingData --> Train[train_model.py]
    Train --> Registry[(Model Registry)]
    Registry --> Runtime[Hybrid Runtime Scoring]
```

## Deployment topology

```mermaid
flowchart TB
    Browser --> Nginx[Frontend Nginx / SPA]
    Nginx --> Flask[Waitress + Flask API]
    Flask --> AppBackend[Protected Web App]
    Flask --> Postgres[(PostgreSQL)]
    Flask --> Redis[(Redis)]
```

## Security decisions

- High-confidence signatures are blocked immediately.
- Hybrid scoring combines behavioral features and ML output.
- Analysts can apply targeted blocks by signature, path, session, or IP.
- Admin actions are audited and tied to authenticated roles.
- Redis-backed rate limiting is used for multi-instance deployments, while storage-backed token buckets remain available as fallback.
- The separated deployment mode uses React as a dedicated SPA and Flask as an API-only backend, while the local mode can still embed the dashboard directly.
