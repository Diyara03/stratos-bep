# Stratos BEP — PlantUML Diagrams

Source files in `puml/`, rendered PNGs in `png/`.

## Figure List

| # | File | Description | UML Type |
|---|------|-------------|----------|
| 1 | 01-use-case.png | Use Case Diagram — all 3 roles (Admin, Analyst, Viewer) | Use Case |
| 2 | 02-use-case-threat-actor.png | Threat Actor Use Cases — attack vectors and detection responses | Use Case |
| 3 | 03-activity-pipeline.png | Email Analysis Pipeline — full Preprocessor/Checker/Decider flow | Activity |
| 4 | 04-sequence-analysis.png | Full Analysis Sequence — Gmail to Dashboard | Sequence |
| 5 | 05-sequence-ti-sync.png | TI Feed Sync — MalwareBazaar and URLhaus daily process | Sequence |
| 6 | 06-activity-quarantine.png | Quarantine Workflow — release/block/delete/whitelist actions | Activity |
| 7 | 07-deployment.png | Docker Compose Deployment Architecture — 5 containers | Deployment |
| 8 | 08-class-models.png | Core Data Model — 15 models with key relationships | Class |
| 9 | 09-activity-rbac.png | Role-Based Access Control — login and permission flow | Activity |
| 10 | 10-sequence-phishing-demo.png | Phishing Detection Demo — end-to-end scored example | Sequence |

## Regenerating

```bash
java -jar plantuml.jar -tpng docs/diagrams/puml/*.puml -o ../png/
```

Requires Java 11+ and PlantUML jar (v1.2024.3 used).
