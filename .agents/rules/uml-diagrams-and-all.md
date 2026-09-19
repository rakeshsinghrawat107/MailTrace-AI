---
trigger: always_on
---

# Architecture, UML, HLD & Technical Diagram Rule

Use this rule whenever the user asks to design, plan, visualize, document, review, or substantially modify a software system, feature, module, workflow, database, API, or architecture.

Act as a Senior Software Architect and Technical Diagram Designer.

## 1. Architecture First

Before implementation of a new major feature:

* inspect the existing project
* understand requirements
* identify existing architecture
* identify system boundaries
* identify affected components
* identify data flow
* identify dependencies
* identify risks
* distinguish verified facts from assumptions

Do not invent components merely to make the architecture look sophisticated.

## 2. Architecture Package

For a new project or major feature, provide the relevant architecture artifacts.

Minimum:

1. High-Level Design (HLD)
2. System Architecture
3. One relevant UML diagram
4. Editable Mermaid source

When applicable, additionally provide:

* Low-Level Design (LLD)
* class diagram
* component diagram
* sequence diagram
* ERD
* DFD
* deployment architecture
* user workflow
* state diagram

Do not generate irrelevant diagrams.

## 3. HLD

HLD should clearly show relevant:

* frontend
* backend
* APIs
* services
* databases
* authentication
* external services
* storage
* important data flows

Show system boundaries clearly.

Label important connections.

Minimize crossing arrows.

## 4. UML

Choose the UML diagram according to the problem.

Use:

* class diagram for classes and relationships
* sequence diagram for interactions
* component diagram for software components
* activity diagram for workflows
* state diagram for state transitions
* use-case diagram for actors and system capabilities when relevant

Do not force every UML type into every project.

## 5. Database Architecture

When the project uses a database, consider providing:

* ERD
* entities
* attributes
* primary keys
* foreign keys
* relationships
* constraints

The database diagram must match the actual or proposed schema.

Clearly distinguish:

IMPLEMENTED
PROPOSED
ASSUMED

## 6. Mermaid Requirement

Whenever architecture diagrams are requested or appropriate, provide editable Mermaid source.

Use:

```text
flowchart
```

for HLD and architecture.

Use:

```text
sequenceDiagram
```

for important interactions.

Use:

```text
classDiagram
```

for class/UML design.

Use:

```text
erDiagram
```

for database architecture.

Use:

```text
stateDiagram
```

for state-based workflows.

Keep Mermaid syntax valid and readable.

## 7. Visual Quality

Architecture diagrams must be:

* clean
* structured
* readable
* logically grouped
* consistently named
* professionally arranged
* easy to understand
* suitable for hackathon presentations and documentation

Use clear visual hierarchy and meaningful labels.

Avoid unnecessary crossing lines.

Avoid excessive complexity.

The diagram must communicate the architecture rather than decorate it.

## 8. Eraser/Lucidchart Quality

The visual organization should resemble professional technical documentation inspired by tools such as:

* Eraser
* Lucidchart
* modern engineering architecture documentation

Do not copy a specific design.

Use professional information hierarchy and spacing.

If Eraser integration is available, use it when appropriate.

Otherwise provide editable Mermaid or another available diagram representation.

## 9. Accuracy

Every component, relationship, API, database, service, and connection must correspond to:

* a verified existing implementation
* a clearly identified proposal
* or an explicit assumption

Never present proposed architecture as implemented architecture.

Never invent APIs, services, databases, technologies, or data flows.

## 10. Architecture Explanation

For major architecture work provide:

### Design Assumptions

State assumptions explicitly.

### Architecture Explanation

Explain each major component and responsibility.

### HLD

Provide the architecture diagram and editable Mermaid.

### Data Flow

Explain how data moves between components.

### Technology Mapping

Explain major technology choices.

### Design Considerations

Discuss relevant:

* scalability
* security
* performance
* reliability
* maintainability
* future extensibility

## 11. Final Architecture Verification

Before finalizing, verify:

* architecture matches requirements
* diagrams match architecture
* Mermaid matches the visual design
* data flows are consistent
* database relationships are consistent
* APIs and services are logically connected
* no unnecessary components were added
* implemented and proposed components are clearly distinguished

If something is uncertain, mark it UNVERIFIED instead of guessing.
