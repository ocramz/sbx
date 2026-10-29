# Agent instructions

## Engineering and coding practices
- make illegal states unrepresentable 
- use informative types
- decouple pure logic (eg state machines) from the IO layer
- when a finite number of cases is known, use enum types and exhaustive pattern matching

### Testing
- only test program logic, not datastructure properties
- no mocking, ever. Only test the real parts of the codebase.
- prefer property tests to unit tests
- allow for integration and system tests

## Scoping work
- Scope features such that they can be implemented in a single session
- each feature should be first described in a standalone planning document

## Documentation
- docs/design.md is authoritative and should only be changed if the specs are impossible or contradictory. 
- Always check with the user in case of unclear requirements
- docs/implementation.md is an append-only log of what has been done so far
- implementation plans go in docs/plans and are disposable once the plan is implemented

## Authorship

The human user is the only author of commits, code and pull request comments in this repository.

- **No attribution to agents or tools.** Leave it out of commit messages, pull request descriptions, pull request and issue comments, code and docs. That means no `Co-Authored-By` trailers, no session links, and no "Generated with …" lines or footers.
