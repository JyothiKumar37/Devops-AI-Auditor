# Cross-service tests

This directory holds end-to-end and integration tests that span the backend and
frontend together (for example, driving a real audit through the API and
asserting on the rendered dashboard).

Component-level unit tests live next to the code they cover:

- Backend unit tests: `backend/tests/`
- Frontend tests: `frontend/` (added alongside UI features)

End-to-end suites are introduced once the scanning engines land in a later stage.
