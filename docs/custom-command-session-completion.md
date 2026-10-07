# Wirepas custom-command completion

After all custom-command response packets have published successfully, MAYA removes and cancels the custom-only virtual session. No HES or GoNIC termination message is required for Wirepas. Multipart responses keep the session through the final publication. Empty output, publication failure, cancellation and exceptions retain the session for retry/idle cleanup.

Custom handling may encounter an existing ordinary DLMS session. Such a session is not owned by the custom command and is preserved. A custom-only session reused by an ordinary DLMS request loses its custom-only marker. Registry removal compares the exact ConnectionState, so late completion cannot remove a replacement session.

Successful-command accounting now occurs after all response publications succeed. It demonstrates completed simulator publication, not HES persistence. Persistent simulator meter state, batch registration, templates, ordinary DLMS association behavior and broker settings are unchanged.

Validation: 948 tests passed, 15 skipped, including five new completion tests covering multipart success, borrowed DLMS session preservation, failed/cancelled publication, and replacement-session safety. Confirm active custom sessions return to zero after a live RF wave and reconcile persisted HES outcomes separately.
