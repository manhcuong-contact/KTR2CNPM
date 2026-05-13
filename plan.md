# WebChat implementation plan

## Problem
The current chat demo has a light UI and in-memory data only. The updated brief requires a dark glassmorphism interface plus real auth, SQLite persistence, and file upload support.

## Approach
1. Add SQLite-backed persistence for users, sessions, conversations, messages, rooms, room members, and file attachments.
2. Add auth endpoints for email/password signup/login and a Google-login placeholder flow that can be wired later.
3. Extend the websocket/chat API to read/write from SQLite and preserve 1:1, 1:N, and N:N behavior.
4. Rebuild `client.html` into a dark glassmorphism WebChat layout with:
   - auth screen
   - fixed sidebar with the 3 tabs
   - searchable conversation list
   - contextual empty state
   - message composer with attachment preview
5. Update README with the new run flow and storage location.

## Todos
- design-sql-schema
- implement-auth-api
- persist-chat-data
- add-file-uploads
- rebuild-dark-ui
- update-documentation

## Notes
- Use SQLite file storage inside the project directory so data survives restarts.
- Keep the existing WebSocket realtime flow, but route it through persisted records.
- Prefer a UI-first implementation for Google sign-in unless a real OAuth client ID is supplied later.
