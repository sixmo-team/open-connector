# Gmail OAuth and native actions

Gmail's native OAuth, attachment, MIME and draft behavior is retained behind the single scoped runtime. Configure OAuth through the protected backend integration using [the private contract](contracts/saas-runtime.openapi.yaml); this branch has no standalone console credential editor, global runtime token, direct SDK endpoint or default connection.

Register the exact backend-facing HTTPS callback URI reported by scoped OAuth setup. `OPEN_CONNECTOR_OAUTH_CALLBACK_ORIGIN` is deployment-controlled, not derived from caller headers. Store the Gmail client ID/secret in the scoped configuration and authorize the selected owner/connection. Managed Gmail uses its selected workspace project/provider configuration and never silently falls back to local OAuth; see [managed OAuth](saas-oauth.md).

The inputs below are provider contracts, not grants. The backend issues the exact signed command after its identity/business/consent checks; OpenConnector checks current function policy and scoped connection access. For example, `{"query":"newer_than:7d","maxResults":5}` is input to `gmail.search_threads`, not an unauthenticated HTTP request.

## Attach files and inline images

Gmail send, draft creation, and reply actions accept `attachments`. For a CID image, provide a
`contentId` and reference the same value from your HTML. Render Markdown, resolve application assets,
and convert image URLs to CID references in your application before calling the connector.

`gmail.create_email_draft` accepts `to`, `subject`, `body`, `isHtml` and `attachments`. An inline item has `filename`, `mimeType`, actual `contentBase64`, `contentId: "logo"` and `disposition: "inline"`; its HTML refers to `cid:logo`. Ordinary attachments need no content ID. Supply actual bytes or a scoped transit-file reference, never a connector-local path.

The subject-only update of this new-message draft preserves the existing MIME body, attachments,
and inline images. `gmail.send_draft` sends the saved draft as-is.

Each attachment accepts exactly one content source: `contentBase64` or `file: { fileId }` for an actual scoped transit file. `filename` and `mimeType` can override transit-file metadata.
Use a bare `contentId`, without `cid:` or angle brackets. Its presence defaults the disposition to
`inline`; otherwise the default is `attachment`.

For `update_draft`:

- Omit `attachments` to preserve existing files and inline images. A supplied list replaces all of
  them; `attachments: []` removes them. Update HTML references when removing or replacing CID images.
- Omit both `body` and `messageBody` to preserve existing plain-text and HTML alternatives. A supplied
  body replaces those alternatives with one body. Omitting `isHtml` inherits the existing body type
  (HTML when an HTML alternative exists). Pass `isHtml: false` for plain text or `isHtml: true` for HTML.
  An empty body clears it. `isHtml` requires a replacement body.
- Omitted editable headers remain unchanged. An empty subject on a new-message draft or an empty
  recipient field clears that field. Reply subjects must still match the associated conversation.
  Content edits to unsupported or ambiguous MIME structures fail rather than discard content.

The connector accepts at most 100 attachments, 25,000,000 decoded attachment bytes in total, and
35,000,000 bytes for the complete MIME message, including encoding overhead. Gmail can impose
additional account or content restrictions.

## Create and send a reply draft

Use the Gmail resource ID of an existing message as `replyToMessageId`. The connector reads its
mail headers, fills in the reply recipient and subject when omitted, and constructs `In-Reply-To`
and `References`. If you also supply `threadId`, it must match that message's thread. Supplying only
`threadId` selects the most recent non-draft message in the conversation. A target without a usable
RFC `Message-ID` header is rejected before creating or sending a reply.


Ordinary reply draft edits preserve the reply association and existing files. A supplied subject
must match the conversation subject, ignoring leading `Re:` prefixes. To change the reply target,
pass `replyToMessageId` or a different `threadId` to `update_draft`; the connector rebuilds the reply
headers and inherits the new target's subject when omitted. Omitted recipients remain unchanged
during updates, so provide the recipients explicitly when switching to a different conversation.

The IDs serve different purposes:

- `draftId` identifies the saved draft and remains stable through updates.
- `messageId` identifies the current Gmail message inside the draft and changes when its content is
  replaced. After sending, Gmail deletes the draft and returns a new sent `messageId`.
- `threadId` identifies the Gmail conversation. Use the returned ID when recording the result.
- The RFC `Message-ID` is an email header used for reply linkage; it is not the Gmail `messageId`.

`send_email`, both reply actions, and `send_draft` return the sent message and thread IDs when Gmail
provides them. Both draft creation actions and `update_draft` return the draft ID and current message
and thread IDs. Missing optional IDs are omitted; `send_draft` retains `threadId: null` when absent.
`list_drafts` returns message IDs by default and hydrated message details with `verbose: true`.

For OAuth grants, `gmail.modify` covers these workflows. When requesting narrower permissions:

| Operation                                       | Scopes                               |
| ----------------------------------------------- | ------------------------------------ |
| Send a new message                              | `gmail.send`                         |
| Reply to an existing message or thread          | `gmail.readonly` and `gmail.send`    |
| Create, edit, or send a normal draft            | `gmail.compose`                      |
| Create a reply draft or change its reply target | `gmail.readonly` and `gmail.compose` |

The fully qualified scope names start with `https://www.googleapis.com/auth/`. Read access is a
conditional requirement for draft actions that resolve a reply target; ordinary draft creation and
editing do not require reading messages outside the draft. `gmail.send` alone does not authorize
Gmail's `drafts.send` endpoint.
Configure `requestedScopes` on the OAuth client before authorizing, and reconnect existing accounts
when their granted scopes do not cover the workflow.

These are the action scopes. OpenConnector also calls Gmail's `users.getProfile` when validating a
connection; that endpoint accepts `gmail.compose` and `gmail.readonly`, but not `gmail.send` alone.
For a connection used to send new messages, request `gmail.readonly` alongside `gmail.send`, or use
`gmail.compose` or `gmail.modify`.

## Common issues

- Callback mismatch: compare the provider registration with the exact scoped backend callback.
- Missing OAuth configuration: provision the selected scoped client/project before starting authorization.
- Missing connection: complete the original authorization and select the genuine resulting connector ID.
- Authentication/function denial: correct the backend command and current owner rule; no static-token fallback exists.
- Insufficient provider permissions: reconnect the same account with the actual scopes required by the action.
