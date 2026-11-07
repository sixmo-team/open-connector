# Instagram OAuth And Actions

This guide connects OpenConnector directly to Meta's official Instagram API with an OAuth
application that you own. OpenConnector does not provide a shared Meta app for this flow. The
provider supports Instagram Business and Creator accounts only.

## Prerequisites And Meta Access

You need:

- a Meta Business app with the Instagram product added;
- Business Login for Instagram enabled on that app;
- an Instagram Business or Creator account;
- an Instagram App ID and App Secret; and
- the backend-facing HTTPS OAuth callback configured for this scoped connector.

Standard Access is sufficient when the professional account is owned or managed by the app
operator and has been added in the Meta App Dashboard. Serving professional accounts you do not
own or manage requires Advanced Access and the applicable Meta App Review approval. Availability
of an Action also depends on the permissions approved for the app and granted by the connected
account.

The provider requests these native Instagram permissions by default:

- `instagram_business_basic`
- `instagram_business_manage_comments`
- `instagram_business_manage_insights`
- `instagram_business_content_publish`
- `instagram_business_manage_messages`

Meta setup starts in the official [Business Login for Instagram documentation](https://developers.facebook.com/documentation/instagram-platform/instagram-api-with-instagram-login/business-login).

## Configure and authorize the scoped connection

Use the authenticated backend integration and [private runtime contract](contracts/saas-runtime.openapi.yaml), not a public console or global `/api` endpoint. Configure Instagram's App ID as `clientId`, App Secret as `clientSecret` and actual `requestedScopes` through the scoped OAuth owner. Register the exact reported backend-facing HTTPS callback. Deployment supplies `OPEN_CONNECTOR_OAUTH_CALLBACK_ORIGIN`; caller origins and aliases are not authority.

Request only needed permissions; basic read-only access can use `instagram_business_basic`. Complete the original browser authorization and select the resulting owner-bound connector ID. Secrets remain in OpenBao and durable metadata in forced-RLS PostgreSQL; no plaintext/local encryption-key mode exists.

Meta first returns a short-lived token, normally valid for about one hour. OpenConnector exchanges
it server-side for a long-lived token before storing the connection. The long-lived token is
normally valid for about 60 days. When an Action resolves a token near or after its stored expiry,
OpenConnector refreshes it through Meta's access-token refresh flow; Instagram does not issue a
standard OAuth `refresh_token` for this flow. A connection that remains unused beyond Meta's actual
token lifetime may require reauthorization, and an expired token that cannot be refreshed requires
reconnecting the account.

## Native Instagram action inputs

Every action uses the exact scoped connection and current OpenConnector permission after backend identity, business and consent checks. These inputs describe native provider behavior, not a direct HTTP/SDK/MCP execution path.

| Action | Input and behavior |
| --- | --- |
| `instagram.get_current_user` | Empty object; selected professional account |
| `instagram.list_media` | `limit`, optional `after`; use the returned cursor, never an arbitrary paging URL |
| `instagram.get_media` | Exact owned `mediaId` |
| `instagram.list_media_comments` | `mediaId`, optional `limit`; top-level comments, not a full reply tree |
| `instagram.get_media_insights` | `mediaId`, `metrics`, optional `period`; Meta validates media/metric/breakdown combinations |
| `instagram.publish_media` | `kind` image/video/reel/carousel with public media URLs and supported caption/cover/alt-text fields; 2–10 carousel children |
| `instagram.create_comment` | Owned `mediaId`, `message` |
| `instagram.reply_to_comment` | Exact parent `commentId`, `message` |
| `instagram.send_message` | Instagram-scoped `recipientId`, `text`, subject to the boundary below |

Resume `publish_media` with `kind: "container"` and the actual existing `containerId` only when the earlier safe error marks it `resumable: true`. Child-container errors are not resumable. Resumption avoids creating another container and duplicate posts.


## Alternative: Facebook Login Access Token

Newer Meta apps are created with Unified login and no longer offer Business Login for Instagram, so
the OAuth flow above is unavailable for them. The `instagram` provider also accepts an access
token from Instagram API with Facebook Login. This connection reads and writes through
`graph.facebook.com` and needs no provider OAuth callback; it still uses the authenticated scoped connection flow.

You need an Instagram Business or Creator account linked to a Facebook Page, and a token that can
reach that Page:

- a Page access token, or a user or system-user access token that can list the Page;
- `instagram_basic`, `pages_show_list` and `pages_read_engagement`, plus `instagram_manage_comments`,
  `instagram_manage_insights` or `instagram_content_publish` for the matching Actions; and
- for an app in Development mode, the token owner holds a role on the app.

Prefer a long-lived or system-user token. OpenConnector does not refresh a pasted token, and a
short-lived user token stops working after about an hour.

Create the owner-bound API-key connection with `apiKey` containing the actual Facebook Login token. Do not send it to a global `/api/connections` endpoint or put it in logs.

OpenConnector resolves the linked Instagram account from the token. When the token reaches several
Pages that each link an Instagram account, add `"instagramAccountId":"<INSTAGRAM_ACCOUNT_ID>"` to
`values`; the error message lists the candidates. The same Action IDs work for both connection
types, with these differences for a pasted token:

- `send_message` is not available; messaging through Facebook Login goes through the Page, so use
  an OAuth connection for it.
- `get_current_user` omits `accountType` because Facebook Login does not return it.
- Permissions are the Facebook Login names (`instagram_basic`, ...), not the `instagram_business_*`
  names listed in each Action's `requiredScopes`.

## Publishing Boundaries

Instagram fetches publishing media from the supplied URL. Image, video, Reel, carousel child, and
cover URLs must therefore be publicly reachable HTTP or HTTPS URLs. OpenConnector rejects
loopback, private, link-local, reserved, and cloud-metadata targets before sending the URL to Meta.
Do not place credentials or sensitive signed data in example URLs or logs.

The provider supports images, feed videos, Reels, and carousels containing 2 through 10 images or
videos. Stories are not supported. Video and carousel publishing creates Meta media containers and
polls processing status at most once per minute. Its native five-minute ceiling is additionally bounded by the inherited connector processing deadline/cancellation. A timeout or terminal processing error includes the safe container ID when available.

Container creation and `media_publish` are external mutations. OpenConnector does not
automatically retry them after an ambiguous transport failure because Meta may have accepted the
request. Inspect the error and account state first; resume with `kind: "container"` only when the
error marks that container `resumable: true`. A successful publish is not rolled back if the optional follow-up
metadata read fails.

## Comment And Messaging Boundaries

`create_comment` creates a top-level comment on owned media. Instagram live-video comments are not
supported; Meta's error is returned as a provider failure. `reply_to_comment` replies to an explicit
comment ID. Neither mutation is automatically retried after an ambiguous transport failure.

`send_message` is a reply Action, not an inbox or cold-outreach tool:

- the recipient must have initiated the conversation with the connected professional account;
- a normal automated reply must be sent inside Meta's current messaging window, generally 24
  hours after the user's message;
- `recipientId` is an Instagram-scoped ID, not a username;
- callers normally obtain that ID through their own Meta webhook integration;
- text is limited to 1,000 UTF-8 bytes;
- group messaging, unsolicited messages, bulk outreach, inbox synchronization, recipient
  discovery, and inbound webhook handling are not supported; and
- required automated-experience disclosure and all applicable legal obligations remain the
  operator's responsibility.

OpenConnector does not automatically retry a message send after an ambiguous transport failure
because Meta may already have delivered it.

## Platform, Privacy, And Data Handling

This provider uses the official Instagram API with Instagram Login and `graph.instagram.com`. It
does not support Instagram Basic Display, personal accounts, scraping, public-account harvesting,
hashtag or Explore browsing, arbitrary-user lookup, follower/following enumeration, ads, commerce,
stories, cold outreach, bulk messaging, or inbound webhooks.

Meta rate limits and permission checks still apply. Request only the permissions you need, protect
the scoped database and external secret storage, avoid retaining Instagram data longer than necessary, and
follow the Meta Platform Terms, privacy requirements, and any laws that apply to your use case.
