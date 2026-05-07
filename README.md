# @appomni/n8n-nodes-agentguard

AppOmni AgentGuard provides runtime security for n8n workflows that leverage AI agents.

[n8n](https://n8n.io/) is a [fair-code licensed](https://docs.n8n.io/sustainable-use-license/) workflow automation platform.

[Installation](#installation)
[Operations](#operations)
[Credentials](#credentials)
[Compatibility](#compatibility)
[Usage](#usage)
[Resources](#resources)

## Installation

Follow the [installation guide](https://docs.n8n.io/integrations/community-nodes/installation/) in the n8n community nodes documentation.

## Operations

| Resource | Operation | Description |
|----------|-----------|-------------|
| Prompt   | Classify  | Send a prompt to AppOmni for DLP and/or prompt firewall analysis. The node has two outputs (`Allowed`, `Blocked`). |

## Credentials

Create an **AgentGuard API** credential with:

- **Tenant URL** — the URL of your AppOmni tenant (e.g. `https://example.appomni.com`).
- **Ingest Token** — your AppOmni-issued ingest token; sent as `X-AppOmni-Ingest-Token`.
- **Host override** *(optional)* — overrides the `X-Host` header; leave blank unless instructed by AppOmni support.

## Compatibility

Last tested against n8n 2.19.2.

## Usage

Wire the node before any LLM call you want to protect:

```
Trigger → AgentGuard ─┬─ Allowed → LLM call
                                         └─ Blocked → log / alert / refuse
```

The output item carries an `agentguard` object with the verdict, the original prompt, and the full API response, ready for downstream nodes.

If the AppOmni tenant's policy includes a `user_quarantine` classifier, repeat-offender users can be temporarily locked out after a set number of strikes within a rolling window. For Chat Trigger workflows the node auto-populates **User ID** with the chat session ID, so users are quarantine-eligible by default — note that this scopes quarantine to the conversation, so starting a fresh chat session resets the strike count. For persistent identity across sessions (or for non-chat triggers), populate **User ID**, **Username**, or **User Email** under *Additional Metadata* explicitly — these resolve in that priority order, and any value you set there overrides the chat-session default. When a user is locked, AgentGuard returns `response_action: "block"` with `block_reasons` containing the quarantine reason — same shape as any other block, so the existing **Blocked** output handles it without extra wiring. Quarantine windows, strike counts, and lock duration are configured server-side per tenant; nothing needs to change in the workflow.

## Resources

* [n8n community nodes documentation](https://docs.n8n.io/integrations/#community-nodes)
* [AppOmni](https://appomni.com)
