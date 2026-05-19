# Seal Python SDK Setup Documentation

## 1. Quick Start

### Step 1: Install the SDK
```bash
pip install desicon-seal
```

### Step 2: Initialize Seal & Add ASGI Middleware
For modern Python frameworks (FastAPI, Starlette, Django 3.0+), you can easily add the Edge-equivalent WAF to your application using the `SealASGIMiddleware`.

```python
from fastapi import FastAPI
from seal import seal

app = FastAPI()

# 1. Initialize Telemetry & SRE
seal.init(
    api_key="grp_live_xxxx",   # From your dashboard
    app_name="My FastAPI App",
    environment="production"
)

# 2. Add the WAF Middleware to protect your API
app.add_middleware(seal.asgi_middleware())
```

## 2. Configuration Options
| Python Parameter | Node.js / Browser Parameter | Type | Description |
| --- | --- | --- | --- |
| `api_key` | `apiKey` | `string` | Your project API key from the dashboard. |
| `app_name` | `appName` | `string` | A human-readable name for your application. |
| `environment` | `environment` | `string` | Current deployment environment: 'production', 'staging', or 'development'. |
| `rescue_engine` | `rescueEngine` | `boolean` | Set to true to enable automated AI hotfix generation and patching. |
| `level` | `level` | `string` | fatal | error | warning |

## 3. The Sensitivity Dialer
The Sensitivity Dialer controls how much noise Grumpy generates. Set it in two places:
1. **SDK**: Set level in grumpy.init().
2. **Dashboard**: Override per-project in Settings. Server enforces it.

### Levels:
- **fatal** (Low): Only unhandled crashes.
  ```js
  grumpy.init({ level: "fatal" });
  ```
- **error** (Medium): Caught exceptions + fatal.
  ```js
  grumpy.init({ level: "error" });
  ```
- **warning** (High): Everything. Good luck.
  ```js
  grumpy.init({ level: "warning" });
  ```

## 4. Grumpy Rescue Engine
When the Rescue Engine is enabled (via Project Settings), Grumpy doesn't just send you an alert. It instructs your connected AI to generate a functional, sandboxed JavaScript fix that addresses the logical error. The fix is minified and encrypted before leaving the server—only your SDK (holding the same API key) can decrypt and execute it.

Each fix is uniquely identified (grp_fix_xxxx) and location-aware: the same error type at two different code locations gets two separate fixes. If a fix fails to apply, the SDK automatically reports the failure, the bad fix is scrubbed server-side, and a fresh fix is generated on the next occurrence. No stale fixes, no fix-the-fix loops.

- 1. Enable 'Grumpy Rescue Engine' in your Project settings.
- 2. Ensure you have an AI Provider configured in settings.
- 3. When an unhandled error occurs, Grumpy generates an encrypted rescue fix.
- 4. The SDK decrypts and applies this fix in memory—invisible to network inspectors, DevTools, and MITM proxies.

### Stack Compatibility & Frameworks
The Rescue Engine dynamically patches JavaScript bugs in the browser, but it is fully compatible with ANY backend stack.

**Server-Rendered Apps:** Even if your backend is Python or PHP, your users still interact with HTML/JS in the browser. Drop the Grumpy JS SDK into your Jinja2, Django, or Blade templates. The Rescue Engine will catch and hotfix frontend JavaScript bugs seamlessly.

```html
<!DOCTYPE html>
<html>
<head>
    <!-- Drop Grumpy before your other scripts -->
    <script src="https://cdn.jsdelivr.net/gh/Desicon-AI/grumpy-cdn@main/grumpy.js"></script>
    <script>
      Grumpy.init({
        apiKey: "{{ GRUMPY_API_KEY }}", // Passed from backend
        appName: "My Web App",
        rescueEngine: true
      });
    </script>
</head>
<body>
    {% block content %}{% endblock %}
</body>
</html>
```

## 5. AI Personas
Grumpy speaks in three voices. Choose the one that fits your team culture. Personas are set at the Organization level and apply to all projects.

### Grumpy (Sarcastic & Mean) — All Plans
The default. Grumpy roasts your code, insults your variable names, and grudgingly tells you how to fix it. Perfect for teams with thick skin and a sense of humor.

> Example: "You passed a string to parseInt and expected magic? Cast your variables, you absolute menace. Here's the fix, don't make me say it twice."

### Friendly (Supportive & Positive) — Pro / Team
A warm, encouraging senior dev who wants you to know it's going to be okay. Uses emojis. Celebrates small wins. Great for junior-heavy teams or if HR keeps filing complaints.

> Example: "Hey! 👋 Looks like a small type mismatch slipped through — happens to everyone! Here's a quick fix. You're doing great! 🎉"

### Professional (Strategic & Objective) — Pro / Team
An enterprise-grade SRE delivering strictly factual root cause analysis and remediation steps. No jokes, no fluff. Designed for large organizations, regulated industries, and teams that need clean audit trails.

> Example: "Root Cause: Type coercion failure in paymentAPI.submit(). Remediation: Validate input type before invocation. Patch recommended."

### How to configure
All future error analyses across every project in your organization will use the new voice.
```text
1. Dashboard → Settings → Organization Persona
2. Select your preferred persona and click Save
```

## 7. Integrations

### Bring Your Own AI (BYOAI)
Grumpy works out of the box for free using our massive database of hand-crafted roasts. But if you want AI to suggest actual code fixes, connect any AI provider (OpenAI, Anthropic, Groq, Ollama). We never markup token usage. If your API goes down, Grumpy seamlessly falls back to standard mode.
```text
Dashboard → Settings → Select Provider → Paste Key
```

### Slack Webhooks
Grumpy sends rich, formatted alerts directly to your Slack channels with full stack traces, AI analysis, and severity badges.
```text
1. Dashboard → Settings → Connect Slack
2. Slack → Channel → Settings → Integrations → Add Grumpy
```

### Discord Webhooks
Same rich alerts, same brutal honesty — delivered to your Discord server. Perfect for indie devs and open source projects.
```text
Dashboard → Settings → Connect Discord (automatic)
```

## 8. The 'Not My Fault' Engine
Our 'Not My Fault' engine analyzes stack traces. If a crash originated from an external package, we will notify the maintainer of the issue so they can work on it. But we are smart about it. If we notice that the error was caused by missing parameters or incorrect usage by the developer, rather than sending the maintainer a ticket, we notify the developer of the correct use.

### For Maintainers
Sign up for a free Grumpy account to claim and track your public npm/pip packages. You only need a paid subscription if you want to use Grumpy to monitor your own applications.

### For Developers
Enable this feature within your project settings so that genuine errors from external packages are automatically sent to the maintainers.
```text
Dashboard → Settings → Enable 'Not My Fault'
```

## 9. Sandbox Testing
Use your Sandbox project to test Grumpy's ingestion and AI analysis without triggering webhooks or skewing your live analytics. Sandbox API keys always start with sandbox_ and can be found in your Dashboard. You can also test everything interactively in the Playground.

```python
from grumpy_ai import grumpy

grumpy.init(
    api_key="sandbox_YOUR_KEY",
    app_name="Test App",
    environment="development",
    endpoint="https://sealengine.desicon.ai/api/v1/sandbox/ingest"
)
```

