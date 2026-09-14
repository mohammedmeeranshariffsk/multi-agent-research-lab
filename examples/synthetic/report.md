# SYNTHETIC — Android sample references

**SYNTHETIC offline fixture. All example.test links and evidence are invented test data, not real samples or research.**

Behavior: SMS / OTP interception

Automated evidence checks only; analyst verification remains a manual step.

| Sample | APK acquisition link | Matching evidence and useful checks |
| --- | --- | --- |
| ExampleBanker — com.example.banker<br>SHA256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef | [SYNTHETIC sample catalog](https://example.test/samples/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef) | SMS / OTP interception: incoming messages are read — Static analysis; match: exact SHA256; [evidence](https://example.test/research/example-banker-static)<br>SMS / OTP interception observed in an existing sandbox report — Existing sandbox execution; match: exact SHA256; [evidence](https://example.test/sandbox/reports/example-banker)<br>ExampleSmsReceiver.onReceive reads message text via SmsMessage.getMessageBody — Researcher demonstration / runtime PoC; match: exact SHA256; [evidence](https://example.test/demos/example-banker-runtime)<br>ExampleSmsReceiver.onReceive reads incoming message text — Static analysis; match: exact SHA256; [evidence](https://example.test/research/example-banker-static)<br>SmsMessage.getMessageBody — Static analysis; match: exact SHA256; [evidence](https://example.test/research/example-banker-static)<br>ExampleSmsReceiver handles SMS_RECEIVED — Static analysis; match: exact SHA256; [evidence](https://example.test/research/example-banker-static) |

## Incomplete or unverified leads

- ExampleFamilyLead: Family-only evidence is context, not proof for an exact APK. No independently verified concrete sample identity. No independently verified, manually usable sample acquisition page. No verified requested behavior linked to concrete sample identity. No verified acquisition page. No concrete matching evidence with a documented evidence type. Context: [SYNTHETIC family context](https://example.test/research/family-context) Record: 92a52516764ec41579c2bf23
