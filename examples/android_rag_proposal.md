# Selective Android Malware RAG Architecture

## Goal

Build an Android malware analysis system that minimizes LLM cost while preserving useful semantic retrieval.

## Proposed Architecture

1. Decompile an APK using JADX.

2. Split Java code into method-level chunks.

3. Embed raw method code into a vector database.

4. Filter known legitimate library classes.

5. Extract deterministic indicators from remaining methods:
   - permissions
   - sensitive API calls
   - method calls
   - suspicious strings
   - URLs
   - reflection
   - dynamic loading
   - shell execution
   - cryptographic APIs
   - network APIs

6. Assign an interest score to each method.

7. Send only high-interest methods to an LLM for security-oriented summarization.

8. Embed the generated summaries into a second vector index.

9. Maintain malware behavior profiles.

Example:

Behavior: SMS interception

Indicators:
- RECEIVE_SMS
- READ_SMS
- BroadcastReceiver

APIs:
- SmsMessage.createFromPdu
- getOriginatingAddress
- getMessageBody

Relationship:
SMS broadcast
→ receiver
→ parse PDU
→ extract SMS body
→ collect metadata
→ transmit data

Potential family association:
- TrickMo

Evidence strength:
- permission only = weak
- permission + API = medium
- connected call path = strong
- family-specific pattern = stronger

10. An LLM planner generates investigation questions from behavior profiles.

11. Questions are routed to the correct subsystem:
   - semantic question → RAG
   - call relationship → call graph
   - API presence → static index
   - permission/component → manifest index
   - source-to-sink → data-flow engine

12. Evidence from all tools is combined.

13. A final LLM determines:
   - detected behavior
   - confidence
   - malware-family similarity
   - contradictory evidence
   - missing evidence

## Research Question

Can selective LLM summarization achieve retrieval quality comparable to full-code LLM summarization while significantly reducing cost?