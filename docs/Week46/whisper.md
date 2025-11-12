# Whisper Leak — LLM Side‑Channel Attack

## Description

Whisper Leak is a newly disclosed side‑channel attack that lets an attacker infer the topic—and sometimes sensitive attributes—of encrypted conversations between users and Large Language Model (LLM) cloud APIs, such as ChatGPT and other streaming AI services. By analyzing observable metadata (packet size and timing) in encrypted network traffic, adversaries can accurately classify what kind of prompt or subject a user is discussing, posing a serious privacy risk even when content itself is protected by TLS.

## Technical Details

* The attack exploits fundamental traits of LLM deployment:

  * Autoregressive token generation (LLMs send output one chunk at a time).
  * Streaming APIs (text displayed to user in near‑real‑time).
  * TLS encryption, which hides content but preserves packet size and timing relationships.

* Attack methods:

  * Observe encrypted HTTPS/TLS traffic between a user and an LLM cloud provider (e.g., OpenAI, Azure, Mistral, X.AI).
  * Record the sequence of encrypted packet sizes and timing intervals as the model streams its response token‑by‑token.
  * Use pre‑trained machine learning classifiers (LightGBM, LSTM, BERT) trained on metadata features (not actual content) to infer whether the user is asking about a particular topic or to distinguish conversation topics.

* Confirmed industry‑wide testing: Research evaluated the method across 28 different LLM providers and reported effectiveness often >98% for topic inference, with near‑perfect accuracy for highly distinctive prompts (e.g., "money laundering"). The study recovered 5–20% of target conversations in some scenarios.

## Attack Scenario

* Passive adversary (ISP, local network snooper, or cloud admin) records encrypted LLM traffic.
* The attacker analyzes packet‑size and timing sequences from many users and queries, then applies a trained classifier to identify or distinguish certain topics.
* No access to TLS keys or platform internals is required.
* Repeated monitoring and large datasets substantially increase attack accuracy.
* The approach typically does not recover full textual content, but leaks high‑level topic and sometimes specific attributes of the conversation.

## Impact

* **Privacy breach:** Adversaries can infer the topic of private LLM chats—enabling surveillance of personal, enterprise, or government queries even when transport encryption is used.
* **Chilling effect:** Users discussing sensitive subjects (legal, medical, political opposition, etc.) lose plausible deniability and privacy.
* **Industry‑wide scope:** Affects most cloud‑based streaming LLM APIs; countermeasures like padding/batching reduce but do not fully eliminate risk.
* **Security risk:** Works across providers and models; attackers can improve performance with more training data.
* **Not a TLS cryptographic failure:** This is inherent metadata leakage from packet size/timing, not a bug in TLS itself.

## Mitigations

* **Obfuscation / Padding:** Add random‑length noise or junk tokens to each streamed response. This significantly reduces attack effectiveness but may increase bandwidth and latency. Several vendors (including OpenAI and Azure) are deploying similar defenses in production.
* **Token Batching:** Send multiple output tokens at once rather than token‑by‑token streaming to reduce the granularity of metadata signals.
* **Packet Injection / Decoys:** Inject decoy packets or dummy traffic during responses to blur packet‑size and timing patterns.
* **Avoid Sensitive Use on Streaming Public Clouds:** For highly sensitive topics, prefer self‑hosted LLMs, turn off streaming, or use offline processing where feasible.
* **Hybrid Defenses:** Combine padding, batching, and traffic shaping; continuously monitor and update defenses as research evolves.
* **Operational Controls:** Detect anomalous traffic collection behaviors on networks and consider rate‑limiting or encrypting at different layers (e.g., VPNs with constant‑rate tunneling), recognizing these have trade‑offs.

## Resources

!!! info "Official & Media Reports"
    - [Whisper Leak: a side-channel attack on Large Language Models](https://arxiv.org/html/2511.03675v1)
    - [CyberNews write-up](https://cybernews.com/security/whisper-leak-microsoft-llm-encryption-spying/)
    - [CyberInsider coverage](https://cyberinsider.com/microsoft-warns-of-whisper-leak-side-channel-on-encrypted-llm-traffic/)
    - [The Register analysis](https://www.theregister.com/2025/11/11/llm_sidechannel_attack_microsoft_researcher/)
    - [Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2025/11/07/whisper-leak-a-novel-side-channel-cyberattack-on-remote-language-models/)
