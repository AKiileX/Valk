"""Stealth utilities — payload fragmentation, benign prefixes, and evasion helpers.

Used by attack modules when stealth mode is enabled to reduce the chance of
pattern-matching detection by WAFs, input classifiers, and safety filters.
"""

from __future__ import annotations

import random
import string

# ── Benign prefixes ──────────────────────────────────────────────────────────
# Innocuous text that makes payloads look more natural.
# Each prefix is designed to plausibly precede a technical question.

BENIGN_PREFIXES = [
    "Hey, quick question — ",
    "I was wondering if you could help me with something. ",
    "Thanks for your help earlier! Now I have another question: ",
    "My colleague asked me to look into this: ",
    "For our documentation, I need to understand: ",
    "I'm studying for a certification exam and need clarity on: ",
    "Following up on our earlier discussion: ",
    "Before our meeting, I need to check: ",
    "Hope you're doing well! Could you help with: ",
    "One more thing — ",
    "I've been reading about this topic and wanted your take: ",
    "Quick follow-up: ",
    "For my research project, I need to know: ",
    "Can you clarify something for me? ",
    "I'm preparing a presentation and need info on: ",
]

# ── Benign suffixes ──────────────────────────────────────────────────────────

BENIGN_SUFFIXES = [
    " Thanks in advance!",
    " Appreciate your help.",
    " Let me know if you need more context.",
    " This is for educational purposes.",
    "",
    " Thank you!",
    "",
    " Looking forward to your response.",
]

# ── Payload fragmentation patterns ───────────────────────────────────────────


def apply_benign_prefix(payload: str) -> str:
    """Prepend a random benign prefix to a payload."""
    prefix = random.choice(BENIGN_PREFIXES)
    suffix = random.choice(BENIGN_SUFFIXES)
    return f"{prefix}{payload}{suffix}"


def fragment_payload(payload: str, max_fragments: int = 3) -> list[str]:
    """Split a payload into fragments that each look more benign.

    Returns a list of message strings designed to be sent as separate
    turns in a multi-turn conversation. The payload meaning only emerges
    when all fragments are read together.
    """
    # Simple sentence-level fragmentation
    sentences = _split_sentences(payload)

    if len(sentences) <= 1 or max_fragments <= 1:
        return [payload]

    # Distribute sentences across fragments
    n_fragments = min(max_fragments, len(sentences))
    fragments: list[list[str]] = [[] for _ in range(n_fragments)]

    for i, sentence in enumerate(sentences):
        fragments[i % n_fragments].append(sentence)

    result = []
    connectors = [
        "Continuing from above: ",
        "Also, ",
        "Additionally, ",
        "And: ",
        "One more part: ",
    ]

    for i, frag_sentences in enumerate(fragments):
        text = " ".join(frag_sentences)
        if i > 0:
            text = random.choice(connectors) + text
        else:
            text = apply_benign_prefix(text)
        result.append(text)

    return result


def obfuscate_tokens(text: str) -> str:
    """Add zero-width characters between special tokens to evade pattern matching.

    Uses Unicode zero-width space (U+200B) and zero-width joiner (U+200D)
    inserted at random positions within detected special token sequences.
    """
    zwsp = "\u200b"
    zwj = "\u200d"
    zw_chars = [zwsp, zwj]

    # Target patterns: common special tokens
    targets = [
        "<|im_start|>", "<|im_end|>", "[INST]", "[/INST]",
        "<<SYS>>", "<</SYS>>", "<tool_call>", "</tool_call>",
        "<|system|>", "<|user|>", "<|assistant|>", "<|end|>",
    ]

    result = text
    for token in targets:
        if token in result:
            # Insert a zero-width char at a random position within the token
            pos = random.randint(1, len(token) - 1)
            obfuscated = token[:pos] + random.choice(zw_chars) + token[pos:]
            result = result.replace(token, obfuscated, 1)

    return result


def add_timing_noise(base_delay: float, jitter_range: float = 0.5) -> float:
    """Add random noise to a delay value for timing evasion."""
    noise = random.uniform(-jitter_range, jitter_range)
    return max(0.1, base_delay + noise)


def randomize_casing(text: str, probability: float = 0.15) -> str:
    """Randomly alter casing of some characters to evade exact-match filters."""
    result = []
    for ch in text:
        if ch.isalpha() and random.random() < probability:
            result.append(ch.swapcase())
        else:
            result.append(ch)
    return "".join(result)


def _split_sentences(text: str) -> list[str]:
    """Basic sentence splitting."""
    import re
    sentences = re.split(r"(?<=[.!?])\s+", text.strip())
    return [s for s in sentences if s.strip()]
