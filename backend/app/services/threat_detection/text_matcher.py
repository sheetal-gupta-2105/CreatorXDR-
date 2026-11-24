
from difflib import SequenceMatcher

from app.services.threat_detection.normalizer import (
    normalize_username,
    normalize_text,
)


def _sequence_similarity(first: str, second: str) -> float:
    if not first or not second:
        return 0.0

    return SequenceMatcher(
        None,
        first,
        second,
    ).ratio() * 100


def _token_similarity(first: str, second: str) -> float:
    first_tokens = set(first.split())
    second_tokens = set(second.split())

    if not first_tokens or not second_tokens:
        return 0.0

    intersection = first_tokens & second_tokens
    union = first_tokens | second_tokens

    return (len(intersection) / len(union)) * 100


def username_similarity(
    reference: str,
    candidate: str,
) -> float:
    reference = normalize_username(reference)
    candidate = normalize_username(candidate)

    return round(
        _sequence_similarity(reference, candidate),
        2,
    )


def display_name_similarity(
    reference: str,
    candidate: str,
) -> float:
    reference = normalize_text(reference)
    candidate = normalize_text(candidate)

    if not reference or not candidate:
        return 0.0

    sequence_score = _sequence_similarity(
        reference,
        candidate,
    )

    token_score = _token_similarity(
        reference,
        candidate,
    )

    return round(
        max(sequence_score, token_score),
        2,
    )


def bio_similarity(
    reference: str,
    candidate: str,
) -> float:
    reference = normalize_text(reference)
    candidate = normalize_text(candidate)

    if not reference or not candidate:
        return 0.0

    sequence_score = _sequence_similarity(
        reference,
        candidate,
    )

    token_score = _token_similarity(
        reference,
        candidate,
    )

    return round(
        (sequence_score * 0.4) + (token_score * 0.6),
        2,
    )
