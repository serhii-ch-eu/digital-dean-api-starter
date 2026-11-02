"""Сховище зберігає конверт, не відкритий текст і не ключ."""

from dataclasses import dataclass
from uuid import UUID


@dataclass(frozen=True)
class EncryptedNote:
    version: int
    student_id: UUID
    note_id: UUID
    algorithm: str
    backend: str
    key_id: UUID
    nonce: bytes
    ciphertext: bytes
    tag: bytes


class SecureNoteRepository:
    def __init__(self):
        self._items: dict[UUID, EncryptedNote] = {}

    def add(self, note: EncryptedNote) -> None:
        """Зберегти коректний конверт без дублювання note_id."""
        if note.note_id in self._items:
            raise ValueError("Note ID already exists")
        self._items[note.note_id] = note

    def get(self, student_id: UUID, note_id: UUID) -> EncryptedNote:
        """Перевірити належність ресурсу; невідомий запис дає KeyError."""
        note = self._items.get(note_id)
        if note is None or note.student_id != student_id:
            raise KeyError("Protected note not found")
        return note

    def clear(self) -> None:
        """Очищення записів не змінює ключ і не скидає його лічильник."""
        self._items.clear()


repository = SecureNoteRepository()