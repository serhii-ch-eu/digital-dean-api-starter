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
        if note.version != 1:
            raise ValueError("Unsupported version")

        if len(note.nonce) != 12 or len(note.tag) != 16:
            raise ValueError("Invalid encrypted note")

        if note.note_id in self._items:
            raise ValueError("Note already exists")

        self._items[note.note_id] = note

    def get(self, student_id: UUID, note_id: UUID) -> EncryptedNote:
        note = self._items.get(note_id)

        if note is None or note.student_id != student_id:
            raise KeyError("Note not found")

        return note

    
    def update(self, note: EncryptedNote) -> None:
        previous = self.get(note.student_id, note.note_id)

        if (
            note.version != previous.version
            or note.student_id != previous.student_id
            or note.note_id != previous.note_id
            or note.key_id != previous.key_id
            or note.algorithm != previous.algorithm
            or note.backend != previous.backend
        ):
            raise ValueError("Protected note metadata changed")

        if (
            note.nonce == previous.nonce
            or len(note.nonce) != 12
            or len(note.tag) != 16
        ):
            raise ValueError("Invalid updated encrypted note")

        self._items[note.note_id] = note
    

    def clear(self) -> None:
        """Очищення записів не змінює ключ і не скидає його лічильник."""
        self._items.clear()


repository = SecureNoteRepository()

# TODO: додайте операції свого індивідуального варіанта.
# Підміна _items допустима лише в тестах, не через окремий HTTP-маршрут.
