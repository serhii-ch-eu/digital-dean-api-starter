"""Маршрути API для роботи із захищеними службовими примітками."""

from uuid import UUID, uuid4
from fastapi import APIRouter, HTTPException, status

from app.schemas.secure_note import NoteCreate, NoteMetadata, NoteRead
from app.repositories.secure_note_repository import EncryptedNote, repository
from app.repositories import student_repository
from app.security.keys import PROCESS_KEY
from app.security.context import note_aad
from app.security.adapters import seal_bytes, open_bytes, CiphertextError

router = APIRouter(prefix="/api/v1/students", tags=["secure-notes"])


@router.post(
    "/{student_id}/secure-notes",
    response_model=NoteMetadata,
    status_code=status.HTTP_201_CREATED,
)
def create_secure_note(student_id: UUID, payload: NoteCreate):
    """POST /{student_id}/secure-notes, 201 із NoteMetadata, без text і ключа."""
    # 1. Перевірка наявності студента
    if not student_repository.get_by_id(student_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Student not found",
        )

    # 2. Отримання nonce з межою лічильника
    note_id = uuid4()
    try:
        nonce = PROCESS_KEY.nonces.next()
    except RuntimeError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Protected note unavailable",
        )

    # 3. Шифрування
    algorithm = "AES-256-GCM"
    backend = "cryptography"
    aad = note_aad(student_id, note_id, algorithm, PROCESS_KEY.key_id)
    plaintext_bytes = payload.text.encode("utf-8")

    ciphertext, tag = seal_bytes(
        backend=backend,
        algorithm=algorithm,
        key=PROCESS_KEY.key,
        nonce=nonce,
        data=plaintext_bytes,
        aad=aad,
    )

    # 4. Збереження конверта
    encrypted_note = EncryptedNote(
        version=1,
        student_id=student_id,
        note_id=note_id,
        algorithm=algorithm,
        backend=backend,
        key_id=PROCESS_KEY.key_id,
        nonce=nonce,
        ciphertext=ciphertext,
        tag=tag,
    )
    repository.add(encrypted_note)

    return NoteMetadata(
        id=note_id,
        student_id=student_id,
        algorithm=algorithm,
    )


@router.get(
    "/{student_id}/secure-notes/{note_id}",
    response_model=NoteRead,
    status_code=status.HTTP_200_OK,
)
def read_secure_note(student_id: UUID, note_id: UUID):
    """GET /{student_id}/secure-notes/{note_id}, 200 із перевіреним NoteRead."""
    # 1. Перевірка студента
    if not student_repository.get_by_id(student_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Student not found",
        )

    # 2. Пошук примітки
    try:
        note_record = repository.get(student_id, note_id)
    except KeyError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Protected note not found",
        )

    # 3. Перевірка відповідності ключа процесу
    if note_record.key_id != PROCESS_KEY.key_id:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Protected note unavailable",
        )

    # 4. Формування контексту та розшифрування
    aad = note_aad(
        student_id,
        note_id,
        note_record.algorithm,
        note_record.key_id,
    )

    try:
        decrypted_bytes = open_bytes(
            backend=note_record.backend,
            algorithm=note_record.algorithm,
            key=PROCESS_KEY.key,
            nonce=note_record.nonce,
            ct=note_record.ciphertext,
            tag=note_record.tag,
            aad=aad,
        )
        decrypted_text = decrypted_bytes.decode("utf-8")
    except (CiphertextError, UnicodeDecodeError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Protected note unavailable",
        )

    return NoteRead(
        id=note_id,
        student_id=student_id,
        algorithm=note_record.algorithm,
        text=decrypted_text,
    )