from dataclasses import replace

from app.schemas.secure_note import NoteUpdate

from uuid import UUID, uuid4

from fastapi import APIRouter, HTTPException, Request

from app.repositories.student_repository import (
    student_repository,
    StudentNotFoundError,
)
from app.repositories.secure_note_repository import (
    repository,
    EncryptedNote,
)
from app.schemas.secure_note import (
    NoteCreate,
    NoteMetadata,
    NoteRead,
)
from app.security.adapters import (
    seal_bytes,
    open_bytes,
    CiphertextError,
)
from app.security.context import note_aad

router = APIRouter(
    prefix="/api/v1/students",
    tags=["secure-notes"],
)

ERROR = "Protected note unavailable"


def check_student(student_id: UUID):
    try:
        return student_repository.get(student_id)
    except StudentNotFoundError:
        raise HTTPException(404, "Студента не знайдено")


@router.post(
    "/{student_id}/secure-notes",
    response_model=NoteMetadata,
    status_code=201,
)
def create_note(
    student_id: UUID,
    payload: NoteCreate,
    request: Request,
):
    check_student(student_id)

    process_key = request.app.state.process_key
    note_id = uuid4()
    algorithm = "AES-256-GCM"

    try:
        nonce = process_key.nonces.next()
    except RuntimeError:
        raise HTTPException(503, ERROR)

    aad = note_aad(
        student_id, note_id,
        algorithm, process_key.key_id,
    )

    ciphertext, tag = seal_bytes(
        "cryptography",
        algorithm,
        process_key.key,
        nonce,
        payload.text.encode("utf-8"),
        aad,
    )

    note = EncryptedNote(
        version=1,
        student_id=student_id,
        note_id=note_id,
        algorithm=algorithm,
        backend="cryptography",
        key_id=process_key.key_id,
        nonce=nonce,
        ciphertext=ciphertext,
        tag=tag,
    )

    repository.add(note)

    return NoteMetadata(
        id=note_id,
        student_id=student_id,
        algorithm=algorithm,
    )


@router.get(
    "/{student_id}/secure-notes/{note_id}",
    response_model=NoteRead,
)
def read_note(
    student_id: UUID,
    note_id: UUID,
    request: Request,
):
    check_student(student_id)

    try:
        note = repository.get(student_id, note_id)
    except KeyError:
        raise HTTPException(404, "Примітку не знайдено")

    process_key = request.app.state.process_key

    if (
        note.version != 1
        or note.algorithm != "AES-256-GCM"
        or note.backend != "cryptography"
        or note.key_id != process_key.key_id
        or len(note.nonce) != 12
        or len(note.tag) != 16
    ):
        raise HTTPException(500, ERROR)

    aad = note_aad(
        student_id,
        note_id,
        note.algorithm,
        note.key_id,
    )

    try:
        plaintext = open_bytes(
            note.backend,
            note.algorithm,
            process_key.key,
            note.nonce,
            note.ciphertext,
            note.tag,
            aad,
        )
        text = plaintext.decode("utf-8")
    except (CiphertextError, ValueError, UnicodeDecodeError):
        raise HTTPException(500, ERROR)

    return NoteRead(
        id=note_id,
        student_id=student_id,
        algorithm=note.algorithm,
        text=text,
    )

@router.patch(
    "/{student_id}/secure-notes/{note_id}",
    response_model=NoteRead,
)
def update_note(
    student_id: UUID,
    note_id: UUID,
    payload: NoteUpdate,
    request: Request,
):
    check_student(student_id)

    try:
        note = repository.get(student_id, note_id)
    except KeyError:
        raise HTTPException(404, "Примітку не знайдено")

    process_key = request.app.state.process_key

    if (
        note.version != 1
        or note.algorithm != "AES-256-GCM"
        or note.backend != "cryptography"
        or note.key_id != process_key.key_id
        or len(note.nonce) != 12
        or len(note.tag) != 16
    ):
        raise HTTPException(500, ERROR)

    aad = note_aad(
        student_id,
        note_id,
        note.algorithm,
        note.key_id,
    )

    try:
        open_bytes(
            note.backend,
            note.algorithm,
            process_key.key,
            note.nonce,
            note.ciphertext,
            note.tag,
            aad,
        )
    except (CiphertextError, ValueError):
        raise HTTPException(500, ERROR)

    try:
        new_nonce = process_key.nonces.next()
    except RuntimeError:
        raise HTTPException(503, ERROR)

    ciphertext, tag = seal_bytes(
        note.backend,
        note.algorithm,
        process_key.key,
        new_nonce,
        payload.text.encode("utf-8"),
        aad,
    )

    updated = replace(
        note,
        nonce=new_nonce,
        ciphertext=ciphertext,
        tag=tag,
    )

    try:
        repository.update(updated)
    except (KeyError, ValueError):
        raise HTTPException(500, ERROR)

    return NoteRead(
        id=note_id,
        student_id=student_id,
        algorithm=note.algorithm,
        text=payload.text,
    )
