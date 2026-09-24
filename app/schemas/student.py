from pydantic import BaseModel, ConfigDict


class StrictModel(BaseModel):
    """Базова модель, яка не приймає невідомих полів."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class StudentCreate(StrictModel):
    # TODO: додайте full_name, email і group_code з обмеженнями.
    pass


class StudentRead(StudentCreate):
    # TODO: додайте серверний ідентифікатор id.
    pass


class StudentUpdate(StrictModel):
    # TODO: оголосіть дозволені необов’язкові поля для часткового оновлення.
    pass
