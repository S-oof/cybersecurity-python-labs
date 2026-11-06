# відповідає за перевірку типів і обмежень вхідних даних від клієнта (Request Body) перед їх збереженням у базу SQLite, а
# також за формування коректної структури відповідей сервера

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Status = Literal["new", "in_progress", "done"]


class CategoryCreate(BaseModel):
    """Тіло запиту POST /categories (id створює база)."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    name: str = Field(min_length=2, max_length=40)


class CategoryRead(CategoryCreate):
    """Категорія у відповіді API."""

    id: int = Field(gt=0)


class RecordCreate(BaseModel):
    """Тіло запиту POST /records та елемент пакета POST /records/bulk."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    code: str = Field(min_length=3, max_length=40)
    title: str = Field(min_length=3, max_length=120)
    # strict=True: не приймати "1", true тощо замість числа.
    category_id: int = Field(gt=0, strict=True)
    value: float = Field(
        ge=0.0,
        allow_inf_nan=False,
        strict=True,
        description="Час відновлення у хвилинах",
    )
    status: Status


class RecordReplace(RecordCreate):
    """Тіло запиту PUT /records/{record_id}: усі змінювані поля обов'язкові."""


class RecordRead(RecordCreate):
    """Запис у відповіді API разом із назвою категорії."""

    id: int = Field(gt=0)
    category_name: str
