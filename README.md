# Digital Dean API — стартовий проєкт

Цей репозиторій є стартовою кодовою базою наскрізного навчального проєкту «Цифровий деканат». Не створюйте окремий застосунок для наступної практичної роботи: розвивайте власний форк цього репозиторію і зберігайте сумісність реалізованих маршрутів.

## Отримання власного репозиторію

1. Відкрийте базовий репозиторій: <https://github.com/serhii-ch-eu/digital-dean-api-starter>.
2. Увійдіть у GitHub і натисніть **Fork**, щоб створити пов’язану копію у власному обліковому записі.
3. Клонуйте саме власний форк, замінивши `<login>` своїм логіном GitHub:

```bash
git clone https://github.com/<login>/digital-dean-api-starter.git digital-dean-api
cd digital-dean-api
```

4. Додайте базовий репозиторій як `upstream` і створіть робочу гілку:

```bash
git remote add upstream https://github.com/serhii-ch-eu/digital-dean-api-starter.git
git remote -v
git switch -c practice-01
```

Після цих команд `origin` має вказувати на ваш форк, а `upstream` — на базовий репозиторій викладача. Не надсилайте зміни безпосередньо до базового репозиторію.

## Підготовка середовища

```bash
python -m venv .venv
```

Активація в macOS або Linux:

```bash
source .venv/bin/activate
```

Активація в Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

Інсталяція залежностей:

```bash
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

## Запуск

```bash
python -m uvicorn app.main:app --reload
```

Перевірте:

- `http://127.0.0.1:8000/health`
- `http://127.0.0.1:8000/docs`
- `http://127.0.0.1:8000/openapi.json`

## Тести

```bash
python -m pytest
```

На старті проходить лише перевірка `/health`. Реалізуйте схеми, репозиторій, маршрути та решту тестів відповідно до документа практичної роботи.

## Фіксація та публікація змін

Створіть щонайменше три змістові фіксації: окремо для каркаса моделей, маршрутів і перевірок. Додавайте до кожної фіксації лише пов’язані завершені зміни. Наприклад:

```bash
git add app/schemas tests
git commit -m "Implement student data models"

git add app/api app/repositories
git commit -m "Implement student API routes"

git add tests postman
git commit -m "Add API verification scenarios"
```

Після успішного виконання тестів опублікуйте гілку та фінальний тег у власному форку:

```bash
git push -u origin practice-01
git tag practice-01
git push origin tag practice-01
```

Для наступних практичних робіт продовжуйте розвивати цей самий форк та історію Git; не створюйте непов’язаний репозиторій.

## Правила роботи з даними

Використовуйте тільки вигадані записи. Не додавайте паролі, токени, приватні ключі, файли `.env` або реальні персональні дані до репозиторію.
