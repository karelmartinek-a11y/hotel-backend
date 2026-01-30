@echo off
set  REPO=C:\github\hotel-backend
call %REPO%\venv\Scripts\activate.bat
pushd %REPO%
python -m uvicorn app.main:app --host 0.0.0.0 --port 8010 --reload
popd
