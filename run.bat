\
@echo off
IF NOT EXIST .venv (
  py -3 -m venv .venv
)
call .\.venv\Scripts\activate
pip install -r requirements.txt
python app.py
