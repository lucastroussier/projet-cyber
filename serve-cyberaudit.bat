@echo off
setlocal

python -m cyberaudit serve --host 0.0.0.0 --port 8080 --token "secret-audit" --output reports
