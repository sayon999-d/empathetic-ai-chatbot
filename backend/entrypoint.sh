#!/bin/bash
exec uvicorn empathetic_ai:app --host 0.0.0.0 --port "${PORT:-8000}"
