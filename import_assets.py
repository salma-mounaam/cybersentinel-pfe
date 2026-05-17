import csv
import requests

BASE = "http://localhost:8000/api/assets"

with open("assets.csv", newline="", encoding="utf-8") as f:
    for row in csv.DictReader(f):
        row["criticality"] = float(row["criticality"])
        row["tags"] = [tag.strip() for tag in row["tags"].split(",") if tag.strip()]

        r = requests.post(BASE, json=row)

        print(r.status_code, row["hostname"], r.text[:200])
